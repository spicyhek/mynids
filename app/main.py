from __future__ import annotations

import hashlib
import asyncio
import hmac
import json
import logging
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.inference import FlowClassifier
from app.limits import IngestBodyLimit
from app.schemas import EventResponse, FlowBatchRequest, HealthResponse, IngestResponse, SummaryResponse
from app.shadow import ShadowClassifier
from app.storage import FlowConflict, StatsStore, UNVALIDATED

logger = logging.getLogger(__name__)
classifier = FlowClassifier(
    model_path=settings.model_path, scaler_path=settings.scaler_path,
    feature_order_path=settings.feature_order_path, label_map_path=settings.label_map_path,
    label_encoder_path=settings.label_encoder_path,
)
shadow: ShadowClassifier | None = (ShadowClassifier(settings.shadow_model_dir, settings.shadow_model_sha256)
                                   if settings.shadow_model_dir else None)
DEFAULT_LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        artifacts = classifier.load()
        labels = artifacts.labels
    except RuntimeError:
        logger.exception("Model initialization failed")
        labels = classifier.labels or DEFAULT_LABELS
    if shadow is not None:
        try:
            shadow.load()
        except RuntimeError:
            # Shadow evaluation is optional; operational inference continues without it.
            logger.exception("Shadow model initialization failed")
    store = StatsStore(settings.db_path, labels=labels)
    try:
        store.initialize()
        store.purge_old_events(settings.retention_hours, max_batches=1)
        app.state.store = store
        stop = asyncio.Event()

        async def maintain():
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=60)
                except TimeoutError:
                    try:
                        await asyncio.to_thread(store.purge_old_events, settings.retention_hours, 1)
                    except Exception:
                        logger.exception("Retention maintenance failed")
        maintenance = asyncio.create_task(maintain())
        try:
            yield
        finally:
            stop.set()
            await maintenance
    finally:
        store.close()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(IngestBodyLimit)
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(RequestValidationError)
async def invalid_request(_, exc: RequestValidationError):
    # Never echo raw feature values (including non-JSON NaN/Infinity) in an error response.
    return JSONResponse(status_code=422, content={
        "detail": [{key: item[key] for key in ("loc", "msg", "type")} for item in exc.errors()]
    })


def get_store() -> StatsStore:
    return app.state.store


def get_warnings() -> list[str]:
    warnings = []
    if not classifier.loaded or classifier.load_error:
        warnings.append("Model inference is unavailable or degraded.")
    if not settings.ingest_token:
        warnings.append("Internal ingestion is disabled until NIDS_INGEST_TOKEN is configured.")
    return warnings


def require_ingest_token(x_ingest_token: str | None = Header(default=None)) -> None:
    if not settings.ingest_token:
        raise HTTPException(503, "Ingestion is disabled because NIDS_INGEST_TOKEN is not configured.")
    if not hmac.compare_digest((x_ingest_token or "").encode(), settings.ingest_token.encode()):
        raise HTTPException(403, "Invalid ingest token.")


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    warnings = get_warnings()
    if shadow is not None and (not shadow.loaded or shadow.load_error):
        # Reported, but never degrades status: the shadow model is not part of operational output.
        warnings.append("Shadow model is configured but unavailable.")
    return HealthResponse(
        status="ok" if classifier.loaded and not classifier.load_error else "degraded",
        generated_at=datetime.now(UTC), model_loaded=classifier.loaded,
        ingest_enabled=bool(settings.ingest_token), warnings=warnings,
    )


@app.get("/readyz", response_model=HealthResponse)
def readyz(response: Response, store: StatsStore = Depends(get_store)) -> HealthResponse:
    health = healthz()
    try:
        store.check_ready()
    except Exception:
        logger.exception("Storage readiness check failed")
        health.status = "degraded"
        health.warnings.append("Storage is unavailable.")
    if health.status != "ok" or not health.ingest_enabled:
        response.status_code = 503
    return health


@app.get("/api/public/summary", response_model=SummaryResponse)
def public_summary(
    response: Response,
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    store: StatsStore = Depends(get_store),
) -> SummaryResponse:
    response.headers["Cache-Control"] = "no-store"
    summary = store.build_summary(settings.public_window_minutes, hours, settings.stale_after_seconds)
    warnings = get_warnings()
    if any(sensor["stale"] for sensor in summary["sensors"]):
        warnings.append("One or more sensors have not delivered flows recently; traffic may be quiet or delayed.")
    if not summary["packet_counts_complete"]:
        warnings.append("Retained packet totals exclude historical flows without packet counts.")
    if summary["recent_counts"][UNVALIDATED]:
        warnings.append("ICMPv6 traffic is unvalidated and is counted separately from benign and attack predictions.")
    return SummaryResponse(
        **summary, model_name=settings.model_name,
        recent_window_minutes=settings.public_window_minutes,
        retention_hours=settings.retention_hours, stale_after_seconds=settings.stale_after_seconds,
        ingest_enabled=bool(settings.ingest_token), warnings=warnings,
    )


@app.post("/api/internal/flows", response_model=IngestResponse, dependencies=[Depends(require_ingest_token)])
def ingest_flows(payload: FlowBatchRequest, store: StatsStore = Depends(get_store)) -> IngestResponse:
    flows = [flow.model_dump() for flow in payload.flows]
    try:
        rows = classifier.classify_batch(flows)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        logger.warning("Inference unavailable: %s", exc)
        raise HTTPException(503, "Inference unavailable; retry this batch.", headers={"Retry-After": "5"}) from exc
    if len(rows) != len(payload.flows):
        raise HTTPException(503, "Invalid prediction batch; no flows were stored.")
    identified_rows = []
    for row, flow in zip(rows, payload.flows):
        canonical = json.dumps(
            {"event_time": flow.event_time.astimezone(UTC).isoformat(), "features": flow.features},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        identified_rows.append(replace(
            row, flow_id=flow.flow_id, payload_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            packet_count=int(flow.features["tot_fwd_pkts"]) + int(flow.features["tot_bwd_pkts"]),
            protocol=int(flow.features["protocol"]) if "protocol" in flow.features else None,
        ))
    try:
        counts = store.record_predictions(payload.source, identified_rows)
    except FlowConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, OverflowError) as exc:
        logger.exception("Prediction storage validation failed")
        raise HTTPException(503, "Prediction validation failed; no flows were stored.") from exc
    if shadow is not None:
        _record_shadow(payload, flows, identified_rows, store)
    # Maintenance must not turn a committed batch into an unsuccessful acknowledgment.
    inserted = sum(counts.values())
    return IngestResponse(
        source=payload.source, accepted=len(rows), stored=inserted, received=len(rows), inserted=inserted,
        duplicates=len(rows) - inserted, flow_ids=[flow.flow_id for flow in payload.flows],
        labels=_ordered_counts(counts), generated_at=datetime.now(UTC),
    )


def _record_shadow(payload: FlowBatchRequest, flows: list[dict], rows: list, store: StatsStore) -> None:
    """Best effort after the operational batch commits; a shadow failure never fails ingestion."""
    try:
        predictions = shadow.classify(payload.features_v2_contract, flows)
        if predictions:
            by_id = {row.flow_id: row for row in rows}
            store.record_shadow_predictions(payload.source, shadow.model_id, [
                (by_id[p.flow_id].observed_at, by_id[p.flow_id].summary_label, p) for p in predictions])
    except Exception:
        logger.warning("Shadow evaluation skipped for a batch from %s", payload.source, exc_info=True)


def _ordered_counts(counts: Counter[str]) -> dict[str, int]:
    ordered = dict.fromkeys([*(classifier.labels or DEFAULT_LABELS), UNVALIDATED], 0)
    ordered.update(counts)
    return ordered


@app.get("/api/internal/events", response_model=list[EventResponse],
         dependencies=[Depends(require_ingest_token)])
def internal_events(
    response: Response,
    limit: int = Query(default=100, ge=1, le=200),
    before_id: int | None = Query(default=None, ge=1, le=2**63 - 1),
    validation_status: Literal["legacy", "classified", "unvalidated"] | None = None,
    store: StatsStore = Depends(get_store),
) -> list[dict]:
    response.headers["Cache-Control"] = "no-store"
    store.purge_old_events(settings.retention_hours)
    return store.list_events(limit=limit, before_id=before_id, validation_status=validation_status)


@app.get("/api/internal/shadow/summary", dependencies=[Depends(require_ingest_token)])
def shadow_summary(
    response: Response,
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    store: StatsStore = Depends(get_store),
) -> dict:
    response.headers["Cache-Control"] = "no-store"
    summary = store.shadow_summary(hours)
    summary["configured_model_id"] = shadow.model_id if shadow is not None else None
    summary["shadow_available"] = bool(shadow is not None and shadow.loaded and not shadow.load_error)
    return summary
