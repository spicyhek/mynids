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
from app.shadow import ICMPV6_REASON, ShadowClassifier, ShadowPrediction
from app.storage import FlowConflict, PredictionRow, StatsStore, UNVALIDATED

logger = logging.getLogger(__name__)
# The Keras model labels every flow when it is operational, and in v2 mode labels the flows v2 cannot
# judge (cold or degraded windows, flows without features_v2, v2 unavailable) and runs in shadow.
classifier = FlowClassifier(
    model_path=settings.model_path, scaler_path=settings.scaler_path,
    feature_order_path=settings.feature_order_path, label_map_path=settings.label_map_path,
    label_encoder_path=settings.label_encoder_path,
)
# The zeek-conn-window-v2 tree model: shadow in keras mode, operational in v2 mode.
tree: ShadowClassifier | None = (ShadowClassifier(settings.v2_model_dir, settings.v2_model_sha256)
                                 if settings.v2_model_dir else None)
# Summary label set in display order. It is the same in both modes so the dashboard contract does not
# change when the operational model does; model-specific labels are appended if a bundle adds one.
DEFAULT_LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
# The most recent per-batch failure of the operational v2 model; cleared by its next successful batch.
tree_runtime_error: str | None = None


def _label_union(*groups: list[str]) -> list[str]:
    labels: list[str] = []
    for group in groups:
        labels.extend(label for label in group if label not in labels)
    return labels


def v2_operational() -> bool:
    return settings.operational_model == "v2"


def v2_unavailable() -> bool:
    return v2_operational() and (tree is None or not tree.loaded or bool(tree.load_error)
                                 or tree_runtime_error is not None)


def keras_model_id() -> str:
    return classifier.model_id or settings.model_name


def operational_model_name() -> str:
    return tree.model_dir.name if v2_operational() and tree is not None else settings.model_name


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        keras_labels = classifier.load().labels
    except RuntimeError:
        logger.exception("Model initialization failed")
        keras_labels = classifier.labels
    tree_labels: list[str] = []
    if tree is not None:
        try:
            tree.load()
        except RuntimeError:
            # In keras mode v2 is optional; in v2 mode its flows fall back to Keras and health is degraded.
            logger.exception("v2 model initialization failed")
        try:
            tree_labels = tree.labels or ShadowClassifier.read_labels(tree.model_dir)
        except (OSError, ValueError):
            logger.exception("v2 model labels are unreadable")
    store = StatsStore(settings.db_path, labels=_label_union(DEFAULT_LABELS, keras_labels, tree_labels))
    try:
        store.initialize()
        store.set_operational_model(operational_model_name())
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
    if v2_unavailable():
        warnings.append("The operational v2 model is unavailable; flows are labeled by the Keras fallback model.")
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
    if not v2_operational() and tree is not None and (not tree.loaded or tree.load_error):
        # Reported, but never degrades status: the shadow model is not part of operational output.
        warnings.append("Shadow model is configured but unavailable.")
    healthy = classifier.loaded and not classifier.load_error and not v2_unavailable()
    return HealthResponse(
        status="ok" if healthy else "degraded",
        generated_at=datetime.now(UTC), model_loaded=classifier.loaded,
        ingest_enabled=bool(settings.ingest_token), warnings=warnings,
    )


@app.get("/readyz", response_model=HealthResponse)
def readyz(response: Response, store: StatsStore = Depends(get_store)) -> HealthResponse:
    health = healthz()
    # Ingestion needs Keras and storage. An unavailable v2 model degrades health but keeps the pod ready,
    # because its flows fall back to Keras rather than failing.
    ready = classifier.loaded and not classifier.load_error
    try:
        store.check_ready()
    except Exception:
        logger.exception("Storage readiness check failed")
        health.status = "degraded"
        health.warnings.append("Storage is unavailable.")
        ready = False
    if not ready or not health.ingest_enabled:
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
        **summary, model_name=operational_model_name(),
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
    keras_rows = []
    for row, flow in zip(rows, payload.flows):
        canonical = json.dumps(
            {"event_time": flow.event_time.astimezone(UTC).isoformat(), "features": flow.features},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        keras_rows.append(replace(
            row, flow_id=flow.flow_id, payload_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            packet_count=int(flow.features["tot_fwd_pkts"]) + int(flow.features["tot_bwd_pkts"]),
            protocol=int(flow.features["protocol"]) if "protocol" in flow.features else None,
            model_id=keras_model_id(),
        ))
    decided = _v2_decisions(payload, flows) if v2_operational() else {}
    identified_rows = [
        replace(row, predicted_label=decision.predicted_label, confidence=decision.confidence,
                model_id=tree.model_id) if (decision := decided.get(row.flow_id)) else row
        for row in keras_rows
    ]
    try:
        counts = store.record_predictions(payload.source, identified_rows)
    except FlowConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, OverflowError) as exc:
        logger.exception("Prediction storage validation failed")
        raise HTTPException(503, "Prediction validation failed; no flows were stored.") from exc
    if v2_operational():
        if decided:
            _record_keras_shadow(payload.source, keras_rows, identified_rows, decided, store)
    elif tree is not None:
        _record_shadow(payload, flows, identified_rows, store)
    # Maintenance must not turn a committed batch into an unsuccessful acknowledgment.
    inserted = sum(counts.values())
    return IngestResponse(
        source=payload.source, accepted=len(rows), stored=inserted, received=len(rows), inserted=inserted,
        duplicates=len(rows) - inserted, flow_ids=[flow.flow_id for flow in payload.flows],
        labels=_ordered_counts(counts, store), generated_at=datetime.now(UTC),
    )


def _v2_decisions(payload: FlowBatchRequest, flows: list[dict]) -> dict[str, ShadowPrediction]:
    """v2 predictions that become operational labels, by flow ID. Any flow left out keeps its Keras label.

    v2 decides flows with a warm, undegraded window; ICMPv6 is included because both models' ICMPv6
    output is stored as unvalidated. If v2 cannot run, the whole batch keeps Keras and health degrades.
    """
    global tree_runtime_error
    if tree is None or not any(flow.get("features_v2") is not None for flow in flows):
        return {}  # VXLAN carriers and the converter's v1-only resend carry no v2 inputs.
    try:
        predictions = tree.classify(payload.features_v2_contract, flows)
    except Exception as exc:
        tree_runtime_error = f"v2 inference failed: {exc}"
        logger.warning("v2 model unavailable for a batch from %s; using Keras labels", payload.source,
                       exc_info=True)
        return {}
    tree_runtime_error = None
    return {p.flow_id: p for p in predictions if p.validation_reason in (None, ICMPV6_REASON)}


def _record_keras_shadow(source: str, keras_rows: list[PredictionRow], rows: list[PredictionRow],
                         decided: dict[str, ShadowPrediction], store: StatsStore) -> None:
    """Best effort after the batch commits: Keras's labels, in shadow, for the flows v2 labeled."""
    try:
        operational = {row.flow_id: row for row in rows}
        store.record_shadow_predictions(source, keras_model_id(), [
            (row.observed_at, operational[row.flow_id].summary_label,
             ShadowPrediction(flow_id=row.flow_id, predicted_label=row.predicted_label, confidence=row.confidence,
                              validation_status=row.validation_status, validation_reason=row.validation_reason))
            for row in keras_rows if row.flow_id in decided])
    except Exception:
        logger.warning("Keras shadow evaluation skipped for a batch from %s", source, exc_info=True)


def _record_shadow(payload: FlowBatchRequest, flows: list[dict], rows: list, store: StatsStore) -> None:
    """Best effort after the operational batch commits; a shadow failure never fails ingestion."""
    try:
        predictions = tree.classify(payload.features_v2_contract, flows)
        if predictions:
            by_id = {row.flow_id: row for row in rows}
            store.record_shadow_predictions(payload.source, tree.model_id, [
                (by_id[p.flow_id].observed_at, by_id[p.flow_id].summary_label, p) for p in predictions])
    except Exception:
        logger.warning("Shadow evaluation skipped for a batch from %s", payload.source, exc_info=True)


def _ordered_counts(counts: Counter[str], store: StatsStore) -> dict[str, int]:
    ordered = dict.fromkeys([*store.labels, UNVALIDATED], 0)
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
    summary["operational_model"] = settings.operational_model
    if v2_operational():
        # Keras is the shadow: its rows cover only the flows v2 labeled.
        summary["configured_model_id"] = keras_model_id()
        summary["shadow_available"] = bool(classifier.loaded and not classifier.load_error)
    else:
        summary["configured_model_id"] = tree.model_id if tree is not None else None
        summary["shadow_available"] = bool(tree is not None and tree.loaded and not tree.load_error)
    # Which model's label each stored flow carries; in v2 mode the Keras share is the fallback rate.
    summary["operational_label_sources"] = store.operational_model_counts(hours)
    return summary
