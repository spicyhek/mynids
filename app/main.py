from __future__ import annotations

import asyncio
import hmac
import logging
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app.alert_rules import (BOTNET_REASON, ICMPV6_RULE_ID, LONE_SYN_RULE_ID, NO_V2_FEATURES_REASON,
                             REFUSED_RULE_ID, SSH_AUTH_RULE_ID, V2_UNAVAILABLE_REASON, is_authenticated_ssh,
                             is_lone_refused_attempt, is_lone_unanswered_syn, is_routine_icmpv6)
from app.config import settings
from app.flow_rows import load_feature_order, unlabeled_rows
from app.limits import IngestBodyLimit
from app.release_headers import ReleaseHeaders
from app.schemas import (EventResponse, FlowBatchRequest, HealthResponse, IngestResponse, SummaryResponse,
                         WebProbeBatchRequest, WebProbeIngestResponse, WebProbeResponse, WebScanResponse)
from app.shadow import ICMPV6_REASON, ShadowClassifier, ShadowPrediction
from app.storage import FlowConflict, PredictionRow, StatsStore, UNVALIDATED
from app.version import __version__

logger = logging.getLogger(__name__)
# The zeek-conn-window-v2 tree model labels every flow it can judge; the rest are stored unvalidated.
tree: ShadowClassifier | None = (ShadowClassifier(settings.v2_model_dir, settings.v2_model_sha256)
                                 if settings.v2_model_dir else None)
# Summary label set in display order, so the dashboard contract does not depend on the bundle; labels a bundle
# adds are appended.
DEFAULT_LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
# The most recent per-batch failure of the v2 model; cleared by its next successful batch.
tree_runtime_error: str | None = None
# The v1 feature names every flow must carry (app/flow_rows.py), read at startup.
feature_order: list[str] = []


def _label_union(*groups: list[str]) -> list[str]:
    labels: list[str] = []
    for group in groups:
        labels.extend(label for label in group if label not in labels)
    return labels


def v2_unavailable() -> bool:
    return tree is None or not tree.loaded or bool(tree.load_error) or tree_runtime_error is not None


def operational_model_name() -> str:
    return tree.model_dir.name if tree is not None else "none"


@asynccontextmanager
async def lifespan(_: FastAPI):
    global feature_order
    feature_order = load_feature_order(settings.feature_order_path)
    tree_labels: list[str] = []
    if tree is None:
        logger.warning("NIDS_V2_MODEL_DIR is not set; every flow will be stored as unvalidated.")
    else:
        try:
            tree.load()
        except RuntimeError:
            # Flows are stored as unvalidated and health is degraded until the bundle loads.
            logger.exception("v2 model initialization failed")
        try:
            tree_labels = tree.labels or ShadowClassifier.read_labels(tree.model_dir)
        except (OSError, ValueError):
            logger.exception("v2 model labels are unreadable")
    store = StatsStore(settings.db_path, labels=_label_union(DEFAULT_LABELS, tree_labels))
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


app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
app.add_middleware(IngestBodyLimit)
app.add_middleware(ReleaseHeaders, release_id=lambda: settings.release_id)
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
    if v2_unavailable():
        warnings.append("Model inference is unavailable; flows are stored as unvalidated until it recovers.")
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
    return HealthResponse(
        status="degraded" if v2_unavailable() else "ok", version=__version__,
        generated_at=datetime.now(UTC), model_loaded=bool(tree is not None and tree.loaded),
        ingest_enabled=bool(settings.ingest_token), warnings=warnings,
    )


@app.get("/readyz", response_model=HealthResponse)
def readyz(response: Response, store: StatsStore = Depends(get_store)) -> HealthResponse:
    health = healthz()
    # Ingestion needs storage. An unavailable v2 model degrades health but keeps the pod ready, because its flows
    # are stored as unvalidated rather than failing.
    ready = True
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
        warnings.append("Unvalidated flows (ICMPv6 that is not routine IPv6 housekeeping, botnet predictions, and "
                        "flows the model could not judge, such as the first minute after a sensor restart) are "
                        "counted separately from benign and attack predictions.")
    return SummaryResponse(
        **summary, version=__version__, model_name=operational_model_name(),
        recent_window_minutes=settings.public_window_minutes,
        retention_hours=settings.retention_hours, stale_after_seconds=settings.stale_after_seconds,
        ingest_enabled=bool(settings.ingest_token), warnings=warnings,
        web_probes=store.web_probe_summary(settings.public_window_minutes, hours, **web_scan_options()),
    )


@app.post("/api/internal/flows", response_model=IngestResponse, dependencies=[Depends(require_ingest_token)])
def ingest_flows(payload: FlowBatchRequest, store: StatsStore = Depends(get_store)) -> IngestResponse:
    flows = [flow.model_dump() for flow in payload.flows]
    try:
        base_rows = unlabeled_rows(flows, feature_order)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    decided = _v2_decisions(payload, flows)
    suppressed = _apply_alert_rules(payload.source, flows, decided)
    icmpv6_cleared = _validate_routine_icmpv6(flows, decided)
    _demote_botnet(decided)  # After the alert rules, which only relabel classified predictions.
    undecided = _undecided_reasons(flows, decided)
    rows = []
    for row in base_rows:
        decision = decided.get(row.flow_id)
        if decision is None:
            rows.append(replace(row, unvalidated_reason=undecided[row.flow_id]))
            continue
        rule = suppressed.get(row.flow_id) or (ICMPV6_RULE_ID if row.flow_id in icmpv6_cleared else None)
        rows.append(replace(
            row, predicted_label=decision.predicted_label, confidence=decision.confidence,
            model_id=f"{tree.model_id}+{rule}" if rule else tree.model_id,
            unvalidated_reason=decision.validation_reason if decision.validation_status == "unvalidated" else None,
            icmpv6_validated=row.flow_id in icmpv6_cleared))
    try:
        counts = store.record_predictions(payload.source, rows)
    except FlowConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, OverflowError) as exc:
        logger.exception("Prediction storage validation failed")
        raise HTTPException(503, "Prediction validation failed; no flows were stored.") from exc
    inserted = sum(counts.values())
    return IngestResponse(
        source=payload.source, accepted=len(rows), stored=inserted, received=len(rows), inserted=inserted,
        duplicates=len(rows) - inserted, flow_ids=[flow.flow_id for flow in payload.flows],
        labels=_ordered_counts(counts, store), generated_at=datetime.now(UTC),
    )


def _v2_decisions(payload: FlowBatchRequest, flows: list[dict]) -> dict[str, ShadowPrediction]:
    """v2 predictions that become the stored labels, by flow ID. Flows left out are undecided and stored as
    unvalidated with the reason (_undecided_reasons).

    v2 decides flows with a warm, undegraded window; ICMPv6 is included because its output is stored as
    unvalidated unless _validate_routine_icmpv6 clears it. If v2 cannot run, the whole batch is undecided and
    health degrades.
    """
    global tree_runtime_error
    if tree is None or not any(flow.get("features_v2") is not None for flow in flows):
        return {}  # VXLAN carriers and the converter's v1-only resend carry no v2 inputs.
    try:
        predictions = tree.classify(payload.features_v2_contract, flows)
    except Exception as exc:
        tree_runtime_error = f"v2 inference failed: {exc}"
        logger.warning("v2 model unavailable for a batch from %s; storing it as unvalidated", payload.source,
                       exc_info=True)
        return {}
    tree_runtime_error = None
    return {p.flow_id: p for p in predictions if p.validation_reason in (None, ICMPV6_REASON)}


def _demote_botnet(decided: dict[str, ShadowPrediction]) -> None:
    """Store v2 BOTNET predictions as unvalidated, in place (alert_rules.BOTNET_REASON explains why)."""
    if settings.botnet_alerts != "unvalidated":
        return
    for flow_id, prediction in decided.items():
        if prediction.validation_status == "classified" and prediction.predicted_label == "BOTNET":
            decided[flow_id] = replace(prediction, validation_status="unvalidated", validation_reason=BOTNET_REASON)


def _undecided_reasons(flows: list[dict], decided: dict[str, ShadowPrediction]) -> dict[str, str]:
    """Why each flow v2 did not judge is unvalidated."""
    reasons = {}
    for flow in flows:
        if flow["flow_id"] in decided:
            continue
        if flow.get("features_v2") is None:
            reasons[flow["flow_id"]] = NO_V2_FEATURES_REASON
        elif flow.get("window_degraded"):
            reasons[flow["flow_id"]] = "window_degraded"
        elif not flow.get("window_warm"):
            reasons[flow["flow_id"]] = "window_not_warm"
        else:
            reasons[flow["flow_id"]] = V2_UNAVAILABLE_REASON  # v2 failed or rejected this batch.
    return reasons


def _apply_alert_rules(source: str, flows: list[dict], decided: dict[str, ShadowPrediction]) -> dict[str, str]:
    """Relabel v2 alerts on lone unanswered SYNs, lone refused or aborted attempts and successful SSH logins
    BENIGN, in place; return the rule ID for each flow changed.

    The stored row keeps the model's confidence and records the rule in its model_id, so suppressed flows stay
    countable (shadow summary's operational_label_sources) and the original label is in the log.
    """
    rules = [(rule_id, description, matches) for enabled, rule_id, description, matches in (
        (settings.suppress_lone_unanswered_syn, LONE_SYN_RULE_ID, "lone unanswered SYN",
         lambda flow: is_lone_unanswered_syn(flow["features_v2"])),
        (settings.suppress_refused_attempts, REFUSED_RULE_ID, "lone refused attempt",
         lambda flow: is_lone_refused_attempt(flow["features_v2"])),
        (settings.suppress_authenticated_ssh, SSH_AUTH_RULE_ID, "successful SSH login", is_authenticated_ssh),
    ) if enabled == "true"]
    if not rules or not decided:
        return {}
    suppressed = {}
    for flow in flows:
        prediction = decided.get(flow["flow_id"])
        if prediction is None or prediction.validation_status != "classified" or prediction.predicted_label == "BENIGN":
            continue
        for rule_id, description, matches in rules:
            if matches(flow):
                decided[flow["flow_id"]] = replace(prediction, predicted_label="BENIGN")
                suppressed[flow["flow_id"]] = rule_id
                # Warning level: the app configures no logging, so info lines would never reach the pod log.
                logger.warning("Suppressed %s (%.3f) on %s %s from %s", prediction.predicted_label,
                               prediction.confidence, description, flow["flow_id"], source)
                break
    return suppressed


def _validate_routine_icmpv6(flows: list[dict], decided: dict[str, ShadowPrediction]) -> set[str]:
    """Store routine ICMPv6 that v2 called BENIGN as classified BENIGN, in place; return the flow IDs changed.

    alert_rules.is_routine_icmpv6 decides; v2 only has to agree (it was never trained on an ICMPv6 attack, so any
    other label is an extrapolation and stays unvalidated). The stored model_id records the rule.
    """
    if settings.validate_routine_icmpv6 != "true" or not decided:
        return set()
    cleared = set()
    for flow in flows:
        prediction = decided.get(flow["flow_id"])
        if (prediction is None or prediction.validation_reason != ICMPV6_REASON
                or prediction.predicted_label != "BENIGN"
                or not is_routine_icmpv6(flow["features"], flow["features_v2"])):
            continue
        decided[flow["flow_id"]] = replace(prediction, validation_status="classified", validation_reason=None)
        cleared.add(flow["flow_id"])
    return cleared


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


@app.post("/api/internal/web-probes", response_model=WebProbeIngestResponse,
          dependencies=[Depends(require_ingest_token)])
def ingest_web_probes(payload: WebProbeBatchRequest, store: StatsStore = Depends(get_store)) -> WebProbeIngestResponse:
    try:
        inserted = store.record_web_probes(payload.source, payload.events)
    except (ValueError, OverflowError) as exc:
        logger.exception("Web-probe storage validation failed")
        raise HTTPException(503, "Web-probe validation failed; no events were stored.") from exc
    return WebProbeIngestResponse(source=payload.source, received=len(payload.events), inserted=inserted,
                                  duplicates=len(payload.events) - inserted,
                                  event_ids=[event.event_id for event in payload.events])


@app.get("/api/internal/web-probes", response_model=list[WebProbeResponse],
         dependencies=[Depends(require_ingest_token)])
def internal_web_probes(
    response: Response,
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    limit: int = Query(default=200, ge=1, le=1000),
    store: StatsStore = Depends(get_store),
) -> list[dict]:
    """Probe requests with client addresses, newest first (private: behind the ingest token)."""
    response.headers["Cache-Control"] = "no-store"
    return store.list_web_probes(history_hours=hours, limit=limit)


def web_scan_options() -> dict:
    return {"gap_seconds": settings.web_scan_gap_seconds, "min_requests": settings.web_scan_min_requests,
            "min_distinct_uris": settings.web_scan_min_distinct_uris}


@app.get("/api/internal/web-scans", response_model=list[WebScanResponse],
         dependencies=[Depends(require_ingest_token)])
def internal_web_scans(
    response: Response,
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    store: StatsStore = Depends(get_store),
) -> list[dict]:
    """Web scans with their clients, user agents and sample URIs, newest first (private: behind the ingest token)."""
    response.headers["Cache-Control"] = "no-store"
    return store.web_scans(since=datetime.now(UTC) - timedelta(hours=hours), **web_scan_options())


@app.get("/api/internal/shadow/summary", dependencies=[Depends(require_ingest_token)])
def shadow_summary(
    response: Response,
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    store: StatsStore = Depends(get_store),
) -> dict:
    response.headers["Cache-Control"] = "no-store"
    # Shadow rows recorded before 2.0.0 (Keras in shadow) stay until retention removes them.
    summary = store.shadow_summary(hours)
    summary["operational_model_id"] = tree.model_id if tree is not None else None
    # Which model, and which alert rule, labeled each stored flow ('unlabeled' when none did).
    summary["operational_label_sources"] = store.operational_model_counts(hours)
    return summary
