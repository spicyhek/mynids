from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.debug_log import agent_log
from app.inference import FlowClassifier
from app.schemas import FlowBatchRequest, HealthResponse, IngestResponse, SummaryResponse
from app.storage import StatsStore


classifier = FlowClassifier(
    model_path=settings.model_path,
    scaler_path=settings.scaler_path,
    feature_order_path=settings.feature_order_path,
    label_map_path=settings.label_map_path,
    label_encoder_path=settings.label_encoder_path,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # region agent log
    agent_log(
        "app/main.py:29",
        "lifespan_start",
        {
            "cwd": str(Path.cwd()),
            "db_path": str(settings.db_path),
            "db_parent_exists": settings.db_path.parent.exists(),
            "model_path": str(settings.model_path),
            "model_exists": settings.model_path.exists(),
            "scaler_exists": settings.scaler_path.exists(),
            "feature_order_exists": settings.feature_order_path.exists(),
            "label_map_exists": settings.label_map_path.exists(),
            "label_encoder_exists": settings.label_encoder_path.exists(),
        },
        hypothesis_id="H1",
    )
    # endregion
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    artifacts = None
    try:
        # region agent log
        agent_log("app/main.py:47", "before_classifier_load", {}, hypothesis_id="H3")
        # endregion
        artifacts = classifier.load()
        # region agent log
        agent_log(
            "app/main.py:50",
            "after_classifier_load",
            {"labels_count": len(artifacts.labels), "feature_count": len(artifacts.feature_order)},
            hypothesis_id="H3",
        )
        # endregion
        store = StatsStore(settings.db_path, labels=artifacts.labels)
        store.initialize()
        store.purge_old_events(settings.retention_hours)
    except Exception as exc:
        # region agent log
        agent_log(
            "app/main.py:61",
            "classifier_or_store_exception",
            {
                "error_type": type(exc).__name__,
                "error": str(exc),
                "load_error": classifier.load_error,
            },
            hypothesis_id="H4",
        )
        # endregion
        labels = classifier.labels or ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]
        store = StatsStore(settings.db_path, labels=labels)
        store.initialize()

    app.state.store = store
    app.state.model_name = settings.model_name
    app.state.model_loaded = artifacts is not None
    app.state.model_warning = classifier.load_error
    # region agent log
    agent_log(
        "app/main.py:78",
        "lifespan_ready",
        {
            "model_loaded": app.state.model_loaded,
            "model_warning": app.state.model_warning,
            "db_exists": settings.db_path.exists(),
        },
        hypothesis_id="H2",
    )
    # endregion
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


def get_store() -> StatsStore:
    return app.state.store


def _count_flow_packets(payload: FlowBatchRequest) -> int:
    total_packets = 0
    for flow in payload.flows:
        features = flow.features or {}
        total_packets += int(max(float(features.get("tot_fwd_pkts", 0.0)), 0.0))
        total_packets += int(max(float(features.get("tot_bwd_pkts", 0.0)), 0.0))
    return total_packets


def get_warnings() -> list[str]:
    warnings: list[str] = []
    if getattr(app.state, "model_warning", None):
        warnings.append(app.state.model_warning)
    if not settings.ingest_token:
        warnings.append("Internal ingestion is disabled until NIDS_INGEST_TOKEN is configured.")
    return warnings


def require_ingest_token(x_ingest_token: str | None = Header(default=None)) -> None:
    if not settings.ingest_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion is disabled because NIDS_INGEST_TOKEN is not configured.",
        )
    if x_ingest_token != settings.ingest_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid ingest token.",
        )


@app.get("/", include_in_schema=False)
async def serve_index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    model_loaded = bool(getattr(app.state, "model_loaded", False))
    status_value = "ok" if model_loaded else "degraded"
    return HealthResponse(
        status=status_value,
        generated_at=datetime.now(UTC).replace(microsecond=0),
        model_loaded=model_loaded,
        ingest_enabled=bool(settings.ingest_token),
        warnings=get_warnings(),
    )


@app.get("/api/public/summary", response_model=SummaryResponse)
async def public_summary(
    hours: int = Query(default=24, ge=1, le=settings.max_history_hours),
    store: StatsStore = Depends(get_store),
) -> SummaryResponse:
    summary = store.build_summary(
        recent_window_minutes=settings.public_window_minutes,
        history_hours=hours,
    )
    return SummaryResponse(
        generated_at=summary["generated_at"],
        model_name=settings.model_name,
        recent_window_minutes=settings.public_window_minutes,
        lifetime_packets=summary["lifetime_packets"],
        total_events=summary["total_events"],
        recent_counts=summary["recent_counts"],
        all_time_counts=summary["all_time_counts"],
        hourly=summary["hourly"],
        sources=summary["sources"],
        last_classified_at=summary["last_classified_at"],
        ingest_enabled=bool(settings.ingest_token),
        warnings=get_warnings(),
    )


@app.post(
    "/api/internal/flows",
    response_model=IngestResponse,
    dependencies=[Depends(require_ingest_token)],
)
async def ingest_flows(
    payload: FlowBatchRequest,
    store: StatsStore = Depends(get_store),
) -> IngestResponse:
    if not payload.flows:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one flow record is required.",
        )

    try:
        rows = classifier.classify_batch([flow.model_dump() for flow in payload.flows])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    source = (payload.source or settings.default_source_name).strip() or settings.default_source_name
    label_counts = store.record_predictions(
        source,
        rows,
        lifetime_packet_total=_count_flow_packets(payload),
    )
    store.purge_old_events(settings.retention_hours)
    return IngestResponse(
        source=source,
        accepted=len(payload.flows),
        stored=len(rows),
        labels=_ordered_counts(label_counts),
        generated_at=datetime.now(UTC).replace(microsecond=0),
    )


def _ordered_counts(counts: Counter[str]) -> dict[str, int]:
    labels = classifier.labels or ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]
    ordered = {label: 0 for label in labels}
    for label, total in counts.items():
        ordered[label] = int(total)
    return ordered
