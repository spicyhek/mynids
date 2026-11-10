from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def _path_env(name: str, default: str | Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


def _optional_path_env(name: str) -> Path | None:
    value = os.getenv(name, "").strip()
    return Path(value).expanduser().resolve() if value else None


@dataclass(frozen=True)
class Settings:
    app_name: str = "NIDS Service"
    model_name: str = "cicids2018_dense_model"
    host: str = "0.0.0.0"
    port: int = int(os.getenv("PORT", "8080"))
    db_path: Path = _path_env("NIDS_DB_PATH", ROOT_DIR / "data" / "nids.sqlite3")
    model_path: Path = _path_env("NIDS_MODEL_PATH", ROOT_DIR / "cicids2018_dense_model.keras")
    scaler_path: Path = _path_env("NIDS_SCALER_PATH", ROOT_DIR / "scaler.joblib")
    feature_order_path: Path = _path_env("NIDS_FEATURE_ORDER_PATH", ROOT_DIR / "feature_order.json")
    label_map_path: Path = _path_env("NIDS_LABEL_MAP_PATH", ROOT_DIR / "label_map.json")
    label_encoder_path: Path = _path_env("NIDS_LABEL_ENCODER_PATH", ROOT_DIR / "label_encoder.joblib")
    ingest_token: str = os.getenv("NIDS_INGEST_TOKEN", "")
    public_window_minutes: int = int(os.getenv("NIDS_PUBLIC_WINDOW_MINUTES", "60"))
    stale_after_seconds: int = max(1, int(os.getenv("NIDS_STALE_AFTER_SECONDS", "300")))
    max_history_hours: int = int(os.getenv("NIDS_MAX_HISTORY_HOURS", "168"))
    retention_hours: int = int(os.getenv("NIDS_RETENTION_HOURS", "720"))
    default_source_name: str = os.getenv("NIDS_DEFAULT_SOURCE_NAME", "homelab-flow-bridge")
    # Optional zeek-conn-window-v2 tree bundle; its pickle loads only if the SHA-256 matches. The
    # NIDS_SHADOW_MODEL_* names are the pre-promotion spelling and are still accepted.
    v2_model_dir: Path | None = (_optional_path_env("NIDS_V2_MODEL_DIR")
                                 or _optional_path_env("NIDS_SHADOW_MODEL_DIR"))
    v2_model_sha256: str = os.getenv("NIDS_V2_MODEL_SHA256", "") or os.getenv("NIDS_SHADOW_MODEL_SHA256", "")
    # Which model's labels are operational: "keras" (v2, if configured, runs in shadow) or "v2" (v2 labels
    # flows it can judge, Keras labels the rest and runs in shadow on the flows v2 judged).
    operational_model: str = os.getenv("NIDS_OPERATIONAL_MODEL", "keras").strip().lower()
    # v2 mode only: relabel lone unanswered SYNs BENIGN instead of alerting (app/alert_rules.py).
    suppress_lone_unanswered_syn: str = os.getenv("NIDS_SUPPRESS_LONE_UNANSWERED_SYN", "true").strip().lower()
    # v2 mode only: flows v2 cannot judge (cold or degraded window, no v2 features, v2 failing) are stored as
    # "unvalidated" with the reason, or keep the Keras fallback label with "keras".
    v2_undecided: str = os.getenv("NIDS_V2_UNDECIDED", "unvalidated").strip().lower()
    # v2 mode only: BOTNET predictions are stored as "unvalidated" (botnet_detection_not_validated), or "alert".
    botnet_alerts: str = os.getenv("NIDS_BOTNET_ALERTS", "unvalidated").strip().lower()

    def __post_init__(self) -> None:
        if self.suppress_lone_unanswered_syn not in ("true", "false"):
            raise ValueError("NIDS_SUPPRESS_LONE_UNANSWERED_SYN must be 'true' or 'false'.")
        if self.v2_undecided not in ("unvalidated", "keras"):
            raise ValueError("NIDS_V2_UNDECIDED must be 'unvalidated' or 'keras'.")
        if self.botnet_alerts not in ("unvalidated", "alert"):
            raise ValueError("NIDS_BOTNET_ALERTS must be 'unvalidated' or 'alert'.")
        for name in ("public_window_minutes", "stale_after_seconds", "max_history_hours", "retention_hours"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive.")
        if self.operational_model not in ("keras", "v2"):
            raise ValueError("NIDS_OPERATIONAL_MODEL must be 'keras' or 'v2'.")
        if self.operational_model == "v2" and self.v2_model_dir is None:
            raise ValueError("NIDS_OPERATIONAL_MODEL=v2 requires NIDS_V2_MODEL_DIR.")
        if self.public_window_minutes > self.retention_hours * 60:
            raise ValueError("The recent window cannot exceed retention.")
        if self.max_history_hours > self.retention_hours:
            raise ValueError("The history window cannot exceed retention.")


settings = Settings()
