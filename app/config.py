from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def _path_env(name: str, default: str | Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


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

    def __post_init__(self) -> None:
        for name in ("public_window_minutes", "stale_after_seconds", "max_history_hours", "retention_hours"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive.")
        if self.public_window_minutes > self.retention_hours * 60:
            raise ValueError("The recent window cannot exceed retention.")
        if self.max_history_hours > self.retention_hours:
            raise ValueError("The history window cannot exceed retention.")


settings = Settings()
