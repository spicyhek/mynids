from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.debug_log import agent_log
from app.storage import PredictionRow, utcnow


@dataclass(frozen=True)
class ModelArtifacts:
    labels: list[str]
    feature_order: list[str]


class FlowClassifier:
    def __init__(
        self,
        *,
        model_path: Path,
        scaler_path: Path,
        feature_order_path: Path,
        label_map_path: Path,
        label_encoder_path: Path,
    ) -> None:
        self._model_path = model_path
        self._scaler_path = scaler_path
        self._feature_order_path = feature_order_path
        self._label_map_path = label_map_path
        self._label_encoder_path = label_encoder_path
        self._model: Any | None = None
        self._scaler: Any | None = None
        self._np: Any | None = None
        self._tf: Any | None = None
        self._labels: list[str] = []
        self._feature_order: list[str] = []
        self._load_error: str | None = None

    @property
    def labels(self) -> list[str]:
        return list(self._labels)

    @property
    def load_error(self) -> str | None:
        return self._load_error

    @property
    def loaded(self) -> bool:
        return self._model is not None and self._scaler is not None and self._np is not None

    def load(self) -> ModelArtifacts:
        if self.loaded:
            return ModelArtifacts(labels=self.labels, feature_order=list(self._feature_order))

        # region agent log
        agent_log(
            "app/inference.py:60",
            "load_start",
            {
                "model_path": str(self._model_path),
                "model_exists": self._model_path.exists(),
                "scaler_exists": self._scaler_path.exists(),
                "feature_order_exists": self._feature_order_path.exists(),
                "label_map_exists": self._label_map_path.exists(),
                "label_encoder_exists": self._label_encoder_path.exists(),
            },
            hypothesis_id="H1",
        )
        # endregion
        try:
            import joblib
            import numpy as np
            import tensorflow as tf
        except Exception as exc:  # pragma: no cover - depends on local runtime
            self._load_error = (
                "Unable to import model runtime dependencies. "
                "Use the container or a Python version supported by TensorFlow. "
                f"Original error: {exc}"
            )
            # region agent log
            agent_log(
                "app/inference.py:81",
                "runtime_import_failed",
                {"error_type": type(exc).__name__, "error": str(exc)},
                hypothesis_id="H3",
            )
            # endregion
            raise RuntimeError(self._load_error) from exc

        # region agent log
        agent_log("app/inference.py:88", "runtime_import_ok", {}, hypothesis_id="H3")
        # endregion

        with self._feature_order_path.open("r", encoding="utf-8") as fh:
            feature_order = json.load(fh)
        with self._label_map_path.open("r", encoding="utf-8") as fh:
            label_map = json.load(fh)

        self._np = np
        self._tf = tf
        self._scaler = joblib.load(self._scaler_path)
        # Loading the label encoder validates that the artifact exists even though
        # the label map is used as the canonical public class order.
        joblib.load(self._label_encoder_path)
        # region agent log
        agent_log(
            "app/inference.py:101",
            "artifacts_loaded_before_model",
            {"feature_count": len(feature_order), "label_count": len(label_map)},
            hypothesis_id="H1",
        )
        # endregion
        self._model = tf.keras.models.load_model(self._model_path)
        self._feature_order = [str(name) for name in feature_order]
        self._labels = [str(label_map[str(index)]) for index in range(len(label_map))]
        self._load_error = None
        # region agent log
        agent_log(
            "app/inference.py:110",
            "model_loaded",
            {"labels_count": len(self._labels), "feature_count": len(self._feature_order)},
            hypothesis_id="H3",
        )
        # endregion
        return ModelArtifacts(labels=self.labels, feature_order=list(self._feature_order))

    def classify_batch(self, flows: list[dict[str, Any]]) -> list[PredictionRow]:
        if not flows:
            return []
        if not self.loaded:
            self.load()

        assert self._np is not None
        assert self._scaler is not None
        assert self._model is not None

        matrix = self._np.asarray(
            [self._build_feature_vector(flow["features"]) for flow in flows],
            dtype=self._np.float32,
        )
        scaled = self._scaler.transform(matrix)
        probabilities = self._model.predict(scaled, verbose=0)
        winners = probabilities.argmax(axis=1)

        rows: list[PredictionRow] = []
        for index, flow in enumerate(flows):
            observed_at = self._normalize_event_time(flow.get("event_time"))
            label_index = int(winners[index])
            rows.append(
                PredictionRow(
                    observed_at=observed_at,
                    predicted_label=self._labels[label_index],
                    confidence=float(probabilities[index][label_index]),
                )
            )
        return rows

    def _build_feature_vector(self, features: dict[str, Any]) -> list[float]:
        if not isinstance(features, dict):
            raise ValueError("Each flow must include a features object.")

        values: list[float] = []
        missing: list[str] = []
        for name in self._feature_order:
            if name not in features:
                missing.append(name)
                continue
            try:
                value = float(features[name])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Feature {name!r} must be numeric.") from exc
            if not math.isfinite(value):
                raise ValueError(f"Feature {name!r} must be finite.")
            values.append(value)

        if missing:
            preview = ", ".join(missing[:5])
            suffix = "" if len(missing) <= 5 else ", ..."
            raise ValueError(f"Missing required features: {preview}{suffix}")

        return values

    @staticmethod
    def _normalize_event_time(value: Any) -> datetime:
        if value is None:
            return utcnow()
        if isinstance(value, datetime):
            return value.astimezone(UTC).replace(microsecond=0)
        raise ValueError("event_time must be a valid ISO-8601 timestamp.")
