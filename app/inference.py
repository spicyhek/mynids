from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.storage import PredictionRow, utcnow
from app.validation import validate_event_time, validate_features


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
        self._runtime_error: str | None = None
        self._lock = threading.RLock()
        self._inference_slot = threading.BoundedSemaphore(1)

    @property
    def labels(self) -> list[str]:
        return list(self._labels)

    @property
    def load_error(self) -> str | None:
        return self._load_error or self._runtime_error

    @property
    def loaded(self) -> bool:
        return self._model is not None and self._scaler is not None and self._np is not None

    def load(self) -> ModelArtifacts:
        with self._lock:
            try:
                return self._load()
            except Exception as exc:
                self._model = self._scaler = self._np = None
                self._load_error = f"Model initialization failed: {exc}"
                raise RuntimeError(self._load_error) from exc

    def _load(self) -> ModelArtifacts:
        if self.loaded:
            return ModelArtifacts(labels=self.labels, feature_order=list(self._feature_order))

        import joblib
        import numpy as np
        import tensorflow as tf

        with self._feature_order_path.open("r", encoding="utf-8") as fh:
            feature_order = json.load(fh)
        with self._label_map_path.open("r", encoding="utf-8") as fh:
            label_map = json.load(fh)

        if (not isinstance(feature_order, list) or not feature_order
                or not all(isinstance(name, str) and name for name in feature_order)
                or len(set(feature_order)) != len(feature_order)):
            raise ValueError("Feature order must contain unique, nonempty names.")
        if not isinstance(label_map, dict) or set(label_map) != {str(i) for i in range(len(label_map))}:
            raise ValueError("Label map must use contiguous class indices.")
        labels = [label_map[str(i)] for i in range(len(label_map))]
        if not labels or not all(isinstance(label, str) and label for label in labels) or len(set(labels)) != len(labels):
            raise ValueError("Class labels must be unique and nonempty.")
        scaler = joblib.load(self._scaler_path)
        encoder = joblib.load(self._label_encoder_path)
        model = tf.keras.models.load_model(self._model_path, compile=False)
        if list(encoder.classes_) != labels:
            raise ValueError("Label encoder and label map disagree.")
        if scaler.n_features_in_ != len(feature_order):
            raise ValueError("Scaler feature count disagrees with feature order.")
        if hasattr(scaler, "feature_names_in_") and list(scaler.feature_names_in_) != feature_order:
            raise ValueError("Scaler feature names disagree with feature order.")
        if "timestamp" in feature_order:
            timestamp_index = feature_order.index("timestamp")
            if (getattr(scaler, "mean_", None) is None
                    or getattr(scaler, "var_", None) is None
                    or scaler.mean_[timestamp_index] != 0.0
                    or scaler.var_[timestamp_index] != 0.0):
                raise ValueError("Timestamp preprocessing requires a constant-zero training feature.")
        if len(model.input_shape) != 2 or model.input_shape[-1] != len(feature_order):
            raise ValueError("Model input dimensions disagree with feature order.")
        if len(model.output_shape) != 2 or model.output_shape[-1] != len(labels):
            raise ValueError("Model output dimensions disagree with labels.")
        # Publish the complete, validated bundle together.
        self._np, self._tf, self._scaler, self._model = np, tf, scaler, model
        self._feature_order, self._labels = feature_order, labels
        self._load_error = None
        self._runtime_error = None
        return ModelArtifacts(labels=self.labels, feature_order=list(self._feature_order))

    def classify_batch(self, flows: list[dict[str, Any]]) -> list[PredictionRow]:
        if not flows:
            return []
        if not self._inference_slot.acquire(blocking=False):
            raise RuntimeError("Inference is busy; retry this batch.")
        try:
            return self._classify_batch(flows)
        finally:
            self._inference_slot.release()

    def _classify_batch(self, flows: list[dict[str, Any]]) -> list[PredictionRow]:
        if not self.loaded:
            self.load()

        assert self._np is not None
        assert self._scaler is not None
        assert self._model is not None

        observed_times = [self._normalize_event_time(flow.get("event_time")) for flow in flows]
        with self._np.errstate(over="ignore", invalid="ignore"):
            matrix = self._np.asarray(
                [self._build_feature_vector(flow["features"]) for flow in flows],
                dtype=self._np.float32,
            )
        if not self._np.isfinite(matrix).all():
            raise ValueError("Features exceed the float32 range.")
        if "timestamp" in self._feature_order:
            # The shipped model was trained with a constant-zero timestamp.
            # Normalize only its input matrix: retaining the original payload keeps
            # event times and deduplication hashes compatible with queued/old flows.
            matrix[:, self._feature_order.index("timestamp")] = 0.0
        try:
            scaled = self._scaler.transform(matrix)
            if scaled.shape != matrix.shape or not self._np.isfinite(scaled).all():
                raise RuntimeError("Scaler returned invalid features.")
            probabilities = self._np.asarray(self._model.predict(scaled, verbose=0))
            if (probabilities.shape != (len(flows), len(self._labels))
                    or not self._np.isfinite(probabilities).all()
                    or (probabilities < 0).any() or (probabilities > 1).any()
                    or not self._np.allclose(probabilities.sum(axis=1), 1.0, rtol=0, atol=1e-5)):
                raise RuntimeError("Model returned invalid probabilities.")
        except Exception as exc:
            self._runtime_error = f"Inference failed: {exc}"
            raise RuntimeError(self._runtime_error) from exc
        self._runtime_error = None
        winners = probabilities.argmax(axis=1)

        rows: list[PredictionRow] = []
        for index, flow in enumerate(flows):
            observed_at = observed_times[index]
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
        validate_features(features)
        extra = set(features) - set(self._feature_order)
        if extra:
            raise ValueError(f"Unexpected features: {', '.join(sorted(extra)[:5])}")

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
            return validate_event_time(value).replace(microsecond=0)
        raise ValueError("event_time must be a valid ISO-8601 timestamp.")
