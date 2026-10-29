"""Optional shadow classifier for the zeek-conn-window-v2 contract.

Shadow predictions are stored separately and never change operational labels, counters or the
dashboard. The model file is a pickle, so it loads only from an operator-configured directory and
only when its SHA-256 matches the pinned value.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import threading
from typing import Any

CONTRACT_ID = "zeek-conn-window-v2"
MODEL_FILE = "tree_model.joblib"
WINDOW_NOT_WARM = "window_not_warm"
WINDOW_DEGRADED = "window_degraded"
ICMPV6_REASON = "icmpv6_detection_not_validated"


@dataclass(frozen=True)
class ShadowPrediction:
    flow_id: str
    predicted_label: str
    confidence: float
    validation_status: str
    validation_reason: str | None


class ShadowClassifier:
    def __init__(self, model_dir: Path, expected_sha256: str) -> None:
        self._model_dir = model_dir
        self._expected_sha256 = expected_sha256.strip().lower()
        self._model: Any | None = None
        self._np: Any | None = None
        self._labels: list[str] = []
        self._feature_order: list[str] = []
        self.model_id: str | None = None
        self.load_error: str | None = None
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        return self._model is not None

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            try:
                self._load()
                self.load_error = None
            except Exception as exc:
                self.load_error = f"Shadow model unavailable: {exc}"
                raise RuntimeError(self.load_error) from exc

    def _load(self) -> None:
        path = self._model_dir / MODEL_FILE
        if len(self._expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in self._expected_sha256):
            raise ValueError("The pinned shadow model SHA-256 must be 64 hexadecimal characters.")
        with path.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != self._expected_sha256:
            raise ValueError("Shadow model hash differs from the pinned value; refusing to unpickle it.")
        feature_order = json.loads((self._model_dir / "feature_order.json").read_text(encoding="utf-8"))
        label_map = json.loads((self._model_dir / "label_map.json").read_text(encoding="utf-8"))
        contract = json.loads((self._model_dir / "feature_contract.json").read_text(encoding="utf-8"))
        if contract.get("feature_contract") != CONTRACT_ID or contract.get("feature_order") != feature_order:
            raise ValueError(f"Shadow bundle is not a {CONTRACT_ID} bundle.")
        if (not isinstance(feature_order, list) or len(set(feature_order)) != len(feature_order)
                or not isinstance(label_map, dict) or set(label_map) != {str(i) for i in range(len(label_map))}):
            raise ValueError("Shadow feature order or label map is malformed.")
        labels = [label_map[str(i)] for i in range(len(label_map))]

        import joblib
        import numpy as np

        model = joblib.load(path)
        if getattr(model, "n_features_in_", None) != len(feature_order):
            raise ValueError("Shadow model input width differs from its feature order.")
        if not set(int(c) for c in model.classes_) <= set(range(len(labels))):
            raise ValueError("Shadow model classes exceed its label map.")
        self._model, self._np = model, np
        self._labels, self._feature_order = labels, feature_order
        self.model_id = f"{self._model_dir.name}:{actual[:12]}"

    def classify(self, contract: str | None, flows: list[dict[str, Any]]) -> list[ShadowPrediction]:
        """Classify flows that carry features_v2; flows without them are skipped."""
        candidates = [flow for flow in flows if flow.get("features_v2") is not None]
        if not candidates:
            return []
        if contract != CONTRACT_ID:
            raise ValueError(f"Batch features_v2_contract {contract!r} does not match the shadow model.")
        if not self.loaded:
            self.load()
        names = set(self._feature_order)
        rows = []
        for flow in candidates:
            features = flow["features_v2"]
            if set(features) != names:
                raise ValueError("features_v2 does not match the shadow model's feature order.")
            rows.append([float(features[name]) for name in self._feature_order])
        np = self._np
        with np.errstate(over="ignore", invalid="ignore"):
            matrix = np.asarray(rows, dtype=np.float32)
        if not np.isfinite(matrix).all():
            raise ValueError("features_v2 exceed the float32 range.")
        with self._lock:
            probabilities = np.asarray(self._model.predict_proba(matrix))
        classes = [int(c) for c in self._model.classes_]
        if probabilities.shape != (len(candidates), len(classes)) or not np.isfinite(probabilities).all():
            raise RuntimeError("Shadow model returned invalid probabilities.")
        predictions = []
        for flow, row in zip(candidates, probabilities):
            winner = int(row.argmax())
            confidence = float(row[winner])
            if not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise RuntimeError("Shadow model returned an invalid confidence.")
            if flow["window_degraded"]:
                reason = WINDOW_DEGRADED
            elif not flow["window_warm"]:
                reason = WINDOW_NOT_WARM
            elif int(flow["features_v2"].get("protocol", -1)) == 58:
                reason = ICMPV6_REASON
            else:
                reason = None
            predictions.append(ShadowPrediction(
                flow_id=flow["flow_id"], predicted_label=self._labels[classes[winner]], confidence=confidence,
                validation_status="unvalidated" if reason else "classified", validation_reason=reason))
        return predictions
