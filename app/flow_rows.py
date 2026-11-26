"""Stored rows for an ingest batch, before any model labels them.

Every flow carries the v1 feature set (feature_order.json, the ingest contract the converter has sent since 1.0.0)
and, from current converters, zeek-conn-window-v2 features for the model. The v1 features no longer feed a model
(the Keras model was removed in 2.0.0), but they are still validated exactly, because they define the flow's
fingerprint (deduplication), packet count and protocol, and the ICMPv6 rule reads the message type from them.

A row starts unvalidated with no label. The v2 model and the alert rules replace that for the flows they judge.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.storage import UNVALIDATED, PredictionRow
from app.validation import validate_event_time, validate_features

FLOAT32_MAX = 3.4028234663852886e38  # The v1 contract's numeric range (the Keras input dtype it was defined for).


def load_feature_order(path: Path) -> list[str]:
    order = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(order, list) or not order or not all(isinstance(name, str) and name for name in order)
            or len(set(order)) != len(order)):
        raise ValueError("Feature order must contain unique, nonempty names.")
    return order


def check_features(features: Any, feature_order: list[str]) -> None:
    """Raise ValueError unless features is exactly the v1 feature set with finite, float32-range values."""
    if not isinstance(features, dict):
        raise ValueError("Each flow must include a features object.")
    validate_features(features)
    extra = set(features) - set(feature_order)
    if extra:
        raise ValueError(f"Unexpected features: {', '.join(sorted(extra)[:5])}")
    missing = [name for name in feature_order if name not in features]
    if missing:
        raise ValueError(f"Missing required features: {', '.join(missing[:5])}{', ...' if len(missing) > 5 else ''}")
    if any(not math.isfinite(float(value)) or abs(float(value)) > FLOAT32_MAX for value in features.values()):
        raise ValueError("Features exceed the float32 range.")


def unlabeled_rows(flows: list[dict[str, Any]], feature_order: list[str]) -> list[PredictionRow]:
    """One unvalidated, unlabeled row per flow (FlowRecord.model_dump() dicts); the whole batch is validated first."""
    for flow in flows:
        check_features(flow.get("features"), feature_order)
    rows = []
    for flow in flows:
        features, event_time = flow["features"], flow["event_time"]
        if not isinstance(event_time, datetime):
            raise ValueError("event_time must be a valid ISO-8601 timestamp.")
        canonical = json.dumps({"event_time": event_time.astimezone(UTC).isoformat(), "features": features},
                               sort_keys=True, separators=(",", ":"), allow_nan=False)
        rows.append(PredictionRow(
            observed_at=validate_event_time(event_time).replace(microsecond=0),
            predicted_label=UNVALIDATED, confidence=0.0, flow_id=flow["flow_id"],
            payload_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            packet_count=int(features["tot_fwd_pkts"]) + int(features["tot_bwd_pkts"]),
            protocol=int(features["protocol"]) if "protocol" in features else None,
            unvalidated_reason="v2_unavailable"))
    return rows
