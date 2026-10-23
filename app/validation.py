"""Shared numeric rules for the ingestion and inference boundaries."""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

MAX_PACKET_COUNT = 2**53 - 1
MAX_BATCH_SIZE = 1000


def validate_features(features: dict) -> dict:
    if not isinstance(features, dict):
        raise ValueError("features must be an object.")
    for name, value in features.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Feature {name!r} must be a finite number.")
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError(f"Feature {name!r} must be a finite number.")
    for name in ("tot_fwd_pkts", "tot_bwd_pkts"):
        value = features.get(name)
        if value is None or value < 0 or value > MAX_PACKET_COUNT or int(value) != value:
            raise ValueError(f"{name} must be a nonnegative safe integer.")
    if sum(features[name] for name in ("tot_fwd_pkts", "tot_bwd_pkts")) > MAX_PACKET_COUNT:
        raise ValueError("Total packet count exceeds the supported range.")
    for name, maximum in (("src_port", 65535), ("dst_port", 65535), ("protocol", 255)):
        if name in features:
            value = features[name]
            if value < 0 or value > maximum or int(value) != value:
                raise ValueError(f"{name} must be an integer between 0 and {maximum}.")
    if features.get("flow_duration", 0) < 0:
        raise ValueError("flow_duration must be nonnegative.")
    return features


def validate_event_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("event_time must include a timezone.")
    value = value.astimezone(UTC)
    if value < datetime(1970, 1, 1, tzinfo=UTC) or value > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("event_time must be after the epoch and no more than five minutes in the future.")
    return value
