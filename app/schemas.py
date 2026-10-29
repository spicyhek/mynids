from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.validation import MAX_BATCH_SIZE, validate_event_time, validate_features


class FlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow_id: str = Field(min_length=1, max_length=200, pattern=r"^\S+$")
    event_time: datetime
    features: dict[str, float] = Field(min_length=2, max_length=80)
    # Optional shadow-contract inputs; the operational model never reads them.
    features_v2: dict[str, float] | None = Field(default=None, min_length=2, max_length=80)
    window_warm: bool | None = None
    window_degraded: bool | None = None

    _validate_time = field_validator("event_time")(validate_event_time)
    _validate_features = field_validator("features", mode="before")(validate_features)

    @field_validator("features_v2", mode="before")
    @classmethod
    def _validate_features_v2(cls, value):
        return value if value is None else validate_features(value)

    @model_validator(mode="after")
    def _window_flags_accompany_features_v2(self) -> "FlowRecord":
        if (self.features_v2 is None) != (self.window_warm is None) or \
                (self.features_v2 is None) != (self.window_degraded is None):
            raise ValueError("features_v2, window_warm and window_degraded must be sent together.")
        return self


class FlowBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    source: str = Field(min_length=1, max_length=128)
    flows: list[FlowRecord] = Field(min_length=1, max_length=MAX_BATCH_SIZE)
    features_v2_contract: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def _contract_names_features_v2(self) -> "FlowBatchRequest":
        if any(flow.features_v2 is not None for flow in self.flows) and self.features_v2_contract is None:
            raise ValueError("Batches with features_v2 must name features_v2_contract.")
        return self


class IngestResponse(BaseModel):
    source: str
    accepted: int
    stored: int
    received: int
    inserted: int
    duplicates: int
    flow_ids: list[str]
    labels: dict[str, int]
    generated_at: datetime


class EventResponse(BaseModel):
    id: int
    source: str
    flow_id: str | None
    observed_at: datetime
    created_at: datetime
    predicted_label: str
    confidence: float
    packet_count: int | None
    protocol: int | None
    validation_status: Literal["legacy", "classified", "unvalidated"]
    validation_reason: str | None


class SourceCount(BaseModel):
    source: str
    total: int


class SensorStatus(BaseModel):
    source: str
    last_received_at: datetime
    last_observed_at: datetime
    lag_seconds: int
    stale: bool


class TimeBucket(BaseModel):
    bucket_start: datetime
    counts: dict[str, int]


class SummaryResponse(BaseModel):
    generated_at: datetime
    model_name: str
    recent_window_minutes: int
    stale_after_seconds: int
    retention_hours: int
    lifetime_flows: int
    lifetime_packets: int
    total_events: int
    recent_counts: dict[str, int]
    all_time_counts: dict[str, int]
    retained_counts: dict[str, int]
    retained_packets: int
    packet_counts_complete: bool
    counter_provenance: str
    hourly: list[TimeBucket]
    sources: list[SourceCount]
    last_classified_at: datetime | None
    last_observed_at: datetime | None
    last_processed_at: datetime | None
    sensors: list[SensorStatus]
    ingest_enabled: bool
    warnings: list[str]


class HealthResponse(BaseModel):
    status: str
    generated_at: datetime
    model_loaded: bool
    ingest_enabled: bool
    warnings: list[str]
