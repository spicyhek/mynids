from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    event_time: datetime | None = None
    features: dict[str, float] = Field(default_factory=dict)


class FlowBatchRequest(BaseModel):
    source: str | None = None
    flows: list[FlowRecord] = Field(default_factory=list)


class IngestResponse(BaseModel):
    source: str
    accepted: int
    stored: int
    labels: dict[str, int]
    generated_at: datetime


class SourceCount(BaseModel):
    source: str
    total: int


class TimeBucket(BaseModel):
    bucket_start: datetime
    counts: dict[str, int]


class SummaryResponse(BaseModel):
    generated_at: datetime
    model_name: str
    recent_window_minutes: int
    total_events: int
    recent_counts: dict[str, int]
    all_time_counts: dict[str, int]
    hourly: list[TimeBucket]
    sources: list[SourceCount]
    last_classified_at: datetime | None
    ingest_enabled: bool
    warnings: list[str]


class HealthResponse(BaseModel):
    status: str
    generated_at: datetime
    model_loaded: bool
    ingest_enabled: bool
    warnings: list[str]
