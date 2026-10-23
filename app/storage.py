from __future__ import annotations

import sqlite3
import threading
import math
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.debug_log import agent_log


SQLITE_DT_FORMAT = "%Y-%m-%d %H:%M:%S"


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def to_sqlite_dt(value: datetime) -> str:
    normalized = value.astimezone(UTC).replace(tzinfo=None, microsecond=0)
    return normalized.strftime(SQLITE_DT_FORMAT)


def from_sqlite_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.strptime(value, SQLITE_DT_FORMAT)
    return parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class PredictionRow:
    observed_at: datetime
    predicted_label: str
    confidence: float
    flow_id: str | None = None
    packet_count: int | None = None
    payload_hash: str | None = None


class FlowConflict(ValueError):
    """An existing identity was submitted with different input data."""


class StatsStore:
    def __init__(self, db_path: Path, labels: list[str]) -> None:
        self._db_path = db_path
        self._labels = labels
        self._lock = threading.Lock()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # region agent log
        agent_log(
            "app/storage.py:45",
            "sqlite_connect_start",
            {"db_path": str(self._db_path), "parent_exists": self._db_path.parent.exists()},
            hypothesis_id="H2",
        )
        # endregion
        self._connection = sqlite3.connect(self._db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        # region agent log
        agent_log("app/storage.py:54", "sqlite_connect_ok", {}, hypothesis_id="H2")
        # endregion

    def initialize(self) -> None:
        # region agent log
        agent_log("app/storage.py:58", "sqlite_initialize_start", {}, hypothesis_id="H2")
        # endregion
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS classified_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_classified_events_observed
                    ON classified_events(observed_at);

                CREATE INDEX IF NOT EXISTS idx_classified_events_label
                    ON classified_events(predicted_label);

                CREATE INDEX IF NOT EXISTS idx_classified_events_source
                    ON classified_events(source);

                CREATE TABLE IF NOT EXISTS lifetime_counters (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seen_flows (
                    source TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    PRIMARY KEY (source, flow_id)
                );
                CREATE TABLE IF NOT EXISTS store_metadata (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sensor_status (
                    source TEXT PRIMARY KEY,
                    last_received_at TEXT NOT NULL,
                    last_observed_at TEXT NOT NULL,
                    last_processed_at TEXT
                );
                """
            )
            self._connection.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(classified_events)")}
            if "packet_count" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN packet_count INTEGER")
            if "flow_id" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN flow_id TEXT")
            # This app inserts one AUTOINCREMENT row per classified flow. The
            # sequence survives retention deletes and includes flows recorded
            # before lifetime counters were introduced.
            self._connection.execute(
                """
                INSERT INTO lifetime_counters (name, value)
                VALUES (
                    'classified_events',
                    COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'classified_events'), 0)
                )
                ON CONFLICT(name) DO UPDATE SET value = MAX(value, excluded.value)
                """
            )
            legacy = self._connection.execute(
                "SELECT value FROM lifetime_counters WHERE name = 'classified_events'"
            ).fetchone()["value"]
            self._connection.execute(
                "INSERT OR IGNORE INTO store_metadata VALUES ('counter_provenance', ?)",
                ("legacy totals preserved; exact deduplication begins at upgrade" if legacy else
                 "unique source/flow IDs; packets represented by ingested flows",),
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO sensor_status
                SELECT source, MAX(created_at), MAX(observed_at), MAX(created_at)
                FROM classified_events GROUP BY source
                """
            )
        # region agent log
        agent_log("app/storage.py:84", "sqlite_initialize_ok", {}, hypothesis_id="H2")
        # endregion

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def check_ready(self) -> None:
        with self._lock:
            self._connection.execute("SELECT value FROM lifetime_counters LIMIT 1").fetchone()

    def record_predictions(
        self, source: str, rows: list[PredictionRow], lifetime_packet_total: int = 0
    ) -> Counter[str]:
        created_at = to_sqlite_dt(utcnow())
        counts: Counter[str] = Counter()
        for row in rows:
            if row.predicted_label not in self._labels or not math.isfinite(row.confidence) or not 0 <= row.confidence <= 1:
                raise ValueError("Invalid prediction label or confidence.")
            if row.observed_at.tzinfo is None:
                raise ValueError("Prediction timestamp must include a timezone.")
            if row.flow_id is not None and (not row.flow_id or not row.payload_hash or row.packet_count is None):
                raise ValueError("Identified flows require a fingerprint and packet count.")
            if row.packet_count is not None and (type(row.packet_count) is not int or not 0 <= row.packet_count <= 2**53 - 1):
                raise ValueError("Packet count must be a nonnegative safe integer.")
        if type(lifetime_packet_total) is not int or lifetime_packet_total < 0:
            raise ValueError("Packet total must be a nonnegative integer.")
        if any(row.packet_count is not None for row in rows) and any(row.packet_count is None for row in rows):
            raise ValueError("A batch cannot mix known and unknown packet counts.")
        packets = 0 if all(row.packet_count is not None for row in rows) else lifetime_packet_total
        with self._lock, self._connection:
            # Reserve the writer before checking IDs, including across processes.
            self._connection.execute("BEGIN IMMEDIATE")
            for row in rows:
                if row.flow_id is not None:
                    existing = self._connection.execute(
                        "SELECT payload_hash FROM seen_flows WHERE source = ? AND flow_id = ?",
                        (source, row.flow_id),
                    ).fetchone()
                    if existing:
                        if existing["payload_hash"] != row.payload_hash:
                            raise FlowConflict("Flow ID already exists with different input data.")
                        continue
                    self._connection.execute(
                        "INSERT INTO seen_flows VALUES (?, ?, ?)", (source, row.flow_id, row.payload_hash)
                    )
                self._connection.execute(
                    """INSERT INTO classified_events
                    (source, observed_at, predicted_label, confidence, created_at, flow_id, packet_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (source, to_sqlite_dt(row.observed_at), row.predicted_label, row.confidence,
                     created_at, row.flow_id, row.packet_count),
                )
                counts[row.predicted_label] += 1
                packets += row.packet_count or 0
            self._connection.execute(
                """
                INSERT INTO lifetime_counters (name, value)
                VALUES ('classified_events', ?)
                ON CONFLICT(name) DO UPDATE SET value = value + excluded.value
                """,
                (sum(counts.values()),),
            )
            self._connection.execute(
                """
                INSERT INTO lifetime_counters (name, value)
                VALUES ('observed_packets', ?)
                ON CONFLICT(name) DO UPDATE SET value = value + excluded.value
                """,
                (packets,),
            )
            if rows:
                self._connection.execute(
                    """
                    INSERT INTO sensor_status VALUES (?, ?, ?, ?)
                    ON CONFLICT(source) DO UPDATE SET
                      last_received_at = excluded.last_received_at,
                      last_observed_at = MAX(last_observed_at, excluded.last_observed_at),
                      last_processed_at = COALESCE(excluded.last_processed_at, last_processed_at)
                    """,
                    (source, created_at, max(to_sqlite_dt(row.observed_at) for row in rows),
                     created_at if counts else None),
                )
            if self._connection.execute(
                "SELECT 1 FROM lifetime_counters WHERE typeof(value) != 'integer' OR value > ?",
                (2**53 - 1,),
            ).fetchone():
                raise OverflowError("Lifetime counter exceeds the supported integer range.")
        return counts

    def purge_old_events(self, retention_hours: int) -> int:
        cutoff = to_sqlite_dt(utcnow() - timedelta(hours=retention_hours))
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM classified_events WHERE observed_at < ?",
                (cutoff,),
            )
            return cursor.rowcount

    def build_summary(self, recent_window_minutes: int, history_hours: int, stale_after_seconds: int = 300) -> dict:
        now = utcnow()
        recent_cutoff = to_sqlite_dt(now - timedelta(minutes=recent_window_minutes))
        history_cutoff = to_sqlite_dt(now - timedelta(hours=history_hours))
        upper_bound = to_sqlite_dt(now)

        all_time_counts = {label: 0 for label in self._labels}
        recent_counts = {label: 0 for label in self._labels}
        hourly: dict[datetime, dict[str, int]] = {}
        sources: list[dict[str, int | str]] = []
        lifetime_flows = 0
        lifetime_packets = 0
        total_events = 0
        last_classified_at: datetime | None = None

        with self._lock, self._connection:
            self._connection.execute("BEGIN")
            counters = {
                str(row["name"]): int(row["value"])
                for row in self._connection.execute("SELECT name, value FROM lifetime_counters")
            }
            lifetime_flows = counters.get("classified_events", 0)
            lifetime_packets = counters.get("observed_packets", 0)

            total_row = self._connection.execute(
                """SELECT COUNT(*) AS total, COALESCE(SUM(packet_count), 0) AS packets,
                COUNT(packet_count) AS known_packets FROM classified_events"""
            ).fetchone()
            total_events = int(total_row["total"])
            retained_packets = int(total_row["packets"])
            packet_counts_complete = int(total_row["known_packets"]) == total_events
            sensor_rows = self._connection.execute("SELECT * FROM sensor_status ORDER BY source").fetchall()
            last_classified_at = max(
                (from_sqlite_dt(row["last_processed_at"]) for row in sensor_rows if row["last_processed_at"]),
                default=None,
            )
            last_observed_at = max(
                (from_sqlite_dt(row["last_observed_at"]) for row in sensor_rows), default=None
            )
            provenance = self._connection.execute(
                "SELECT value FROM store_metadata WHERE name = 'counter_provenance'"
            ).fetchone()["value"]

            for row in self._connection.execute(
                """
                SELECT predicted_label, COUNT(*) AS total
                FROM classified_events
                GROUP BY predicted_label
                """
            ):
                label = str(row["predicted_label"])
                all_time_counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT predicted_label, COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY predicted_label
                """,
                (recent_cutoff, upper_bound),
            ):
                label = str(row["predicted_label"])
                recent_counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT
                    strftime('%Y-%m-%d %H:00:00', observed_at) AS bucket_start,
                    predicted_label,
                    COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY bucket_start, predicted_label
                ORDER BY bucket_start ASC
                """,
                (history_cutoff, upper_bound),
            ):
                bucket = from_sqlite_dt(str(row["bucket_start"]))
                if bucket is None:
                    continue
                counts = hourly.setdefault(bucket, {label: 0 for label in self._labels})
                label = str(row["predicted_label"])
                counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT source, COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY source
                ORDER BY total DESC, source ASC
                LIMIT 8
                """,
                (history_cutoff, upper_bound),
            ):
                sources.append({"source": str(row["source"]), "total": int(row["total"])})

        bucket = (now - timedelta(hours=history_hours)).replace(minute=0, second=0)
        while bucket <= now:
            hourly.setdefault(bucket, dict.fromkeys(self._labels, 0))
            bucket += timedelta(hours=1)
        bucket_rows = [
            {"bucket_start": bucket, "counts": counts}
            for bucket, counts in sorted(hourly.items(), key=lambda item: item[0])
        ]

        return {
            "generated_at": now,
            "lifetime_flows": lifetime_flows,
            "lifetime_packets": lifetime_packets,
            "total_events": total_events,
            "recent_counts": recent_counts,
            "all_time_counts": all_time_counts,
            "retained_counts": all_time_counts,
            "retained_packets": retained_packets,
            "packet_counts_complete": packet_counts_complete,
            "counter_provenance": provenance,
            "hourly": bucket_rows,
            "sources": sources,
            "last_classified_at": last_classified_at,
            "last_processed_at": last_classified_at,
            "last_observed_at": last_observed_at,
            "sensors": [
                {
                    "source": row["source"],
                    "last_received_at": from_sqlite_dt(row["last_received_at"]),
                    "last_observed_at": from_sqlite_dt(row["last_observed_at"]),
                    "lag_seconds": max(0, int((now - from_sqlite_dt(row["last_observed_at"])).total_seconds())),
                    "stale": (now - from_sqlite_dt(row["last_received_at"])).total_seconds() >= stale_after_seconds,
                }
                for row in sensor_rows
            ],
        }
