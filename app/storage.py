from __future__ import annotations

import sqlite3
import threading
import math
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.debug_log import agent_log


SQLITE_DT_FORMAT = "%Y-%m-%d %H:%M:%S"
UNVALIDATED = "UNVALIDATED"
ICMPV6_REASON = "icmpv6_detection_not_validated"


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
    protocol: int | None = None

    @property
    def validation_status(self) -> str:
        return "unvalidated" if self.protocol == 58 else "classified"

    @property
    def validation_reason(self) -> str | None:
        return ICMPV6_REASON if self.protocol == 58 else None

    @property
    def summary_label(self) -> str:
        return UNVALIDATED if self.validation_status == "unvalidated" else self.predicted_label


class FlowConflict(ValueError):
    """An existing identity was submitted with different input data."""


class StatsStore:
    def __init__(self, db_path: Path, labels: list[str]) -> None:
        self._db_path = db_path
        self._labels = labels
        self._summary_labels = [*labels, UNVALIDATED]
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
        self._connection.execute("PRAGMA journal_mode=WAL")
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
                CREATE TABLE IF NOT EXISTS retained_totals (
                    label TEXT PRIMARY KEY,
                    events INTEGER NOT NULL,
                    packets INTEGER NOT NULL,
                    known_packets INTEGER NOT NULL
                );
                -- Shadow-model output only; never read by public summaries or counters.
                CREATE TABLE IF NOT EXISTS shadow_predictions (
                    source TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_reason TEXT,
                    production_label TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (source, flow_id, model_id)
                );
                CREATE INDEX IF NOT EXISTS idx_shadow_predictions_observed
                    ON shadow_predictions(observed_at);
                """
            )
            self._connection.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(classified_events)")}
            if "packet_count" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN packet_count INTEGER")
            if "flow_id" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN flow_id TEXT")
            if "protocol" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN protocol INTEGER")
            if "validation_status" not in columns:
                self._connection.execute(
                    "ALTER TABLE classified_events ADD COLUMN validation_status TEXT NOT NULL DEFAULT 'legacy'"
                )
            if "validation_reason" not in columns:
                self._connection.execute("ALTER TABLE classified_events ADD COLUMN validation_reason TEXT")
            self._connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_classified_events_unvalidated
                   ON classified_events(id) WHERE validation_status = 'unvalidated'"""
            )
            # Backfill once on upgrade, before installing triggers. A populated
            # table is maintained transactionally by inserts and retention deletes.
            if not self._connection.execute("SELECT 1 FROM retained_totals LIMIT 1").fetchone():
                self._connection.execute(
                    """INSERT INTO retained_totals (label, events, packets, known_packets)
                    SELECT CASE WHEN validation_status = 'unvalidated' THEN 'UNVALIDATED'
                                ELSE predicted_label END,
                           COUNT(*), COALESCE(SUM(packet_count), 0), COUNT(packet_count)
                    FROM classified_events GROUP BY 1"""
                )
            self._connection.execute(
                """CREATE TRIGGER IF NOT EXISTS classified_events_retained_insert
                AFTER INSERT ON classified_events BEGIN
                    INSERT INTO retained_totals (label, events, packets, known_packets)
                    VALUES (CASE WHEN NEW.validation_status = 'unvalidated' THEN 'UNVALIDATED'
                                 ELSE NEW.predicted_label END,
                            1, COALESCE(NEW.packet_count, 0), NEW.packet_count IS NOT NULL)
                    ON CONFLICT(label) DO UPDATE SET
                        events = events + excluded.events,
                        packets = packets + excluded.packets,
                        known_packets = known_packets + excluded.known_packets;
                END"""
            )
            self._connection.execute(
                """CREATE TRIGGER IF NOT EXISTS classified_events_retained_delete
                AFTER DELETE ON classified_events BEGIN
                    UPDATE retained_totals SET
                        events = events - 1,
                        packets = packets - COALESCE(OLD.packet_count, 0),
                        known_packets = known_packets - (OLD.packet_count IS NOT NULL)
                    WHERE label = CASE WHEN OLD.validation_status = 'unvalidated'
                                       THEN 'UNVALIDATED' ELSE OLD.predicted_label END;
                END"""
            )
            self._connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_classified_events_summary
                   ON classified_events(observed_at, validation_status, predicted_label, source)"""
            )
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
            if not self._connection.execute("SELECT 1 FROM sensor_status LIMIT 1").fetchone():
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
        # An independent WAL reader does not queue behind a long summary or
        # retention operation on the application's connection lock.
        with closing(sqlite3.connect(self._db_path, timeout=1)) as connection:
            connection.execute("SELECT value FROM lifetime_counters LIMIT 1").fetchone()

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
            if row.protocol is not None and (type(row.protocol) is not int or not 0 <= row.protocol <= 255):
                raise ValueError("Protocol must be an integer from 0 to 255.")
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
                    (source, observed_at, predicted_label, confidence, created_at, flow_id, packet_count,
                     protocol, validation_status, validation_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (source, to_sqlite_dt(row.observed_at), row.predicted_label, row.confidence,
                     created_at, row.flow_id, row.packet_count, row.protocol,
                     row.validation_status, row.validation_reason),
                )
                counts[row.summary_label] += 1
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

    def purge_old_events(self, retention_hours: int, max_batches: int | None = None) -> int:
        cutoff = to_sqlite_dt(utcnow() - timedelta(hours=retention_hours))
        deleted = 0
        batches = 0
        while max_batches is None or batches < max_batches:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    """DELETE FROM classified_events WHERE id IN
                       (SELECT id FROM classified_events WHERE observed_at < ? LIMIT 1000)""",
                    (cutoff,),
                )
                count = cursor.rowcount
            deleted += count
            batches += 1
            if count < 1000:
                break
        batches = 0
        while max_batches is None or batches < max_batches:
            with self._lock, self._connection:
                count = self._connection.execute(
                    """DELETE FROM shadow_predictions WHERE rowid IN
                       (SELECT rowid FROM shadow_predictions WHERE observed_at < ? LIMIT 1000)""",
                    (cutoff,),
                ).rowcount
            batches += 1
            if count < 1000:
                break
        return deleted

    def record_shadow_predictions(self, source: str, model_id: str, rows: list[tuple]) -> int:
        """Store (observed_at, production summary label, shadow prediction) rows; replays are ignored."""
        created_at = to_sqlite_dt(utcnow())
        values = []
        for observed_at, production_label, prediction in rows:
            if (not prediction.flow_id or not math.isfinite(prediction.confidence)
                    or not 0 <= prediction.confidence <= 1
                    or prediction.validation_status not in ("classified", "unvalidated")
                    or production_label not in self._summary_labels):
                raise ValueError("Invalid shadow prediction.")
            values.append((source, prediction.flow_id, model_id, to_sqlite_dt(observed_at),
                           prediction.predicted_label, prediction.confidence, prediction.validation_status,
                           prediction.validation_reason, production_label, created_at))
        with self._lock, self._connection:
            before = self._connection.total_changes
            self._connection.executemany(
                "INSERT OR IGNORE INTO shadow_predictions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values)
            return self._connection.total_changes - before

    def shadow_summary(self, history_hours: int) -> dict:
        cutoff = to_sqlite_dt(utcnow() - timedelta(hours=history_hours))
        models: dict[str, dict] = {}
        with self._lock:
            for row in self._connection.execute(
                """SELECT model_id, validation_status, validation_reason, production_label, predicted_label,
                          COUNT(*) AS total
                   FROM shadow_predictions WHERE observed_at >= ?
                   GROUP BY 1, 2, 3, 4, 5""",
                (cutoff,),
            ):
                model = models.setdefault(row["model_id"], {
                    "flows": 0, "classified": 0, "unvalidated_reasons": {}, "shadow_counts": {},
                    "agreement": {}, "production_alerts": 0, "shadow_alerts": 0})
                total = int(row["total"])
                model["flows"] += total
                production = row["production_label"]
                if production not in ("BENIGN", UNVALIDATED):
                    model["production_alerts"] += total
                if row["validation_status"] == "unvalidated":
                    reasons = model["unvalidated_reasons"]
                    reasons[row["validation_reason"]] = reasons.get(row["validation_reason"], 0) + total
                    continue
                model["classified"] += total
                shadow = row["predicted_label"]
                model["shadow_counts"][shadow] = model["shadow_counts"].get(shadow, 0) + total
                if shadow != "BENIGN":
                    model["shadow_alerts"] += total
                matrix = model["agreement"].setdefault(production, {})
                matrix[shadow] = matrix.get(shadow, 0) + total
        return {"generated_at": utcnow(), "history_hours": history_hours, "models": models}

    def build_summary(self, recent_window_minutes: int, history_hours: int, stale_after_seconds: int = 300) -> dict:
        now = utcnow()
        recent_cutoff = to_sqlite_dt(now - timedelta(minutes=recent_window_minutes))
        history_cutoff = to_sqlite_dt(now - timedelta(hours=history_hours))
        upper_bound = to_sqlite_dt(now)

        all_time_counts = {label: 0 for label in self._summary_labels}
        recent_counts = {label: 0 for label in self._summary_labels}
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

            retained_packets = 0
            known_packets = 0
            for row in self._connection.execute("SELECT * FROM retained_totals"):
                all_time_counts[str(row["label"])] = int(row["events"])
                retained_packets += int(row["packets"])
                known_packets += int(row["known_packets"])
            total_events = sum(all_time_counts.values())
            packet_counts_complete = known_packets == total_events
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
                SELECT CASE WHEN validation_status = 'unvalidated' THEN 'UNVALIDATED'
                       ELSE predicted_label END AS classification, COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY classification
                """,
                (recent_cutoff, upper_bound),
            ):
                label = str(row["classification"])
                recent_counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT
                    strftime('%Y-%m-%d %H:00:00', observed_at) AS bucket_start,
                    CASE WHEN validation_status = 'unvalidated' THEN 'UNVALIDATED'
                         ELSE predicted_label END AS classification,
                    COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY bucket_start, classification
                ORDER BY bucket_start ASC
                """,
                (history_cutoff, upper_bound),
            ):
                bucket = from_sqlite_dt(str(row["bucket_start"]))
                if bucket is None:
                    continue
                counts = hourly.setdefault(bucket, {label: 0 for label in self._summary_labels})
                label = str(row["classification"])
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
            hourly.setdefault(bucket, dict.fromkeys(self._summary_labels, 0))
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

    def list_events(self, *, limit: int = 100, before_id: int | None = None,
                    validation_status: str | None = None) -> list[dict]:
        if not 1 <= limit <= 200:
            raise ValueError("Event limit must be between 1 and 200.")
        clauses = []
        params = []
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        if validation_status is not None:
            if validation_status not in ("legacy", "classified", "unvalidated"):
                raise ValueError("Unknown validation status.")
            clauses.append("validation_status = ?")
            params.append(validation_status)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""SELECT id, source, flow_id, observed_at, created_at, predicted_label,
                    confidence, packet_count, protocol, validation_status, validation_reason
                    FROM classified_events {where} ORDER BY id DESC LIMIT ?""",
                [*params, limit],
            ).fetchall()
        return [{**dict(row), "observed_at": from_sqlite_dt(row["observed_at"]),
                 "created_at": from_sqlite_dt(row["created_at"])} for row in rows]
