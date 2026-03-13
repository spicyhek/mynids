from __future__ import annotations

import sqlite3
import threading
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
                """
            )
        # region agent log
        agent_log("app/storage.py:84", "sqlite_initialize_ok", {}, hypothesis_id="H2")
        # endregion

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def record_predictions(self, source: str, rows: list[PredictionRow]) -> Counter[str]:
        created_at = to_sqlite_dt(utcnow())
        counts: Counter[str] = Counter()
        with self._lock, self._connection:
            self._connection.executemany(
                """
                INSERT INTO classified_events (
                    source,
                    observed_at,
                    predicted_label,
                    confidence,
                    created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        source,
                        to_sqlite_dt(row.observed_at),
                        row.predicted_label,
                        row.confidence,
                        created_at,
                    )
                    for row in rows
                ],
            )
        for row in rows:
            counts[row.predicted_label] += 1
        return counts

    def purge_old_events(self, retention_hours: int) -> int:
        cutoff = to_sqlite_dt(utcnow() - timedelta(hours=retention_hours))
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM classified_events WHERE observed_at < ?",
                (cutoff,),
            )
            return cursor.rowcount

    def build_summary(self, recent_window_minutes: int, history_hours: int) -> dict:
        now = utcnow()
        recent_cutoff = to_sqlite_dt(now - timedelta(minutes=recent_window_minutes))
        history_cutoff = to_sqlite_dt(now - timedelta(hours=history_hours))

        all_time_counts = {label: 0 for label in self._labels}
        recent_counts = {label: 0 for label in self._labels}
        hourly: dict[datetime, dict[str, int]] = {}
        sources: list[dict[str, int | str]] = []
        total_events = 0
        last_classified_at: datetime | None = None

        with self._lock:
            total_row = self._connection.execute(
                "SELECT COUNT(*) AS total, MAX(observed_at) AS latest FROM classified_events"
            ).fetchone()
            total_events = int(total_row["total"])
            last_classified_at = from_sqlite_dt(total_row["latest"])

            for row in self._connection.execute(
                """
                SELECT predicted_label, COUNT(*) AS total
                FROM classified_events
                GROUP BY predicted_label
                """
            ):
                label = str(row["predicted_label"])
                if label in all_time_counts:
                    all_time_counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT predicted_label, COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ?
                GROUP BY predicted_label
                """,
                (recent_cutoff,),
            ):
                label = str(row["predicted_label"])
                if label in recent_counts:
                    recent_counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT
                    strftime('%Y-%m-%d %H:00:00', observed_at) AS bucket_start,
                    predicted_label,
                    COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ?
                GROUP BY bucket_start, predicted_label
                ORDER BY bucket_start ASC
                """,
                (history_cutoff,),
            ):
                bucket = from_sqlite_dt(str(row["bucket_start"]))
                if bucket is None:
                    continue
                counts = hourly.setdefault(bucket, {label: 0 for label in self._labels})
                label = str(row["predicted_label"])
                if label in counts:
                    counts[label] = int(row["total"])

            for row in self._connection.execute(
                """
                SELECT source, COUNT(*) AS total
                FROM classified_events
                WHERE observed_at >= ?
                GROUP BY source
                ORDER BY total DESC, source ASC
                LIMIT 8
                """,
                (history_cutoff,),
            ):
                sources.append({"source": str(row["source"]), "total": int(row["total"])})

        bucket_rows = [
            {"bucket_start": bucket, "counts": counts}
            for bucket, counts in sorted(hourly.items(), key=lambda item: item[0])
        ]

        return {
            "generated_at": now,
            "total_events": total_events,
            "recent_counts": recent_counts,
            "all_time_counts": all_time_counts,
            "hourly": bucket_rows,
            "sources": sources,
            "last_classified_at": last_classified_at,
        }
