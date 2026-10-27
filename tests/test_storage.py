from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from app.storage import FlowConflict, PredictionRow, StatsStore, utcnow


LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]


class LifetimeFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = Path(self.temp_dir.name) / "nids.sqlite3"

    def open_store(self) -> StatsStore:
        store = StatsStore(self.db_path, labels=LABELS)
        store.initialize()
        self.addCleanup(store.close)
        return store

    def summary(self, store: StatsStore) -> dict:
        return store.build_summary(recent_window_minutes=60, history_hours=24)

    def rows(self, count: int, *, old: bool = False) -> list[PredictionRow]:
        observed_at = utcnow() - timedelta(days=40) if old else utcnow()
        return [PredictionRow(observed_at, "BENIGN", 0.99) for _ in range(count)]

    def test_empty_database_and_batches_count_flows_separately_from_packets(self) -> None:
        store = self.open_store()
        self.assertEqual(self.summary(store)["lifetime_flows"], 0)

        store.record_predictions("zeek", self.rows(2), lifetime_packet_total=200)
        store.record_predictions("zeek", self.rows(3), lifetime_packet_total=300)
        store.record_predictions("zeek", [])

        summary = self.summary(store)
        self.assertEqual(summary["lifetime_flows"], 5)
        self.assertEqual(summary["lifetime_packets"], 500)
        self.assertEqual(summary["total_events"], 5)

    def test_lifetime_flows_survive_purge_and_restart(self) -> None:
        store = StatsStore(self.db_path, labels=LABELS)
        store.initialize()
        try:
            store.record_predictions("zeek", self.rows(3, old=True))
            self.assertEqual(store.purge_old_events(retention_hours=24 * 28), 3)
            self.assertEqual(self.summary(store)["lifetime_flows"], 3)
            self.assertEqual(self.summary(store)["total_events"], 0)
        finally:
            store.close()

        restarted = self.open_store()
        restarted.record_predictions("zeek", self.rows(2))
        self.assertEqual(self.summary(restarted)["lifetime_flows"], 5)
        self.assertEqual(self.summary(restarted)["total_events"], 2)

    def test_migration_recovers_history_recorded_before_counter_existed(self) -> None:
        store = self.open_store()
        store.record_predictions("zeek", self.rows(3, old=True))
        store.record_predictions("zeek", self.rows(2))
        store.purge_old_events(retention_hours=24 * 28)
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute("DELETE FROM lifetime_counters WHERE name = 'classified_events'")

        store.initialize()
        store.initialize()
        self.assertEqual(self.summary(store)["lifetime_flows"], 5)
        self.assertEqual(self.summary(store)["total_events"], 2)
        store.record_predictions("zeek", self.rows(1))
        self.assertEqual(self.summary(store)["lifetime_flows"], 6)

    def test_migration_repairs_partial_history_without_lowering_existing_total(self) -> None:
        store = self.open_store()
        store.record_predictions("zeek", self.rows(4))
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute("UPDATE lifetime_counters SET value = 2 WHERE name = 'classified_events'")
        store.initialize()
        self.assertEqual(self.summary(store)["lifetime_flows"], 4)

        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute("UPDATE lifetime_counters SET value = 10 WHERE name = 'classified_events'")
        store.initialize()
        self.assertEqual(self.summary(store)["lifetime_flows"], 10)

    def test_failed_counter_write_rolls_back_events_and_all_counters(self) -> None:
        store = self.open_store()
        store.record_predictions("zeek", self.rows(1), lifetime_packet_total=10)
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER fail_packet_counter BEFORE UPDATE ON lifetime_counters
                WHEN NEW.name = 'observed_packets'
                BEGIN SELECT RAISE(ABORT, 'simulated counter write failure'); END
                """
            )

        with self.assertRaises(sqlite3.IntegrityError):
            store.record_predictions("zeek", self.rows(2), lifetime_packet_total=20)
        summary = self.summary(store)
        self.assertEqual(summary["lifetime_flows"], 1)
        self.assertEqual(summary["lifetime_packets"], 10)
        self.assertEqual(summary["total_events"], 1)
        store.initialize()
        self.assertEqual(self.summary(store)["lifetime_flows"], 1)

    def test_separate_connections_cannot_lose_counter_increments(self) -> None:
        stores = [self.open_store() for _ in range(4)]
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(store.record_predictions, f"zeek-{index}", self.rows(10))
                for index, store in enumerate(stores)
            ]
            for future in futures:
                future.result()
        self.assertEqual(self.summary(stores[0])["lifetime_flows"], 40)
        self.assertEqual(self.summary(stores[0])["total_events"], 40)

    def test_concurrent_duplicates_survive_retention_and_restart(self):
        stores = [self.open_store() for _ in range(4)]
        row = PredictionRow(utcnow() - timedelta(days=40), "BENIGN", 0.9, "uid", 20, "hash")
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda store: store.record_predictions("sensor", [row]), stores))
        self.assertEqual(sum(sum(counts.values()) for counts in results), 1)
        stores[0].purge_old_events(24)
        restarted = self.open_store()
        self.assertFalse(restarted.record_predictions("sensor", [row]))
        summary = self.summary(restarted)
        self.assertEqual((summary["lifetime_flows"], summary["lifetime_packets"]), (1, 20))
        self.assertEqual(summary["total_events"], 0)
        self.assertIsNotNone(summary["last_processed_at"])

    def test_identity_conflict_rolls_back_whole_batch(self):
        store = self.open_store()
        store.record_predictions("sensor", [PredictionRow(utcnow(), "BENIGN", 0.9, "old", 20, "original")])
        with self.assertRaises(FlowConflict):
            store.record_predictions("sensor", [
                PredictionRow(utcnow(), "BENIGN", 0.9, "new", 10, "new"),
                PredictionRow(utcnow(), "BENIGN", 0.9, "old", 30, "changed"),
            ])
        summary = self.summary(store)
        self.assertEqual((summary["lifetime_flows"], summary["lifetime_packets"]), (1, 20))
        self.assertEqual(sum(store.record_predictions("sensor", [
            PredictionRow(utcnow(), "BENIGN", 0.9, "new", 10, "new")]).values()), 1)

    def test_future_records_are_excluded_from_windows_and_timestamps_have_distinct_meanings(self):
        store = self.open_store()
        store.record_predictions("sensor", [PredictionRow(utcnow() + timedelta(days=2), "BENIGN", 0.9)])
        summary = self.summary(store)
        self.assertEqual(sum(summary["recent_counts"].values()), 0)
        self.assertEqual(sum(sum(bucket["counts"].values()) for bucket in summary["hourly"]), 0)
        self.assertLess(summary["last_processed_at"], summary["last_observed_at"])
        self.assertEqual(sum(summary["retained_counts"].values()), summary["total_events"])

    def test_duplicate_reservation_rolls_back_with_counter_failure(self):
        store = self.open_store()
        store.record_predictions("sensor", [PredictionRow(utcnow(), "BENIGN", 0.9)], 10)
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute("""CREATE TRIGGER fail_counter BEFORE UPDATE ON lifetime_counters
                BEGIN SELECT RAISE(ABORT, 'failure'); END""")
        row = PredictionRow(utcnow(), "BENIGN", 0.9, "uid", 20, "hash")
        with self.assertRaises(sqlite3.IntegrityError):
            store.record_predictions("sensor", [row])
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute("DROP TRIGGER fail_counter")
        self.assertEqual(sum(store.record_predictions("sensor", [row]).values()), 1)

    def test_actual_legacy_schema_upgrade_preserves_totals_and_marks_unknown_packets(self):
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.executescript("""
                CREATE TABLE classified_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
                    observed_at TEXT NOT NULL, predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL, created_at TEXT NOT NULL
                );
                INSERT INTO classified_events
                (source, observed_at, predicted_label, confidence, created_at)
                VALUES ('old-sensor', '2024-01-01 00:00:00', 'BENIGN', 0.8, '2024-01-02 00:00:00');
            """)
        store = self.open_store()
        summary = self.summary(store)
        self.assertEqual(summary["lifetime_flows"], 1)
        self.assertFalse(summary["packet_counts_complete"])
        self.assertIn("legacy", summary["counter_provenance"])
        event = store.list_events()[0]
        self.assertEqual(event["validation_status"], "legacy")
        self.assertIsNone(event["protocol"])
        self.assertEqual(summary["retained_counts"]["UNVALIDATED"], 0)
        self.assertEqual(summary["retained_counts"]["BENIGN"], 1)
        self.assertLess(summary["last_observed_at"], summary["last_processed_at"])
        store.purge_old_events(24)
        summary = self.summary(store)
        self.assertEqual(summary["lifetime_flows"], 1)
        self.assertIsNotNone(summary["last_processed_at"])

    def test_unvalidated_status_survives_restart_and_keeps_raw_prediction(self):
        store = self.open_store()
        row = PredictionRow(utcnow(), "DOS_DDOS", 0.999, "icmpv6-uid", 4, "hash", 58)
        self.assertEqual(dict(store.record_predictions("sensor", [row])), {"UNVALIDATED": 1})
        store.close()
        reopened = self.open_store()
        summary = self.summary(reopened)
        self.assertEqual(summary["retained_counts"]["UNVALIDATED"], 1)
        self.assertEqual(summary["retained_counts"]["DOS_DDOS"], 0)
        self.assertEqual(summary["lifetime_flows"], 1)
        self.assertEqual(summary["lifetime_packets"], 4)
        self.assertEqual(dict(reopened.record_predictions("sensor", [row])), {})
        event = reopened.list_events(validation_status="unvalidated")[0]
        self.assertEqual(event["predicted_label"], "DOS_DDOS")
        self.assertEqual(event["confidence"], 0.999)
        self.assertEqual(event["protocol"], 58)
        with patch("app.storage.utcnow", return_value=utcnow() + timedelta(hours=2)):
            self.assertEqual(reopened.purge_old_events(1), 1)
        self.assertEqual(reopened.list_events(validation_status="unvalidated"), [])
        self.assertEqual(self.summary(reopened)["lifetime_flows"], 1)
        self.assertEqual(dict(reopened.record_predictions("sensor", [row])), {})

    def test_retained_totals_remain_exact_after_duplicate_and_purge(self):
        store = self.open_store()
        old = utcnow() - timedelta(days=40)
        rows = [
            PredictionRow(old, "BENIGN", 0.9, "old", 4, "old-hash"),
            PredictionRow(utcnow(), "DOS_DDOS", 0.9, "v6", 2, "v6-hash", 58),
            PredictionRow(utcnow(), "BENIGN", 0.9, "new", 3, "new-hash"),
        ]
        store.record_predictions("sensor", rows)
        store.record_predictions("sensor", rows)
        self.assertEqual(store.purge_old_events(24 * 28), 1)
        summary = self.summary(store)
        self.assertEqual(summary["retained_counts"], {
            "BENIGN": 1, "BOTNET": 0, "DOS_DDOS": 0,
            "OTHER_ATTACK": 0, "UNVALIDATED": 1,
        })
        self.assertEqual((summary["total_events"], summary["retained_packets"],
                          summary["lifetime_flows"]), (2, 5, 3))
        self.assertTrue(summary["packet_counts_complete"])
        store.initialize()
        self.assertEqual(self.summary(store)["total_events"], 2)

    def test_readiness_does_not_wait_for_summary_connection_lock(self):
        store = self.open_store()
        with store._lock:
            store.check_ready()


if __name__ == "__main__":
    unittest.main()
