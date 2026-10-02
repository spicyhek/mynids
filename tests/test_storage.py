from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from app.storage import PredictionRow, StatsStore, utcnow


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


if __name__ == "__main__":
    unittest.main()
