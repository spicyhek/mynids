from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.inference import ModelArtifacts
from app.storage import PredictionRow, StatsStore, utcnow


LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]


class SummaryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        settings = replace(
            main.settings,
            db_path=Path(temp_dir.name) / "nids.sqlite3",
            retention_hours=24 * 28,
            ingest_token="test-token",
        )
        self.enterContext(patch.object(main, "settings", settings))
        self.enterContext(patch.object(main.classifier, "load", return_value=ModelArtifacts(LABELS, [])))
        self.client = self.enterContext(TestClient(main.app))
        self.store: StatsStore = main.app.state.store

    def test_summary_exposes_persistent_flow_total_and_configured_retention(self) -> None:
        self.store.record_predictions("zeek", [PredictionRow(utcnow(), "BENIGN", 0.99)], 20)
        response = self.client.get("/api/public/summary")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        data = response.json()
        self.assertEqual(data["lifetime_flows"], 1)
        self.assertEqual(data["lifetime_packets"], 20)
        self.assertEqual(data["retention_hours"], 672)

    def test_summary_expires_old_records_when_ingestion_has_stopped(self) -> None:
        self.store.record_predictions(
            "zeek", [PredictionRow(utcnow() - timedelta(days=29), "BOTNET", 0.99)], 20
        )
        data = self.client.get("/api/public/summary").json()
        self.assertEqual(data["total_events"], 0)
        self.assertEqual(data["all_time_counts"]["BOTNET"], 0)
        self.assertEqual(data["lifetime_flows"], 1)
        self.assertEqual(data["lifetime_packets"], 20)

    def test_ingestion_counts_classified_rows_and_rejects_failed_classification(self) -> None:
        payload = {"source": "zeek", "flows": [{"features": {"tot_fwd_pkts": 12, "tot_bwd_pkts": 8}}]}
        with patch.object(main.classifier, "classify_batch", return_value=[PredictionRow(utcnow(), "BENIGN", 0.99)]):
            response = self.client.post("/api/internal/flows", json=payload, headers={"X-Ingest-Token": "test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stored"], 1)

        with patch.object(main.classifier, "classify_batch", side_effect=ValueError("Missing required features")):
            response = self.client.post("/api/internal/flows", json=payload, headers={"X-Ingest-Token": "test-token"})
        self.assertEqual(response.status_code, 422)
        data = self.client.get("/api/public/summary").json()
        self.assertEqual(data["lifetime_flows"], 1)
        self.assertEqual(data["lifetime_packets"], 20)


if __name__ == "__main__":
    unittest.main()
