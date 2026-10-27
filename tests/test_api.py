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
            stale_after_seconds=90,
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
        self.assertEqual(data["stale_after_seconds"], 90)

    def test_icmpv6_is_separate_and_raw_predictions_are_private(self):
        payload = {"source": "zeek", "flows": [
            {"flow_id": f"test-{i}", "event_time": utcnow().isoformat(),
             "features": {"tot_fwd_pkts": 2, "tot_bwd_pkts": 2, "protocol": protocol}}
            for i, protocol in enumerate((58, 58, 6, 1))
        ]}
        labels = ["DOS_DDOS", "BENIGN", "BOTNET", "OTHER_ATTACK"]
        # The API attaches protocol metadata even if a classifier implementation
        # returns only the four raw labels. Clients cannot choose their status.
        rows = [PredictionRow(utcnow(), label, 0.99) for label in labels]
        with patch.object(main.classifier, "classify_batch", return_value=rows):
            first = self.post(payload)
            second = self.post(payload)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["labels"], {
            "BENIGN": 0, "BOTNET": 1, "DOS_DDOS": 0, "OTHER_ATTACK": 1, "UNVALIDATED": 2})
        self.assertEqual(second.json()["duplicates"], 4)
        summary = self.client.get("/api/public/summary").json()
        self.assertEqual(summary["recent_counts"], first.json()["labels"])
        self.assertEqual(summary["retained_counts"], first.json()["labels"])
        self.assertEqual(summary["lifetime_flows"], 4)
        self.assertEqual(summary["lifetime_packets"], 16)
        self.assertEqual(sum(summary["retained_counts"].values()), summary["total_events"])
        self.assertEqual(sum(b["counts"]["UNVALIDATED"] for b in summary["hourly"]), 2)
        self.assertTrue(any("ICMPv6" in warning for warning in summary["warnings"]))
        self.assertNotIn("flow_id", str(summary))
        self.assertEqual(self.client.get("/api/internal/events").status_code, 403)
        self.assertEqual(self.client.get("/api/internal/events", headers={"X-Ingest-Token": "wrong"}).status_code, 403)
        headers = {"X-Ingest-Token": "test-token"}
        response = self.client.get("/api/internal/events?validation_status=unvalidated&limit=1", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        event = response.json()[0]
        self.assertEqual(event["predicted_label"], "BENIGN")
        self.assertEqual(event["validation_status"], "unvalidated")
        self.assertEqual(event["validation_reason"], "icmpv6_detection_not_validated")
        self.assertEqual(event["protocol"], 58)
        self.assertEqual(event["confidence"], 0.99)
        older = self.client.get(f"/api/internal/events?validation_status=unvalidated&before_id={event['id']}", headers=headers).json()
        self.assertEqual(len(older), 1)
        self.assertEqual(older[0]["predicted_label"], "DOS_DDOS")
        for query in ("limit=201", "limit=0", "before_id=0", "before_id=99999999999999999999", "validation_status=invalid"):
            self.assertEqual(self.client.get("/api/internal/events?" + query, headers=headers).status_code, 422)

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
        payload = {"source": "zeek", "flows": [{"flow_id": "test-flow", "event_time": utcnow().isoformat(),
                   "features": {"tot_fwd_pkts": 12, "tot_bwd_pkts": 8}}]}
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

    def payload(self):
        return {"source": "zeek", "flows": [{"flow_id": "flow-1", "event_time": utcnow().isoformat(),
                "features": {"tot_fwd_pkts": 12, "tot_bwd_pkts": 8}}]}

    def post(self, payload):
        return self.client.post("/api/internal/flows", json=payload, headers={"X-Ingest-Token": "test-token"})

    def test_retries_only_increment_once_and_conflicting_identity_is_atomic(self):
        payload = self.payload()
        with patch.object(main.classifier, "classify_batch", return_value=[PredictionRow(utcnow(), "BENIGN", 0.99)]):
            first = self.post(payload).json()
            second = self.post(payload).json()
            self.assertEqual((first["inserted"], second["inserted"], second["duplicates"]), (1, 0, 1))
            self.assertEqual(second["flow_ids"], ["flow-1"])
            payload["flows"][0]["features"]["tot_fwd_pkts"] = 13
            self.assertEqual(self.post(payload).status_code, 409)
        summary = self.client.get("/api/public/summary").json()
        self.assertEqual((summary["lifetime_flows"], summary["lifetime_packets"]), (1, 20))
        self.assertEqual(summary["retained_packets"], 20)
        self.assertTrue(summary["packet_counts_complete"])
        self.assertEqual(summary["retained_counts"], summary["all_time_counts"])

    def test_invalid_inputs_never_reach_classifier(self):
        with patch.object(main.classifier, "classify_batch") as classify:
            for value in (-1, 1.5, True, "12", 2**53, 10**400):
                payload = self.payload()
                payload["flows"][0]["features"]["tot_fwd_pkts"] = value
                self.assertEqual(self.post(payload).status_code, 422)
            for timestamp in ("2026-01-01T00:00:00", (utcnow() + timedelta(days=1)).isoformat()):
                payload = self.payload()
                payload["flows"][0]["event_time"] = timestamp
                self.assertEqual(self.post(payload).status_code, 422)
            payload = self.payload()
            payload["flows"] *= 1001
            self.assertEqual(self.post(payload).status_code, 422)
            classify.assert_not_called()

    def test_invalid_prediction_batch_does_not_mutate_storage(self):
        for rows in ([], [PredictionRow(utcnow(), "BENIGN", 1.7)], [PredictionRow(utcnow(), "UNKNOWN", 0.9)]):
            with patch.object(main.classifier, "classify_batch", return_value=rows):
                self.assertEqual(self.post(self.payload()).status_code, 503)
        self.assertEqual(self.client.get("/api/public/summary").json()["lifetime_flows"], 0)

    def test_auth_and_current_readiness(self):
        self.assertEqual(self.client.post("/api/internal/flows", json=self.payload()).status_code, 403)
        self.assertEqual(self.client.get("/readyz").status_code, 503)
        with patch.object(main.classifier, "_model", object()), patch.object(main.classifier, "_scaler", object()), patch.object(main.classifier, "_np", object()):
            self.assertEqual(self.client.get("/readyz").status_code, 200)
            with patch.object(main.classifier, "_runtime_error", "bad scores"):
                self.assertEqual(self.client.get("/readyz").status_code, 503)

    def test_nonfinite_json_is_rejected_without_error_serialization_failure(self):
        import json
        payload = self.payload()
        payload["flows"][0]["features"]["tot_fwd_pkts"] = float("nan")
        response = self.client.post("/api/internal/flows", content=json.dumps(payload),
            headers={"X-Ingest-Token": "test-token", "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("NaN", response.text)

    def test_oversized_ingestion_body_is_rejected(self):
        response = self.client.post("/api/internal/flows", content=b" " * (8 * 1024 * 1024 + 1),
                                   headers={"X-Ingest-Token": "test-token"})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
