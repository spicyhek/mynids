from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.shadow import CONTRACT_ID, ICMPV6_REASON, WINDOW_DEGRADED, WINDOW_NOT_WARM, ShadowPrediction
from app.storage import PredictionRow, StatsStore, utcnow
from sensor.zeek_to_cicids import conn_record_to_flow
from test_zeek_to_cicids import SAMPLE_CONN_RECORD


LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]


class FakeTree:
    """Stands in for the v2 bundle: labels come from labels_by_flow, validation reasons follow app/shadow.py."""
    model_id = "fake-v2:000000000000"
    model_dir = Path("fake-v2")
    loaded = True
    load_error = None

    def __init__(self) -> None:
        self.labels_by_flow: dict[str, str] = {}
        self.labels = list(LABELS)

    def load(self) -> None:
        pass

    def classify(self, contract, flows):
        predictions = []
        for flow in flows:
            if flow.get("features_v2") is None:
                continue
            reason = (WINDOW_DEGRADED if flow["window_degraded"] else WINDOW_NOT_WARM if not flow["window_warm"]
                      else ICMPV6_REASON if flow["features_v2"]["protocol"] == 58 else None)
            predictions.append(ShadowPrediction(flow["flow_id"], self.labels_by_flow.get(flow["flow_id"], "BENIGN"),
                                                0.99, "unvalidated" if reason else "classified", reason))
        return predictions


def flow(flow_id: str, *, protocol: int = 6, warm: bool = True, packets: tuple[int, int] = (12, 8)) -> dict:
    """A converter flow with complete v1 features and minimal features_v2."""
    converted = conn_record_to_flow({**SAMPLE_CONN_RECORD, "uid": flow_id, "orig_pkts": packets[0],
                                     "resp_pkts": packets[1]})
    converted.update(flow_id=flow_id, event_time=utcnow().isoformat())
    converted["features"]["protocol"] = float(protocol)
    v2 = {"protocol": float(protocol), "dst_port": 443.0, "tot_fwd_pkts": float(packets[0]),
          "tot_bwd_pkts": float(packets[1])}
    return {**converted, "features_v2": v2,
            "window_warm": warm, "window_degraded": False}


def batch(*flows: dict) -> dict:
    return {"source": "zeek", "flows": list(flows), "features_v2_contract": CONTRACT_ID}


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
        self.tree = FakeTree()
        self.enterContext(patch.object(main, "tree", self.tree))
        self.client = self.enterContext(TestClient(main.app))
        self.store: StatsStore = main.app.state.store

    def payload(self):
        return batch(flow("flow-1"))

    def post(self, payload):
        return self.client.post("/api/internal/flows", json=payload, headers={"X-Ingest-Token": "test-token"})

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
        self.assertEqual(data["model_name"], "fake-v2")

    def test_icmpv6_is_separate_and_raw_predictions_are_private(self):
        flows = [flow(f"test-{i}", protocol=protocol, packets=(2, 2)) for i, protocol in enumerate((58, 58, 6, 1))]
        self.tree.labels_by_flow = dict(zip((f["flow_id"] for f in flows),
                                            ("DOS_DDOS", "BENIGN", "BRUTE_FORCE", "OTHER_ATTACK")))
        first = self.post(batch(*flows))
        second = self.post(batch(*flows))
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["labels"], {
            "BENIGN": 0, "BOTNET": 0, "BRUTE_FORCE": 1, "DOS_DDOS": 0, "OTHER_ATTACK": 1, "UNVALIDATED": 2})
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
        older = self.client.get(f"/api/internal/events?validation_status=unvalidated&before_id={event['id']}",
                                headers=headers).json()
        self.assertEqual(len(older), 1)
        self.assertEqual(older[0]["predicted_label"], "DOS_DDOS")
        for query in ("limit=201", "limit=0", "before_id=0", "before_id=99999999999999999999",
                      "validation_status=invalid"):
            self.assertEqual(self.client.get("/api/internal/events?" + query, headers=headers).status_code, 422)

    def test_summary_expires_old_records_when_ingestion_has_stopped(self) -> None:
        self.store.record_predictions(
            "zeek", [PredictionRow(utcnow() - timedelta(days=29), "BOTNET", 0.99)], 20
        )
        self.store.purge_old_events(main.settings.retention_hours)
        data = self.client.get("/api/public/summary").json()
        self.assertEqual(data["total_events"], 0)
        self.assertEqual(data["all_time_counts"]["BOTNET"], 0)
        self.assertEqual(data["lifetime_flows"], 1)
        self.assertEqual(data["lifetime_packets"], 20)

    def test_public_summary_does_not_run_retention_cleanup(self) -> None:
        with patch.object(self.store, "purge_old_events", side_effect=AssertionError("cleanup in request")):
            self.assertEqual(self.client.get("/api/public/summary").status_code, 200)

    def test_ingestion_counts_classified_rows_and_rejects_incomplete_features(self) -> None:
        response = self.post(self.payload())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual((response.json()["stored"], response.json()["labels"]["BENIGN"]), (1, 1))
        incomplete = batch(flow("flow-2"))
        del incomplete["flows"][0]["features"]["dst_port"]
        response = self.post(incomplete)
        self.assertEqual(response.status_code, 422)
        self.assertIn("Missing required features: dst_port", response.text)
        data = self.client.get("/api/public/summary").json()
        self.assertEqual(data["lifetime_flows"], 1)
        self.assertEqual(data["lifetime_packets"], 20)

    def test_retries_only_increment_once_and_conflicting_identity_is_atomic(self):
        payload = self.payload()
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

    def test_invalid_inputs_never_reach_the_model(self):
        with patch.object(self.tree, "classify") as classify:
            for value in (-1, 1.5, True, "12", 2**53, 10**400):
                payload = self.payload()
                payload["flows"][0]["features"]["tot_fwd_pkts"] = value
                self.assertEqual(self.post(payload).status_code, 422)
            for timestamp in ("2026-01-01T00:00:00", (utcnow() + timedelta(days=1)).isoformat()):
                payload = self.payload()
                payload["flows"][0]["event_time"] = timestamp
                self.assertEqual(self.post(payload).status_code, 422)
            payload = self.payload()
            payload["flows"][0]["features"]["src_port"] = 1e39  # Beyond the v1 contract's float32 range.
            self.assertEqual(self.post(payload).status_code, 422)
            payload = self.payload()
            payload["flows"] *= 1001
            self.assertEqual(self.post(payload).status_code, 422)
            classify.assert_not_called()

    def test_invalid_prediction_batch_does_not_mutate_storage(self):
        for prediction in (ShadowPrediction("flow-1", "BENIGN", 1.7, "classified", None),
                           ShadowPrediction("flow-1", "UNKNOWN", 0.9, "classified", None)):
            with patch.object(self.tree, "classify", return_value=[prediction]):
                self.assertEqual(self.post(self.payload()).status_code, 503)
        self.assertEqual(self.client.get("/api/public/summary").json()["lifetime_flows"], 0)

    def test_flows_the_model_cannot_judge_are_stored_unvalidated(self):
        with patch.object(self.tree, "classify", side_effect=RuntimeError("model crashed")):
            response = self.post(batch(flow("crash")))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["labels"]["UNVALIDATED"], 1)
        self.assertEqual(self.client.get("/healthz").json()["status"], "degraded")
        cold, v1_only = flow("cold", warm=False), flow("v1-only")
        for key in ("features_v2", "window_warm", "window_degraded"):
            del v1_only[key]
        self.assertEqual(self.post(batch(cold)).json()["labels"]["UNVALIDATED"], 1)
        self.assertEqual(self.client.get("/healthz").json()["status"], "ok")  # The model recovered.
        self.assertEqual(self.post({"source": "zeek", "flows": [v1_only]}).json()["labels"]["UNVALIDATED"], 1)
        events = {e["flow_id"]: e for e in self.client.get(
            "/api/internal/events", headers={"X-Ingest-Token": "test-token"}).json()}
        self.assertEqual({k: (e["predicted_label"], e["validation_reason"], e["model_id"]) for k, e in events.items()},
                         {"crash": ("UNVALIDATED", "v2_unavailable", None),
                          "cold": ("UNVALIDATED", "window_not_warm", None),
                          "v1-only": ("UNVALIDATED", "no_v2_features", None)})

    def test_auth_health_and_readiness(self):
        self.assertEqual(self.client.post("/api/internal/flows", json=self.payload()).status_code, 403)
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.client.get("/healthz").json()["status"], "ok")
        # Without a model the pod stays ready (flows are stored unvalidated) but reports degraded health.
        with patch.object(main, "tree", None):
            self.assertEqual(self.client.get("/readyz").status_code, 200)
            health = self.client.get("/healthz").json()
            self.assertEqual((health["status"], health["model_loaded"]), ("degraded", False))
            self.assertEqual(self.post(batch(flow("no-model"))).json()["labels"]["UNVALIDATED"], 1)
        with patch.object(main, "settings", replace(main.settings, ingest_token="")):
            self.assertEqual(self.client.get("/readyz").status_code, 503)

    def test_nonfinite_json_is_rejected_without_error_serialization_failure(self):
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


class ReleaseHeaderTests(unittest.TestCase):
    """mybuilds checks X-Release-ID on /healthz through Cloudflare, so the header must be fresh."""

    def client_with(self, release_id: str) -> TestClient:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        settings = replace(main.settings, db_path=Path(temp_dir.name) / "nids.sqlite3",
                           ingest_token="test-token", release_id=release_id)
        self.enterContext(patch.object(main, "settings", settings))
        return self.enterContext(TestClient(main.app))

    def test_healthz_carries_the_release_id_and_is_never_cached(self) -> None:
        client = self.client_with("mynids/0123456/production/57")
        response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-release-id"], "mynids/0123456/production/57")
        self.assertEqual(response.headers["cache-control"], "no-store")
        # The body is unchanged: mybuilds reads its status field.
        self.assertIn(response.json()["status"], ("ok", "degraded"))

    def test_only_healthz_gets_the_headers(self) -> None:
        client = self.client_with("mynids/0123456/production/57")
        # /readyz calls healthz() directly but is not mybuilds' check.
        readyz = client.get("/readyz")
        self.assertNotIn("x-release-id", readyz.headers)
        summary = client.get("/api/public/summary")
        self.assertNotIn("x-release-id", summary.headers)

    def test_unset_release_id_leaves_the_header_out(self) -> None:
        client = self.client_with("")
        response = client.get("/healthz")
        self.assertNotIn("x-release-id", response.headers)
        self.assertEqual(response.headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main()
