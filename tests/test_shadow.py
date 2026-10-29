"""Shadow evaluation: optional v2 inputs, pinned model loading, isolated storage, exporter safety."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import error

import joblib
import numpy as np
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main
from app.inference import ModelArtifacts
from app.schemas import FlowBatchRequest
from app.shadow import CONTRACT_ID, MODEL_FILE, ShadowClassifier
from app.storage import PredictionRow, utcnow
from sensor.zeek_features_v2 import FEATURE_ORDER, Extractor
from sensor.zeek_to_cicids import FeatureV2Stream, export_log_once

LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
V1_LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]
CONN = {"ts": 1710200000.25, "uid": "Cshadow", "id.orig_h": "10.0.0.15", "id.orig_p": 52344,
        "id.resp_h": "10.0.0.25", "id.resp_p": 443, "proto": "tcp", "duration": 1.5, "orig_bytes": 4096,
        "resp_bytes": 2048, "conn_state": "SF", "missed_bytes": 0, "history": "ShADadFf", "orig_pkts": 12,
        "orig_ip_bytes": 4920, "resp_pkts": 8, "resp_ip_bytes": 2864}


def write_bundle(directory: Path) -> str:
    """A tiny real tree model: BENIGN for port 443, DOS_DDOS for port 80."""
    from sklearn.ensemble import HistGradientBoostingClassifier

    directory.mkdir(parents=True)
    port = list(FEATURE_ORDER).index("dst_port")
    matrix = np.zeros((40, len(FEATURE_ORDER)), dtype=np.float32)
    matrix[:20, port], matrix[20:, port] = 443, 80
    model = HistGradientBoostingClassifier(max_iter=10, random_state=0).fit(matrix, [0] * 20 + [3] * 20)
    joblib.dump(model, directory / MODEL_FILE)
    (directory / "feature_order.json").write_text(json.dumps(list(FEATURE_ORDER)))
    (directory / "label_map.json").write_text(json.dumps(dict(enumerate(LABELS))))
    (directory / "feature_contract.json").write_text(json.dumps(
        {"feature_contract": CONTRACT_ID, "feature_order": list(FEATURE_ORDER)}))
    return hashlib.sha256((directory / MODEL_FILE).read_bytes()).hexdigest()


def v2_flow(flow_id: str, *, port: int = 443, warm: bool = True, degraded: bool = False, protocol: int = 6) -> dict:
    features = Extractor().process({**CONN, "id.resp_p": port})["features"]
    features["protocol"] = float(protocol)
    return {"flow_id": flow_id, "event_time": utcnow().isoformat(),
            "features": {"tot_fwd_pkts": 2, "tot_bwd_pkts": 2, "protocol": protocol},
            "features_v2": features, "window_warm": warm, "window_degraded": degraded}


class ShadowSchemaTests(unittest.TestCase):
    def test_v2_fields_are_optional_but_travel_together(self):
        flow = v2_flow("a")
        FlowBatchRequest.model_validate({"source": "s", "flows": [{k: flow[k] for k in ("flow_id", "event_time", "features")}]})
        FlowBatchRequest.model_validate({"source": "s", "features_v2_contract": CONTRACT_ID, "flows": [flow]})
        with self.assertRaisesRegex(ValidationError, "features_v2_contract"):
            FlowBatchRequest.model_validate({"source": "s", "flows": [flow]})
        partial = {k: v for k, v in flow.items() if k != "window_degraded"}
        with self.assertRaisesRegex(ValidationError, "sent together"):
            FlowBatchRequest.model_validate({"source": "s", "features_v2_contract": CONTRACT_ID, "flows": [partial]})
        broken = {**flow, "features_v2": {**flow["features_v2"], "dst_port": float("nan")}}
        with self.assertRaises(ValidationError):
            FlowBatchRequest.model_validate({"source": "s", "features_v2_contract": CONTRACT_ID, "flows": [broken]})


class ShadowClassifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "candidate"
        self.sha = write_bundle(self.directory)

    def test_unpinned_or_mismatched_model_is_never_unpickled(self):
        for pinned in ("", "0" * 64):
            with self.subTest(pinned=pinned), patch("joblib.load") as load:
                classifier = ShadowClassifier(self.directory, pinned)
                with self.assertRaises(RuntimeError):
                    classifier.load()
                load.assert_not_called()
                self.assertFalse(classifier.loaded)

    def test_bundle_must_declare_the_v2_contract(self):
        (self.directory / "feature_contract.json").write_text(json.dumps({"feature_contract": "zeek-conn-v1"}))
        with self.assertRaisesRegex(RuntimeError, "not a zeek-conn-window-v2 bundle"):
            ShadowClassifier(self.directory, self.sha).load()

    def test_statuses_follow_window_and_protocol_flags(self):
        classifier = ShadowClassifier(self.directory, self.sha)
        classifier.load()
        self.assertEqual(classifier.model_id, f"candidate:{self.sha[:12]}")
        flows = [v2_flow("ok"), v2_flow("dos", port=80), v2_flow("cold", warm=False),
                 v2_flow("lossy", degraded=True, warm=False), v2_flow("icmp6", protocol=58),
                 {k: v for k, v in v2_flow("v1-only").items() if k == "flow_id" or k == "features"}]
        result = {p.flow_id: p for p in classifier.classify(CONTRACT_ID, flows)}
        self.assertNotIn("v1-only", result)
        self.assertEqual((result["ok"].predicted_label, result["ok"].validation_status), ("BENIGN", "classified"))
        self.assertEqual(result["dos"].predicted_label, "DOS_DDOS")
        self.assertEqual(result["cold"].validation_reason, "window_not_warm")
        self.assertEqual(result["lossy"].validation_reason, "window_degraded")
        self.assertEqual(result["icmp6"].validation_reason, "icmpv6_detection_not_validated")
        with self.assertRaisesRegex(ValueError, "does not match the shadow model"):
            classifier.classify("zeek-conn-v9", flows)
        missing = v2_flow("missing")
        del missing["features_v2"]["src_conns"]
        with self.assertRaisesRegex(ValueError, "feature order"):
            classifier.classify(CONTRACT_ID, [missing])


class ShadowApiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        sha = write_bundle(root / "candidate")
        self.shadow = ShadowClassifier(root / "candidate", sha)
        self.shadow.load()
        settings = replace(main.settings, db_path=root / "nids.sqlite3", ingest_token="test-token")
        self.enterContext(patch.object(main, "settings", settings))
        self.enterContext(patch.object(main, "shadow", self.shadow))
        self.enterContext(patch.object(main.classifier, "load", return_value=ModelArtifacts(V1_LABELS, [])))
        self.client = self.enterContext(TestClient(main.app))
        self.headers = {"X-Ingest-Token": "test-token"}

    def post(self, flows, labels, contract=CONTRACT_ID):
        rows = [PredictionRow(utcnow(), label, 0.9) for label in labels]
        payload = {"source": "zeek", "flows": flows}
        if contract:
            payload["features_v2_contract"] = contract
        with patch.object(main.classifier, "classify_batch", return_value=rows):
            return self.client.post("/api/internal/flows", json=payload, headers=self.headers)

    def test_shadow_rows_are_separate_from_operational_output(self):
        flows = [v2_flow("a"), v2_flow("b", port=80), v2_flow("c", warm=False)]
        first = self.post(flows, ["DOS_DDOS", "DOS_DDOS", "BENIGN"])
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["labels"]["DOS_DDOS"], 2)
        self.assertEqual(first.json()["labels"]["BENIGN"], 1)
        self.assertEqual(self.post(flows, ["DOS_DDOS", "DOS_DDOS", "BENIGN"]).json()["duplicates"], 3)
        public = self.client.get("/api/public/summary").json()
        self.assertEqual(public["total_events"], 3)
        self.assertNotIn("shadow", json.dumps(public).lower())
        self.assertEqual(self.client.get("/api/internal/shadow/summary").status_code, 403)
        summary = self.client.get("/api/internal/shadow/summary", headers=self.headers).json()
        model = summary["models"][self.shadow.model_id]
        self.assertTrue(summary["shadow_available"])
        self.assertEqual(model["flows"], 3)  # The replay added nothing.
        self.assertEqual(model["classified"], 2)
        self.assertEqual(model["unvalidated_reasons"], {"window_not_warm": 1})
        self.assertEqual(model["agreement"], {"DOS_DDOS": {"BENIGN": 1, "DOS_DDOS": 1}})
        self.assertEqual((model["production_alerts"], model["shadow_alerts"]), (2, 1))

    def test_v2_payload_does_not_change_v1_identity(self):
        flow = v2_flow("same")
        self.assertEqual(self.post([flow], ["BENIGN"]).status_code, 200)
        v1_only = {k: flow[k] for k in ("flow_id", "event_time", "features")}
        replay = self.post([v1_only], ["BENIGN"], contract=None)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["duplicates"], 1)

    def test_shadow_failure_never_fails_ingestion(self):
        response = self.post([v2_flow("x")], ["BENIGN"], contract="zeek-conn-v9")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["stored"], 1)
        with patch.object(self.shadow, "classify", side_effect=RuntimeError("model crashed")):
            self.assertEqual(self.post([v2_flow("y")], ["BENIGN"]).status_code, 200)
        summary = self.client.get("/api/internal/shadow/summary", headers=self.headers).json()
        self.assertEqual(summary["models"], {})

    def test_unavailable_shadow_is_a_warning_not_degraded_health(self):
        with patch.object(self.shadow, "_model", None):
            health = self.client.get("/healthz").json()
        self.assertTrue(any("Shadow model" in warning for warning in health["warnings"]))
        self.assertNotIn("Shadow", json.dumps(self.client.get("/api/public/summary").json()))


class ExporterShadowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "conn.log"
        self.log.write_text("".join(json.dumps({**CONN, "uid": f"C{i}", "ts": CONN["ts"] + i * 40}) + "\n"
                                    for i in range(3)) + json.dumps({**CONN, "uid": "Cvx", "proto": "udp",
                                                                     "id.resp_p": 8472}) + "\n")

    def export(self, stream, send):
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=send):
            return export_log_once(log_path=self.log, endpoint="http://nids/api/internal/flows",
                                   state_file=self.root / "state.json", source_name="zeek-a", token="t",
                                   batch_size=100, features_v2=stream)

    def test_flows_carry_window_features_and_carriers_stay_v1_only(self):
        sent = []

        def send(endpoint, token, source, flows):
            sent.extend(flows)
            return {"source": source, "received": len(flows), "inserted": len(flows), "duplicates": 0,
                    "flow_ids": [f["flow_id"] for f in flows]}

        self.assertEqual(self.export(FeatureV2Stream(), send), 4)
        self.assertEqual([f["features_v2"]["src_conns"] for f in sent[:3]], [1, 2, 2])
        # Records end at +1.5 s, +41.5 s and +81.5 s: only the third is 60 s past the first.
        self.assertEqual([f["window_warm"] for f in sent[:3]], [False, False, True])
        self.assertNotIn("features_v2", sent[3])  # VXLAN carrier: operational v1 flow only.

    def test_lines_are_fed_to_the_window_once(self):
        stream = FeatureV2Stream()
        record = json.loads(self.log.read_text().splitlines()[0])
        self.assertIsNotNone(stream.process("file-a", 100, record))
        self.assertIsNone(stream.process("file-a", 100, record))
        self.assertEqual(stream.process("file-b", 100, record)["features"]["src_conns"], 2)

    def test_server_without_shadow_support_keeps_every_v1_flow(self):
        attempts = []

        def old_server(endpoint, token, source, flows):
            attempts.append(flows)
            if any("features_v2" in flow for flow in flows):
                raise error.HTTPError(endpoint, 422, "Unprocessable", {}, None)
            return {"source": source, "received": len(flows), "inserted": len(flows), "duplicates": 0,
                    "flow_ids": [f["flow_id"] for f in flows]}

        self.assertEqual(self.export(FeatureV2Stream(), old_server), 4)
        self.assertEqual(len(attempts), 2)
        self.assertFalse((self.root / "state.json.quarantine.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
