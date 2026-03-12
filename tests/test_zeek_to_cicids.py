from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.inference import FlowClassifier
from app.storage import PredictionRow, StatsStore, utcnow
from sensor.zeek_to_cicids import conn_record_to_flow, export_log_once


SAMPLE_CONN_RECORD = {
    "ts": 1710200000.25,
    "uid": "CbXwre3xQ4example",
    "id.orig_h": "10.0.0.15",
    "id.orig_p": 52344,
    "id.resp_h": "10.0.0.25",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 1.5,
    "orig_bytes": 4096,
    "resp_bytes": 2048,
    "conn_state": "SF",
    "local_orig": True,
    "local_resp": False,
    "missed_bytes": 0,
    "history": "ShADadFfPp",
    "orig_pkts": 12,
    "orig_ip_bytes": 4920,
    "resp_pkts": 8,
    "resp_ip_bytes": 2864,
}


class ZeekToCicidsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.feature_order = json.loads((cls.repo_root / "feature_order.json").read_text(encoding="utf-8"))

    def build_validator(self) -> FlowClassifier:
        validator = FlowClassifier(
            model_path=Path("unused.keras"),
            scaler_path=Path("unused.joblib"),
            feature_order_path=Path("unused.json"),
            label_map_path=Path("unused.json"),
            label_encoder_path=Path("unused.joblib"),
        )
        validator._feature_order = list(self.feature_order)
        return validator

    def test_conn_record_produces_complete_numeric_schema(self) -> None:
        flow = conn_record_to_flow(SAMPLE_CONN_RECORD)

        self.assertEqual(set(flow["features"]), set(self.feature_order))
        validator = self.build_validator()
        vector = validator._build_feature_vector(flow["features"])

        self.assertEqual(len(vector), len(self.feature_order))
        self.assertEqual(flow["features"]["dst_port"], 443.0)
        self.assertEqual(flow["features"]["src_port"], 52344.0)
        self.assertEqual(flow["features"]["protocol"], 6.0)
        self.assertEqual(flow["features"]["tot_fwd_pkts"], 12.0)
        self.assertEqual(flow["features"]["tot_bwd_pkts"], 8.0)

    def test_export_log_once_posts_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            log_path = temp_path / "conn.log"
            state_file = temp_path / "state.json"
            log_path.write_text(json.dumps(SAMPLE_CONN_RECORD) + "\n", encoding="utf-8")

            with patch("sensor.zeek_to_cicids.send_payload", return_value={"stored": 1}) as send_payload:
                exported = export_log_once(
                    log_path=log_path,
                    endpoint="http://nids.default.svc.cluster.local/api/internal/flows",
                    state_file=state_file,
                    source_name="zeek-worker-node-a",
                    token="secret-token",
                    batch_size=100,
                )

            self.assertEqual(exported, 1)
            send_payload.assert_called_once()
            endpoint, token, source_name, flows = send_payload.call_args.args
            self.assertEqual(endpoint, "http://nids.default.svc.cluster.local/api/internal/flows")
            self.assertEqual(token, "secret-token")
            self.assertEqual(source_name, "zeek-worker-node-a")
            self.assertEqual(len(flows), 1)
            self.assertEqual(set(flows[0]["features"]), set(self.feature_order))

    def test_exported_batch_matches_ingest_contract_and_summary_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            log_path = temp_path / "conn.log"
            state_file = temp_path / "state.json"
            db_path = temp_path / "nids.sqlite3"
            log_path.write_text(json.dumps(SAMPLE_CONN_RECORD) + "\n", encoding="utf-8")

            captured_payload: dict[str, object] = {}

            def fake_send(endpoint: str, token: str, source_name: str, flows: list[dict]) -> dict:
                captured_payload["endpoint"] = endpoint
                captured_payload["token"] = token
                captured_payload["source"] = source_name
                captured_payload["flows"] = flows
                return {"stored": len(flows)}

            with patch("sensor.zeek_to_cicids.send_payload", side_effect=fake_send):
                export_log_once(
                    log_path=log_path,
                    endpoint="http://nids.default.svc.cluster.local/api/internal/flows",
                    state_file=state_file,
                    source_name="zeek-worker-node-a",
                    token="secret-token",
                    batch_size=100,
                )

            flow = captured_payload["flows"][0]

            validator = self.build_validator()
            validator._build_feature_vector(flow["features"])

            store = StatsStore(db_path, labels=["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"])
            store.initialize()
            store.record_predictions(
                captured_payload["source"],
                [
                    PredictionRow(
                        observed_at=utcnow(),
                        predicted_label="BENIGN",
                        confidence=0.99,
                    )
                ],
            )

            summary = store.build_summary(recent_window_minutes=60, history_hours=24)
            self.assertEqual(summary["recent_counts"]["BENIGN"], 1)
            self.assertEqual(summary["all_time_counts"]["BENIGN"], 1)
            self.assertEqual(summary["sources"][0]["source"], "zeek-worker-node-a")
            store.close()


if __name__ == "__main__":
    unittest.main()
