from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
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


def acknowledge(endpoint, token, source, flows):
    return {"source": source, "received": len(flows), "inserted": len(flows), "duplicates": 0,
            "flow_ids": [flow["flow_id"] for flow in flows]}


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

    def test_icmpv6_ip_protocol_survives_conversion(self):
        record = json.loads((self.repo_root / "tools/fixtures/smoke_icmpv6_conn.json").read_text())
        flow = conn_record_to_flow(record)
        self.assertEqual(flow["features"]["protocol"], 58.0)
        self.assertEqual(flow["features"]["tot_fwd_pkts"], 2.0)
        self.assertEqual(flow["features"]["tot_bwd_pkts"], 2.0)
        self.assertEqual(flow["features"]["src_port"], 135.0)
        self.assertEqual(flow["features"]["dst_port"], 136.0)
        self.assertEqual(set(flow["features"]), set(self.feature_order))
        self.assertEqual(flow["flow_id"], f"{record['uid']}:{flow['event_time']}")
        self.assertEqual(flow, conn_record_to_flow({k: v for k, v in record.items() if k != "ip_proto"}))

    def test_protocol_mapping_for_current_and_legacy_logs(self):
        for proto, number in (("tcp", 6), ("udp", 17), ("icmp", 1), ("icmp6", 58)):
            with self.subTest(proto=proto):
                record = {**SAMPLE_CONN_RECORD, "proto": proto}
                expected = conn_record_to_flow(record)
                self.assertEqual(expected["features"]["protocol"], number)
                self.assertEqual(expected, conn_record_to_flow({**record, "ip_proto": number}))
        for missing in (None, "-", ""):
            with self.subTest(missing=missing):
                record = {**SAMPLE_CONN_RECORD, "proto": "icmp", "ip_proto": missing,
                          "id.orig_h": "2001:db8::1", "id.resp_h": "2001:db8::2"}
                self.assertEqual(conn_record_to_flow(record)["features"]["protocol"], 58)
                del record["id.orig_h"]
                self.assertEqual(conn_record_to_flow(record)["features"]["protocol"], 58)
                del record["id.resp_h"]
                self.assertEqual(conn_record_to_flow(record)["features"]["protocol"], 1)

    def test_malformed_protocol_metadata_is_rejected(self):
        for value in (True, "58", -1, 256, 58.5, float("nan"), float("inf"), 1e100):
            with self.subTest(value=value), self.assertRaises(ValueError):
                conn_record_to_flow({**SAMPLE_CONN_RECORD, "proto": "icmp", "ip_proto": value})
        for proto, number in (("tcp", 58), ("udp", 6), ("icmp", 17), ("icmp6", 1)):
            with self.subTest(proto=proto, number=number), self.assertRaisesRegex(ValueError, "disagrees"):
                conn_record_to_flow({**SAMPLE_CONN_RECORD, "proto": proto, "ip_proto": number})
        for address in ("not-an-ip", "2001:db8::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                conn_record_to_flow({**SAMPLE_CONN_RECORD, "proto": "icmp", "id.orig_h": address})

    def test_export_log_once_posts_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            log_path = temp_path / "conn.log"
            state_file = temp_path / "state.json"
            log_path.write_text(json.dumps(SAMPLE_CONN_RECORD) + "\n", encoding="utf-8")

            with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send_payload:
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

    def test_decoded_vxlan_carriers_are_not_exported(self) -> None:
        # Shape of K3s flannel traffic once Zeek decodes UDP 8472: the outer flow is tagged and its
        # inner pod flow names it as a tunnel parent. An undecoded 8472 flow is still sent.
        outer = {**SAMPLE_CONN_RECORD, "uid": "Couter", "proto": "udp", "service": "vxlan",
                 "id.orig_h": "192.168.1.122", "id.resp_h": "192.168.1.78", "id.resp_p": 8472,
                 "history": "Dd", "orig_pkts": 2, "resp_pkts": 2}
        inner = {**SAMPLE_CONN_RECORD, "uid": "Cinner", "proto": "udp", "service": "dns",
                 "id.orig_h": "10.42.0.12", "id.resp_h": "10.42.2.3", "id.resp_p": 53,
                 "history": "Dd", "orig_pkts": 2, "resp_pkts": 2, "tunnel_parents": ["Couter"]}
        undecoded = {**outer, "uid": "Cundecoded", "service": None}
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            log_path = temp_path / "conn.log"
            state_file = temp_path / "state.json"
            log_path.write_text("".join(json.dumps(r) + "\n" for r in (outer, inner, undecoded, SAMPLE_CONN_RECORD)),
                                encoding="utf-8")
            with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send_payload:
                exported = export_log_once(log_path=log_path, endpoint="http://nids/api/internal/flows",
                                           state_file=state_file, source_name="zeek-worker-node-a",
                                           token="t", batch_size=100)
            flows = send_payload.call_args.args[3]
            self.assertEqual(exported, 3)
            self.assertEqual([f["flow_id"].split(":")[0] for f in flows], ["Cinner", "Cundecoded", SAMPLE_CONN_RECORD["uid"]])
            self.assertEqual(json.loads(state_file.read_text())["offset"], log_path.stat().st_size)

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
                return acknowledge(endpoint, token, source_name, flows)

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
                lifetime_packet_total=20,
            )

            summary = store.build_summary(recent_window_minutes=60, history_hours=24)
            self.assertEqual(summary["recent_counts"]["BENIGN"], 1)
            self.assertEqual(summary["all_time_counts"]["BENIGN"], 1)
            self.assertEqual(summary["lifetime_packets"], 20)
            self.assertEqual(summary["sources"][0]["source"], "zeek-worker-node-a")
            store.close()

    def test_lifetime_packet_counter_survives_retention_purge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "nids.sqlite3"
            store = StatsStore(db_path, labels=["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"])
            store.initialize()
            store.record_predictions(
                "zeek-worker-node-a",
                [
                    PredictionRow(
                        observed_at=utcnow() - timedelta(days=40),
                        predicted_label="BENIGN",
                        confidence=0.99,
                    )
                ],
                lifetime_packet_total=20,
            )

            deleted = store.purge_old_events(retention_hours=24 * 30)
            summary = store.build_summary(recent_window_minutes=60, history_hours=24)

            self.assertEqual(deleted, 1)
            self.assertEqual(summary["total_events"], 0)
            self.assertEqual(summary["lifetime_packets"], 20)
            store.close()


if __name__ == "__main__":
    unittest.main()
