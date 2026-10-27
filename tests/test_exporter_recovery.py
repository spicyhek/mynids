import io
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.inference import ModelArtifacts
from app.storage import PredictionRow
from sensor.zeek_to_cicids import conn_record_to_flow, export_log_once, load_state
from test_zeek_to_cicids import SAMPLE_CONN_RECORD, acknowledge


class ExporterRecoveryTests(unittest.TestCase):
    def test_direct_script_entrypoint_works_outside_repository(self):
        script = Path(__file__).resolve().parents[1] / "sensor" / "zeek_to_cicids.py"
        result = subprocess.run([sys.executable, str(script), "--help"], cwd=self.root,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--source-name", result.stdout)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.log = self.root / "conn.log"
        self.state = self.root / "state.json"
        self.log.write_text(self.line("first"), encoding="utf-8")

    def line(self, uid):
        return json.dumps({**SAMPLE_CONN_RECORD, "uid": uid}) + "\n"

    def export(self, batch_size=100):
        return export_log_once(log_path=self.log, endpoint="http://test/api/internal/flows",
            state_file=self.state, source_name="sensor-a", token="token", batch_size=batch_size)

    def test_partial_line_is_not_checkpointed_and_is_read_once_completed(self):
        line = self.line("partial")
        self.log.write_text(line[:30], encoding="utf-8")
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send:
            self.assertEqual(self.export(), 0)
            self.assertEqual(load_state(self.state)["offset"], 0)
            with self.log.open("a", encoding="utf-8") as handle:
                handle.write(line[30:])
            self.assertEqual(self.export(), 1)
            self.assertEqual(self.export(), 0)
            send.assert_called_once()

    def test_invalid_ack_keeps_durable_batch_until_valid_retry(self):
        with patch("sensor.zeek_to_cicids.send_payload", return_value={"stored": 0}):
            with self.assertRaises(ValueError):
                self.export()
        self.assertEqual(load_state(self.state)["offset"], 0)
        self.assertTrue(self.state.with_suffix(".json.pending.json").exists())
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send:
            self.assertEqual(self.export(), 1)
            send.assert_called_once()
        self.assertEqual(load_state(self.state)["offset"], self.log.stat().st_size)

    def test_protocol_upgrade_preserves_pending_payload_and_corrects_new_flows(self):
        record = {**SAMPLE_CONN_RECORD, "proto": "icmp", "ip_proto": 58,
                  "id.orig_h": "fe80::10", "id.resp_h": "fe80::1"}
        self.log.write_text(json.dumps(record) + "\n", encoding="utf-8")
        # Simulate an old serialized batch with a lost acknowledgment. Changing
        # its payload on retry would cause an HTTP 409 after a committed insert.
        with patch("sensor.zeek_to_cicids.protocol_number", return_value=1), patch(
                "sensor.zeek_to_cicids.send_payload", side_effect=TimeoutError("lost acknowledgment")):
            with self.assertRaises(TimeoutError):
                self.export()
        pending_path = self.state.with_suffix(".json.pending.json")
        pending_flows = json.loads(pending_path.read_text())["flows"]
        self.assertEqual(pending_flows[0]["features"]["protocol"], 1)
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({**record, "uid": "after-upgrade"}) + "\n")
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send:
            self.assertEqual(self.export(), 2)
            self.assertEqual(self.export(), 0)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(send.call_args_list[0].args[3], pending_flows)
        self.assertEqual(send.call_args_list[1].args[3][0]["features"]["protocol"], 58)
        self.assertFalse(pending_path.exists())
        self.assertEqual(load_state(self.state)["offset"], self.log.stat().st_size)

    def test_rotation_drains_old_file_before_new_file_even_if_new_file_is_larger(self):
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send:
            self.export()
            with self.log.open("a", encoding="utf-8") as handle:
                handle.write(self.line("old-tail"))
            self.log.rename(self.root / "conn.previous.log")
            self.log.write_text(self.line("new-1") + self.line("new-2"), encoding="utf-8")
            self.assertEqual(self.export(), 1)
            self.assertEqual(self.export(), 2)
            ids = [flow["flow_id"].split(":")[0] for call in send.call_args_list for flow in call.args[3]]
            self.assertEqual(ids, ["first", "old-tail", "new-1", "new-2"])

    def test_copy_truncate_regrowth_is_detected_by_checkpoint_anchor(self):
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge):
            self.export()
            self.log.write_text(self.line("replacement-1") + self.line("replacement-2"), encoding="utf-8")
            self.assertEqual(self.export(), 2)

    def test_same_length_replacement_with_matching_record_suffix_is_replayed(self):
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge):
            self.export()
            self.log.write_text(self.line("other"), encoding="utf-8")
            self.assertEqual(self.export(), 1)

    def test_corrupt_state_replays_and_missing_rotated_file_fails_visibly(self):
        self.state.write_text("{", encoding="utf-8")
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge):
            self.assertEqual(self.export(), 1)
            old = self.root / "deleted.log"
            self.log.rename(old)
            self.log.write_text(self.line("new"), encoding="utf-8")
            with self.assertRaisesRegex(OSError, "rotated log"):
                self.export()

    def test_malformed_and_permanently_rejected_records_do_not_block_valid_records(self):
        self.log.write_text("invalid JSON\n" + self.line("bad") + self.line("good"), encoding="utf-8")
        def send(endpoint, token, source, flows):
            if any(flow["flow_id"].startswith("bad:") for flow in flows):
                raise HTTPError(endpoint, 422, "Invalid", {}, io.BytesIO(b"bad"))
            return acknowledge(endpoint, token, source, flows)
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=send):
            self.assertEqual(self.export(), 1)
            self.assertEqual(self.export(), 0)
        journal = self.state.with_suffix(".json.quarantine.jsonl").read_text().splitlines()
        self.assertEqual(len(journal), 2)

    def test_lost_response_after_commit_retries_through_real_api_without_double_counting(self):
        settings = replace(main.settings, db_path=self.root / "api.sqlite3", ingest_token="token")
        labels = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]
        def classify(flows):
            return [PredictionRow(flow["event_time"], "BENIGN", 0.9) for flow in flows]
        with patch.object(main, "settings", settings), patch.object(main.classifier, "load", return_value=ModelArtifacts(labels, [])), patch.object(main.classifier, "classify_batch", side_effect=classify):
            with TestClient(main.app) as client:
                lose_ack = True
                responses = []
                def send(endpoint, token, source, flows):
                    nonlocal lose_ack
                    response = client.post("/api/internal/flows", json={"source": source, "flows": flows},
                                           headers={"X-Ingest-Token": token})
                    self.assertEqual(response.status_code, 200, response.text)
                    responses.append(response.json())
                    if lose_ack:
                        lose_ack = False
                        raise TimeoutError("response lost after server commit")
                    return response.json()
                with patch("sensor.zeek_to_cicids.send_payload", side_effect=send):
                    with self.assertRaises(TimeoutError):
                        self.export()
                    self.assertEqual(self.export(), 1)
                self.assertEqual([r["inserted"] for r in responses], [1, 0])
                summary = client.get("/api/public/summary").json()
                self.assertEqual((summary["lifetime_flows"], summary["lifetime_packets"]), (1, 20))

    def test_sensor_rejects_bad_required_fields(self):
        for change in ({"ts": None}, {"uid": ""}, {"orig_pkts": -1}, {"resp_pkts": 1.1},
                       {"id.orig_p": 65536}, {"proto": "invalid"}, {"duration": float("nan")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                conn_record_to_flow({**SAMPLE_CONN_RECORD, **change})
