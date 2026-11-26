"""SSH login flag: the converter marks flows whose SSH login Zeek saw succeed, and older servers still get flows."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import error

from app.schemas import FlowBatchRequest
from sensor.ssh_auth import FIELD, SshAuthIndex, successful_login_uid
from sensor.zeek_to_cicids import deliver, export_log_once

# Shaped like the live 2026-11-25 operator session (Windows OpenSSH to the control plane).
CONN = {"ts": 1795641083.201661, "uid": "Clogin", "id.orig_h": "2600:1700:38c0:a2e0:4c56:e477:8609:7b98",
        "id.orig_p": 54725, "id.resp_h": "2600:1700:38c0:a2e0::524", "id.resp_p": 22, "proto": "tcp",
        "service": "ssh", "duration": 18.03, "orig_bytes": 3645, "resp_bytes": 12698, "conn_state": "RSTO",
        "missed_bytes": 0, "history": "ShADadR", "orig_pkts": 25, "orig_ip_bytes": 5157, "resp_pkts": 32,
        "resp_ip_bytes": 14630}
SSH = {"ts": 1795641083.206774, "uid": "Clogin", "id.orig_h": CONN["id.orig_h"], "id.orig_p": 54725,
       "id.resp_h": CONN["id.resp_h"], "id.resp_p": 22, "version": 2, "auth_success": True, "auth_attempts": 3,
       "client": "SSH-2.0-OpenSSH_for_Windows_9.5"}


def acknowledge(endpoint, token, source, flows):
    return {"source": source, "received": len(flows), "inserted": len(flows), "duplicates": 0,
            "flow_ids": [flow["flow_id"] for flow in flows]}


class SshAuthIndexTests(unittest.TestCase):
    def test_only_successful_logins_are_indexed(self):
        self.assertEqual(successful_login_uid(SSH), "Clogin")
        for change in ({"auth_success": False}, {"auth_success": None}, {"auth_success": "T"}, {"uid": ""}):
            with self.subTest(change=change):
                self.assertIsNone(successful_login_uid({**SSH, **change}))
        without = dict(SSH)
        del without["auth_success"]  # Zeek leaves it out when it cannot tell (most guessing sessions).
        self.assertIsNone(successful_login_uid(without))

    def test_index_keeps_the_newest_uids(self):
        index = SshAuthIndex(max_entries=2)
        for uid in ("a", "b", "c"):
            index.add(uid)
        self.assertEqual((len(index), "a" in index, "c" in index), (2, False, True))
        with self.assertRaises(ValueError):
            SshAuthIndex(max_entries=0)


class ConverterTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.index = SshAuthIndex()

    def write(self, name, *records):
        (self.dir / name).write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    def export_ssh(self):
        return export_log_once(log_path=self.dir / "ssh.log", endpoint="ssh-auth-index",
                               state_file=self.dir / "state.json.ssh", source_name="zeek", token="",
                               batch_size=100, convert=successful_login_uid, send=self.index.deliver)

    def export_conn(self):
        with patch("sensor.zeek_to_cicids.send_payload", side_effect=acknowledge) as send:
            export_log_once(log_path=self.dir / "conn.log", endpoint="http://nids/api/internal/flows",
                            state_file=self.dir / "state.json", source_name="zeek", token="t", batch_size=100,
                            annotate=self.index.annotate)
        return [flow for call in send.call_args_list for flow in call.args[3]]

    def test_flows_of_successful_logins_carry_the_flag_and_pass_the_ingest_schema(self):
        self.write("ssh.log", SSH, {**SSH, "uid": "Cguess", "auth_success": False, "auth_attempts": 4})
        self.write("conn.log", CONN, {**CONN, "uid": "Cguess"}, {**CONN, "uid": "Cother", "id.resp_p": 443})
        self.assertEqual(self.export_ssh(), 1)
        flows = self.export_conn()
        self.assertEqual({f["flow_id"].split(":")[0]: f.get(FIELD) for f in flows},
                         {"Clogin": True, "Cguess": None, "Cother": None})
        batch = FlowBatchRequest.model_validate({"source": "zeek", "flows": flows})
        self.assertEqual([f.ssh_auth_success for f in batch.flows], [True, None, None])

    def test_a_login_not_yet_indexed_is_sent_without_the_flag(self):
        self.write("ssh.log")
        self.write("conn.log", CONN)
        self.export_ssh()
        self.assertNotIn(FIELD, self.export_conn()[0])

    def test_an_older_server_gets_the_flows_without_the_flag(self):
        flows = [{"flow_id": "Clogin:t", FIELD: True}, {"flow_id": "Cother:t"}]
        seen = []

        def server(endpoint, token, source, batch):
            seen.append([dict(f) for f in batch])
            if any(FIELD in f for f in batch):
                raise error.HTTPError(endpoint, 422, "extra field", {}, io.BytesIO(b"{}"))
            return acknowledge(endpoint, token, source, batch)

        with patch("sensor.zeek_to_cicids.send_payload", side_effect=server):
            self.assertEqual(deliver("http://nids", "t", "zeek", flows, self.dir / "state.json"), 2)
        self.assertEqual(seen[-1], [{"flow_id": "Clogin:t"}, {"flow_id": "Cother:t"}])
        self.assertFalse((self.dir / "state.json.quarantine.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
