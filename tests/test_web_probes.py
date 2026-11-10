"""Web-probe detection: matching, client address, converter tailing with rotation, API storage and summary."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi.testclient import TestClient

from app import main
from app.inference import ModelArtifacts
from sensor.web_probes import client_address, deliver_probes, probe_event, web_probe_endpoint
from sensor.zeek_to_cicids import export_log_once, load_state

LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]
NOW = time.time()
REQUEST = {"ts": NOW - 60, "uid": "CprobeA", "id.orig_h": "10.42.1.129", "id.orig_p": 40014,
           "id.resp_h": "10.42.0.215", "id.resp_p": 80, "trans_depth": 3, "method": "GET",
           "host": "brendanmanley.com", "uri": "/.env", "status_code": 404, "user_agent": "Mozilla/5.0",
           "proxied": ["X-FORWARDED-FOR -> 34.62.254.152"]}


def acknowledge(endpoint, token, source, events):
    return {"source": source, "received": len(events), "inserted": len(events), "duplicates": 0,
            "event_ids": [event["event_id"] for event in events]}


class ProbeMatchingTests(unittest.TestCase):
    def test_probe_paths_match_and_ordinary_requests_do_not(self):
        for uri in ("/.env", "/v2/.env", "/.git/config", "/.aws/credentials", "/wp-login.php",
                    "/wp-content/plugins/x/", "/xmlrpc.php", "/database.sql", "/?phpinfo.php",
                    "/cgi-bin/luci", "/admin/.env", "/.claude/settings.json", "/config.env"):
            with self.subTest(uri=uri):
                self.assertIsNotNone(probe_event({**REQUEST, "uri": uri}))
        for uri in ("/", "/main.js?v=6", "/api/public/summary", "/favicon.ico", "/static/styles.css",
                    "/generate_204?t=1", "/robots.txt", "/blog/environment-notes", "/github"):
            with self.subTest(uri=uri):
                self.assertIsNone(probe_event({**REQUEST, "uri": uri}))

    def test_event_fields(self):
        event = probe_event(REQUEST)
        self.assertEqual(event["event_id"], "CprobeA:3")
        self.assertEqual((event["client"], event["host"], event["status_code"], event["rule"]),
                         ("34.62.254.152", "brendanmanley.com", 404, "probe-path-v1"))
        long = probe_event({**REQUEST, "uri": "/.env" + "a" * 2000, "status_code": "404", "user_agent": None})
        self.assertEqual((len(long["uri"]), long["status_code"], long["user_agent"]), (512, None, ""))
        with self.assertRaisesRegex(ValueError, "uid/ts"):
            probe_event({**REQUEST, "uid": None})

    def test_client_is_the_right_most_forwarded_address(self):
        self.assertEqual(client_address({**REQUEST, "proxied": ["X-FORWARDED-FOR -> 100.119.229.5,34.126.191.26"]}),
                         "34.126.191.26")  # The client-supplied left entry is ignored.
        self.assertEqual(client_address({**REQUEST, "proxied": ["FORWARDED -> for=172.26.46.205"]}),
                         "172.26.46.205")
        self.assertEqual(client_address({**REQUEST, "proxied": None}), "10.42.1.129")

    def test_endpoint_is_derived_beside_the_flow_endpoint(self):
        self.assertEqual(web_probe_endpoint("http://nids.default.svc:8080/api/internal/flows"),
                         "http://nids.default.svc:8080/api/internal/web-probes")


class ProbeExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "http.log"
        self.state = self.root / "state.json.http"

    def write(self, path, *records):
        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

    def export(self):
        return export_log_once(log_path=self.log, endpoint="http://test/api/internal/web-probes",
                               state_file=self.state, source_name="sensor-a", token="t", batch_size=100,
                               convert=probe_event, send=deliver_probes)

    def test_only_probes_are_sent_once_and_rotation_is_drained(self):
        self.write(self.log, REQUEST, {**REQUEST, "uid": "Cpage", "uri": "/"})
        with patch("sensor.web_probes.send_probes", side_effect=acknowledge) as send:
            self.assertEqual(self.export(), 1)
            self.assertEqual(self.export(), 0)
            self.assertEqual([e["event_id"] for e in send.call_args.args[3]], ["CprobeA:3"])
            # Rotate with an unread probe still in the old file; it is drained before the new one.
            self.write(self.log, {**REQUEST, "uid": "Clate"})
            os.replace(self.log, self.root / "http.2026-11-10-06-00-00.log")
            self.write(self.log, {**REQUEST, "uid": "Cnew", "uri": "/wp-login.php"})
            self.assertEqual(self.export(), 1)
            self.assertEqual(self.export(), 1)
            sent = [e["event_id"] for call in send.call_args_list for e in call.args[3]]
        self.assertEqual(sent, ["CprobeA:3", "Clate:3", "Cnew:3"])
        self.assertEqual(load_state(self.state)["offset"], self.log.stat().st_size)

    def test_failed_delivery_keeps_the_pending_batch(self):
        self.write(self.log, REQUEST)
        with patch("sensor.web_probes.send_probes", side_effect=OSError("down")):
            with self.assertRaises(OSError):
                self.export()
        self.assertTrue(self.state.with_suffix(".http.pending.json").exists())
        with patch("sensor.web_probes.send_probes", side_effect=acknowledge) as send:
            self.assertEqual(self.export(), 1)
            send.assert_called_once()

    def test_rejected_event_is_quarantined_not_retried_forever(self):
        self.write(self.log, REQUEST)
        rejected = HTTPError("http://test", 422, "bad", {}, None)
        with patch("sensor.web_probes.send_probes", side_effect=rejected):
            self.assertEqual(self.export(), 0)
        self.assertTrue(self.state.with_suffix(".http.quarantine.jsonl").exists())


class WebProbeApiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        settings = replace(main.settings, db_path=Path(temporary.name) / "nids.sqlite3", ingest_token="test-token")
        self.enterContext(patch.object(main, "settings", settings))
        self.enterContext(patch.object(main.classifier, "load", return_value=ModelArtifacts(LABELS, [])))
        self.client = self.enterContext(TestClient(main.app))
        self.headers = {"X-Ingest-Token": "test-token"}

    def post(self, events):
        return self.client.post("/api/internal/web-probes", headers=self.headers,
                                json={"source": "zeek-a", "events": events})

    def test_ingest_dedupes_and_summary_shows_counts_only(self):
        events = [probe_event(REQUEST), probe_event({**REQUEST, "uid": "CprobeB", "uri": "/.git/config"}),
                  probe_event({**REQUEST, "uid": "CprobeC", "proxied": ["X-FORWARDED-FOR -> 20.46.43.126"]})]
        first = self.post(events)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual((first.json()["inserted"], first.json()["duplicates"]), (3, 0))
        self.assertEqual(first.json()["event_ids"], ["CprobeA:3", "CprobeB:3", "CprobeC:3"])
        self.assertEqual((self.post(events).json()["inserted"]), 0)
        public = self.client.get("/api/public/summary")
        self.assertEqual(public.status_code, 200, public.text)
        probes = public.json()["web_probes"]
        self.assertEqual((probes["recent_requests"], probes["recent_clients"]), (3, 2))
        self.assertEqual((probes["history_requests"], probes["history_clients"]), (3, 2))
        self.assertEqual(sum(bucket["requests"] for bucket in probes["hourly"]), 3)
        self.assertNotIn("34.62.254.152", public.text)
        listed = self.client.get("/api/internal/web-probes", headers=self.headers).json()
        self.assertEqual({row["client"] for row in listed}, {"34.62.254.152", "20.46.43.126"})
        self.assertEqual(listed[0]["uri"], "/.env")

    def test_endpoints_require_the_token_and_valid_events(self):
        self.assertEqual(self.client.get("/api/internal/web-probes").status_code, 403)
        self.assertEqual(self.client.post("/api/internal/web-probes",
                                          json={"source": "s", "events": [probe_event(REQUEST)]}).status_code, 403)
        bad = {**probe_event(REQUEST), "event_time": "2026-11-10T00:00:00"}  # No timezone.
        self.assertEqual(self.post([bad]).status_code, 422)
        self.assertEqual(self.post([{**probe_event(REQUEST), "extra": 1}]).status_code, 422)

    def test_retention_removes_old_probes(self):
        self.post([probe_event({**REQUEST, "ts": NOW - 3600 * 24 * 40})])
        self.assertEqual(len(self.client.get("/api/internal/web-probes?hours=168", headers=self.headers).json()), 0)
        main.app.state.store.purge_old_events(main.settings.retention_hours)
        rows = main.app.state.store._connection.execute("SELECT COUNT(*) FROM web_probe_events").fetchone()[0]
        self.assertEqual(rows, 0)
        self.assertEqual(self.client.get("/api/internal/web-probes?hours=168", headers=self.headers).json(), [])


if __name__ == "__main__":
    unittest.main()
