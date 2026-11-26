"""Web-probe detection: matching, client address, converter tailing with rotation, API storage, summary and scans."""
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

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app import main
from app.web_scans import group_scans
from sensor.web_probes import client_address, deliver_probes, probe_event, web_probe_endpoint
from sensor.zeek_to_cicids import export_log_once, load_state

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
                    "/cgi-bin/luci", "/admin/.env", "/.claude/settings.json", "/config.env",
                    # probe-path-v2: v1 missed these from the 2026-11-21 scanner.
                    "/.kube/config", "/.azure/accessTokens.json", "/.config/gcloud/credentials.db", "/.svn/wc.db",
                    "/.hg/hgrc", "/.netrc", "/.s3cfg", "/terraform.tfstate", "/secrets.json",
                    "/homeassistant/secrets.yaml", "/client_secrets.json", "/credentials.json", "/credentials",
                    "/phpinfo", "/_profiler/phpinfo", "/_environment", "/web.config", "/configuration.php.old",
                    "/service-account-key.json", "/....//....//proc/self/environ", "/.well-known/../.env"):
            with self.subTest(uri=uri):
                event = probe_event({**REQUEST, "uri": uri, "status_code": 200})
                self.assertEqual(event and event["rule"], "probe-path-v2")
        for uri in ("/", "/main.js?v=6", "/api/public/summary", "/favicon.ico", "/static/styles.css",
                    "/generate_204?t=1", "/robots.txt", "/blog/environment-notes", "/github",
                    "/.well-known/security.txt", "/.well-known/acme-challenge/x", "/blog/credentials-rotation",
                    "/blog/service-account-notes", "/projects/terraform", "/environment"):
            with self.subTest(uri=uri):
                self.assertIsNone(probe_event({**REQUEST, "uri": uri, "status_code": 200}))

    def test_other_client_errors_are_exported_for_scan_grouping(self):
        for status in (400, 401, 403, 404, 405, 429, 499):
            with self.subTest(status=status):
                event = probe_event({**REQUEST, "uri": "/bk", "status_code": status})
                self.assertEqual((event["rule"], event["status_code"]), ("client-error-v1", status))
        for status in (200, 301, 304, 500, 503, None, "404"):
            with self.subTest(status=status):
                self.assertIsNone(probe_event({**REQUEST, "uri": "/bk", "status_code": status}))
        # A probe path keeps the more specific rule whatever the answer.
        self.assertEqual(probe_event(REQUEST)["rule"], "probe-path-v2")
        self.assertIsNone(probe_event({**REQUEST, "uri": ""}))

    def test_event_fields(self):
        event = probe_event(REQUEST)
        self.assertEqual(event["event_id"], "CprobeA:3")
        self.assertEqual((event["client"], event["host"], event["status_code"], event["rule"]),
                         ("34.62.254.152", "brendanmanley.com", 404, "probe-path-v2"))
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
        self.write(self.log, REQUEST, {**REQUEST, "uid": "Cpage", "uri": "/", "status_code": 200})
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


def scan_events(client, start, count, *, step=0.5, uri=lambda i: f"/guess-{i}", status=404, rule="client-error-v1",
                uid=lambda i: "Cscan"):
    return [{"client": client, "observed_at": start + timedelta(seconds=i * step), "uri": uri(i), "status_code": status,
             "rule": rule, "event_id": f"{uid(i)}:{i + 1}", "host": "brendanmanley.com", "user_agent": "scanner"}
            for i in range(count)]


class ScanGroupingTests(unittest.TestCase):
    START = datetime(2026, 11, 21, 6, 26, 57, tzinfo=UTC)

    def test_burst_becomes_one_scan_with_its_shape(self):
        events = scan_events("35.233.22.121", self.START, 12, uid=lambda i: f"C{i % 3}",
                             uri=lambda i: "/.env" if i == 0 else f"/guess-{i}")
        events[0]["rule"] = "probe-path-v2"
        [scan] = group_scans(events)
        self.assertEqual((scan["client"], scan["requests"], scan["distinct_uris"], scan["probe_paths"],
                          scan["not_found"], scan["client_errors"], scan["succeeded"], scan["connections"]),
                         ("35.233.22.121", 12, 12, 1, 12, 12, 0, 3))
        self.assertEqual((scan["started_at"], scan["duration_seconds"]), (self.START, 5.5))
        self.assertEqual(scan["sample_uris"][:2], ["/.env", "/guess-1"])

    def test_thresholds_gap_and_clients_split_scans(self):
        self.assertEqual(group_scans(scan_events("a", self.START, 9)), [])  # Below 10 requests.
        # The operator retrying one missing URL is not a scan, however often (36 /healthz in 43 s, 2026-11-08).
        self.assertEqual(group_scans(scan_events("lan", self.START, 36, uri=lambda i: "/healthz")), [])
        self.assertEqual(group_scans(scan_events("a", self.START, 10, uri=lambda i: f"/g{i % 4}")), [])
        # A pause longer than the gap ends a scan; two clients interleaved stay apart.
        later = self.START + timedelta(minutes=5)
        events = (scan_events("a", self.START, 10) + scan_events("a", later, 10)
                  + scan_events("b", self.START, 10, step=0.7))
        scans = group_scans(events)
        self.assertEqual([(scan["client"], scan["started_at"]) for scan in scans],
                         [("a", later), ("b", self.START), ("a", self.START)])
        slow = scan_events("c", self.START, 10, step=61)
        self.assertEqual(group_scans(slow), [])
        self.assertEqual(len(group_scans(slow, gap_seconds=120)), 1)
        with self.assertRaises(ValueError):
            group_scans(events, min_requests=0)

    def test_only_a_probe_path_answered_2xx_counts_as_succeeded(self):
        events = scan_events("a", self.START, 12, rule="probe-path-v2")
        events[0].update(uri="/?phpinfo=1", status_code=200)  # The home page ignoring its query (2026-11-09).
        events[1].update(uri="/.git/config", status_code=200)
        events[2].update(uri="/guess-x", status_code=200, rule="client-error-v1")
        [scan] = group_scans(events)
        self.assertEqual((scan["succeeded"], scan["succeeded_uris"]), (1, ["/.git/config"]))


class WebProbeApiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        settings = replace(main.settings, db_path=Path(temporary.name) / "nids.sqlite3", ingest_token="test-token")
        self.enterContext(patch.object(main, "settings", settings))
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

    def test_scans_in_summary_are_counts_only_and_listed_privately(self):
        # The 2026-11-21 scanner's shape: one probe path, then guesses answered 404, a second apart at most.
        events = [probe_event({**REQUEST, "ts": NOW - 120 + i * 0.4, "uid": f"Cscan{i % 3}", "trans_depth": i + 1,
                               "uri": "/.env" if i == 0 else f"/guess-{i}",
                               "proxied": ["X-FORWARDED-FOR -> 35.233.22.121"]}) for i in range(12)]
        # A visitor's stray 404s and a lone probe from someone else make no scan.
        events += [probe_event({**REQUEST, "uid": "Cvisitor", "uri": "/contacto",
                                "proxied": ["X-FORWARDED-FOR -> 76.236.31.183"]}),
                   probe_event({**REQUEST, "uid": "Clone", "proxied": ["X-FORWARDED-FOR -> 20.46.43.126"]})]
        self.assertEqual(self.post(events).status_code, 200)
        public = self.client.get("/api/public/summary").json()["web_probes"]
        # Requests and clients still count probe paths only: the scanner's /.env and the lone probe.
        self.assertEqual((public["history_requests"], public["history_clients"]), (2, 2))
        self.assertEqual((public["recent_scans"], public["history_scans"], public["history_scans_succeeded"]),
                         (1, 1, 0))
        [scan] = public["scans"]
        self.assertEqual((scan["requests"], scan["probe_paths"], scan["not_found"], scan["connections"],
                          scan["hosts"]), (12, 1, 12, 3, ["brendanmanley.com"]))
        self.assertTrue({"client", "user_agents", "sample_uris", "succeeded_uris"}.isdisjoint(scan))
        self.assertEqual(sum(bucket["scans"] for bucket in public["hourly"]), 1)
        text = self.client.get("/api/public/summary").text
        self.assertNotIn("35.233.22.121", text)
        self.assertNotIn("/guess-1", text)
        self.assertEqual(self.client.get("/api/internal/web-scans").status_code, 403)
        [private] = self.client.get("/api/internal/web-scans", headers=self.headers).json()
        self.assertEqual((private["client"], private["sample_uris"][0], private["user_agents"]),
                         ("35.233.22.121", "/.env", ["Mozilla/5.0"]))

    def test_scan_thresholds_come_from_settings(self):
        events = [probe_event({**REQUEST, "ts": NOW - 60 + i, "uid": "Csmall", "trans_depth": i + 1,
                               "uri": f"/guess-{i}"}) for i in range(6)]
        self.post(events)
        self.assertEqual(self.client.get("/api/public/summary").json()["web_probes"]["history_scans"], 0)
        with patch.object(main, "settings", replace(main.settings, web_scan_min_requests=5)):
            self.assertEqual(self.client.get("/api/public/summary").json()["web_probes"]["history_scans"], 1)

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
