"""Allowlist benign tier: rule evidence, exclusions, session pinning and recipe isolation."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest

from tools.capture_session import MANIFEST, digest
from tools.label_homelab_benign import label_session, load_policy
from tools.training_data import load_prepared, prepare, sha256

T0 = 1793310000.0


def iso(offset: float) -> str:
    return datetime.fromtimestamp(T0 + offset, UTC).isoformat()


def conn(uid, offset, orig="192.0.2.20", resp="203.0.113.5", port=443, proto="tcp", state="SF", **extra):
    return {"ts": T0 + offset, "uid": uid, "id.orig_h": orig, "id.orig_p": 40000, "id.resp_h": resp,
            "id.resp_p": port, "proto": proto, "duration": 1.0, "orig_bytes": 100, "resp_bytes": 200,
            "conn_state": state, "missed_bytes": 0, "history": "ShADadFf", "orig_pkts": 5, "orig_ip_bytes": 360,
            "resp_pkts": 5, "resp_ip_bytes": 460, **extra}


class HomelabBenignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = self.root / "session"
        self.zeek = self.root / "zeek"
        self.session.mkdir()
        self.zeek.mkdir()
        self.activities = []

    def activity(self, name, begin, end):
        activity_id = f"{len(self.activities):032x}"
        self.activities += [{"event": "activity_begin", "activity_id": activity_id, "name": name,
                             "recorded_at_utc": iso(begin)},
                            {"event": "activity_end", "activity_id": activity_id, "outcome": "completed",
                             "recorded_at_utc": iso(end)}]

    def seal(self):
        (self.session / "activity.jsonl").write_text("".join(json.dumps(e) + "\n" for e in self.activities))
        (self.session / "capture.json").write_text(json.dumps({"session_id": "unit-session"}))
        files = {p.name: {"bytes": p.stat().st_size, "sha256": digest(p)} for p in self.session.iterdir()}
        (self.session / MANIFEST).write_text(json.dumps({"session_id": "unit-session", "files": files,
                                                          "quality_flags": []}))

    def logs(self, conns, ssl=(), http=(), dns=()):
        for name, rows in (("conn.log", conns), ("ssl.log", ssl), ("http.log", http), ("dns.log", dns)):
            (self.zeek / name).write_text("".join(json.dumps(row) + "\n" for row in rows))

    def policy(self, **changes):
        value = {
            "schema_version": 1, "label_tier": "allowlist-benign",
            "session": {"session_id": "unit-session", "manifest_sha256": sha256(self.session / MANIFEST),
                        "attestation": "No deliberate attack traffic (unit test)."},
            "networks": {"lan": ["192.0.2.0/24"], "gateway": ["192.0.2.1/32"], "multicast": ["224.0.0.0/4"]},
            "exclusions": {"activities": [], "windows": [], "pad_seconds": 0,
                           "max_distinct_destination_ports_per_minute": 5,
                           "max_distinct_destination_hosts_per_minute": 5},
            "rules": [
                {"name": "tls", "rationale": "known sites", "proto": ["tcp"], "orig_hosts": ["lan"],
                 "resp_ports": [443], "tls_server_names": ["github.com", ".github.com"]},
                {"name": "dns", "rationale": "resolver", "proto": ["udp"], "orig_hosts": ["lan"],
                 "resp_hosts": ["gateway"], "resp_ports": [53], "conn_states": ["SF", "S0"]},
                {"name": "probe", "rationale": "connectivity check", "proto": ["tcp"], "resp_ports": [80],
                 "http": {"uri_prefix": "/generate_204", "status_codes": [204]}},
                {"name": "mdns", "rationale": "local discovery", "proto": ["udp"], "resp_hosts": ["multicast"],
                 "resp_ports": [5353], "conn_states": ["S0"]},
            ]}
        value.update(changes)
        path = self.root / "policy.json"
        path.write_text(json.dumps(value))
        return path

    def run_label(self, policy=None, output="labels"):
        return label_session(self.session, self.zeek, policy or self.policy(), self.root / output, "homelab-unit")

    def test_rules_require_their_protocol_evidence(self):
        self.seal()
        self.logs([conn("tls-ok", 0), conn("tls-sub", 1), conn("tls-lookalike", 2), conn("tls-no-sni", 3),
                   conn("tls-s0", 4, state="S0"),
                   conn("dns", 5, resp="192.0.2.1", port=53, proto="udp"),
                   conn("probe-ok", 6, port=80), conn("probe-404", 7, port=80),
                   conn("mdns", 8, resp="224.0.0.251", port=5353, proto="udp", state="S0"),
                   conn("other", 9, port=8443),
                   conn("vxlan", 10, resp="192.0.2.30", port=8472, proto="udp", state="S0")],
                  ssl=[{"uid": "tls-ok", "server_name": "github.com"}, {"uid": "tls-sub", "server_name": "api.github.com"},
                       {"uid": "tls-lookalike", "server_name": "evilgithub.com"}, {"uid": "tls-no-sni"},
                       {"uid": "tls-s0", "server_name": "github.com"}],
                  http=[{"uid": "probe-ok", "uri": "/generate_204?t=1", "status_code": 204},
                        {"uid": "probe-404", "uri": "/generate_204?t=2", "status_code": 404}])
        report = self.run_label()
        rows = [json.loads(l) for l in (self.root / "labels/reviewed.jsonl").read_text().splitlines()]
        self.assertEqual({row["conn"]["uid"] for row in rows}, {"tls-ok", "tls-sub", "dns", "probe-ok", "mdns"})
        self.assertTrue(all(row["label"] == "BENIGN" and row["label_tier"] == "allowlist-benign" for row in rows))
        self.assertEqual(report["counts"], {"connections": 11, "labeled": 5, "unmatched": 5,
                                            "excluded_tunnel_carrier": 1})
        self.assertEqual(report["labeled_by_rule"], {"tls": 2, "dns": 1, "probe": 1, "mdns": 1})
        provenance = {json.loads(l)["uid"]: json.loads(l)
                      for l in (self.root / "labels/reviewed-label-provenance.jsonl").read_text().splitlines()}
        self.assertEqual(provenance["tls-sub"]["evidence"]["tls"]["tls_server_names"], ["api.github.com"])
        self.assertEqual(provenance["probe-ok"]["evidence"]["probe"]["http"][0]["status_code"], 204)
        self.assertEqual(sum(group["count"] for group in report["unmatched_groups"]), 5)

    def test_activity_window_operator_window_and_scan_guard_exclude(self):
        self.activity("attack-drill", 10, 20)
        self.seal()
        scanner = [conn(f"scan-{p}", 100 + p, orig="192.0.2.66", port=p, state="S0") for p in range(1, 8)]
        scanner.append(conn("scanner-tls", 200, orig="192.0.2.66"))
        # Many sites on one port within a minute is ordinary client behavior, not a port scan.
        browsing = [conn(f"site-{i}", 300 + i, orig="192.0.2.20", resp=f"203.0.113.{i + 10}") for i in range(3)]
        self.logs([conn("during-drill", 15), conn("during-window", 50), conn("clean", 300), *browsing, *scanner],
                  ssl=[{"uid": uid, "server_name": "github.com"}
                       for uid in ("during-drill", "during-window", "clean", "scanner-tls",
                                   *(f"site-{i}" for i in range(3)))])
        policy = self.policy()
        value = json.loads(policy.read_text())
        value["exclusions"].update(activities=["attack-drill"],
                                   windows=[{"start_utc": iso(45), "end_utc": iso(55), "reason": "unexplained spike"}])
        policy.write_text(json.dumps(value))
        report = self.run_label(policy)
        self.assertEqual(report["counts"]["labeled"], 4)
        self.assertEqual(report["counts"]["excluded_activity"], 1)
        self.assertEqual(report["counts"]["excluded_window"], 1)
        self.assertEqual(report["counts"]["excluded_scan_guard"], 8)
        self.assertEqual(report["scan_guard_originators"], {"192.0.2.66": "fan_out_destination_ports"})

    def test_session_pinning_and_policy_mistakes_are_refused(self):
        self.seal()
        self.logs([conn("a", 0)])
        with self.assertRaisesRegex(ValueError, "different session"):
            self.run_label(self.policy(session={"session_id": "unit-session", "manifest_sha256": "0" * 64,
                                                "attestation": "x"}))
        policy = self.policy()
        value = json.loads(policy.read_text())
        value["rules"][0]["resp_port"] = [443]
        policy.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "unknown keys"):
            load_policy(policy)
        value = json.loads(self.policy().read_text())
        value["exclusions"]["activities"] = ["never-journaled"]
        policy.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "not closed activities"):
            self.run_label(policy)
        value["exclusions"] = {"max_distinct_destination_ports_per_minute": 0,
                               "max_distinct_destination_hosts_per_minute": 5}
        policy.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "cannot be disabled"):
            load_policy(policy)
        with (self.session / "activity.jsonl").open("a") as handle:
            handle.write("\n")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.run_label()
        self.assertFalse((self.root / "labels").exists())

    def test_existing_output_is_preserved(self):
        self.seal()
        self.logs([conn("a", 0)])
        (self.root / "labels").mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.run_label()

    def test_recipe_must_declare_the_weaker_tier(self):
        self.seal()
        self.logs([conn("tls-ok", 0)], ssl=[{"uid": "tls-ok", "server_name": "github.com"}])
        self.run_label()
        labels = self.root / "labels"
        entry = {"path": "labels/reviewed.jsonl", "sha256": sha256(labels / "reviewed.jsonl"),
                 "provenance_path": "labels/report.json", "provenance_sha256": sha256(labels / "report.json"),
                 "label_basis": "Allowlist rules over an attested session.", "origin": "homelab",
                 "group": "homelab-unit-session", "split": "regression"}
        recipe = self.root / "recipe.json"
        recipe.write_text(json.dumps({"schema_version": 1, "name": "tier-test", "sources": [entry]}))
        with self.assertRaisesRegex(ValueError, "label_tier differs"):
            prepare(recipe, self.root / "prepared-undeclared")
        recipe.write_text(json.dumps({"schema_version": 1, "name": "tier-test",
                                      "sources": [{**deepcopy(entry), "label_tier": "allowlist-benign"}]}))
        manifest = prepare(recipe, self.root / "prepared")
        records, _ = load_prepared(self.root / "prepared")
        self.assertEqual(records[0]["label_tier"], "allowlist-benign")
        self.assertEqual(manifest["sources"][0]["label_tier"], "allowlist-benign")


if __name__ == "__main__":
    unittest.main()
