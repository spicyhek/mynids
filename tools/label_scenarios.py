"""Label only published campaign endpoint/service windows after independent clock verification."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path

from sensor.zeek_to_cicids import protocol_number
from tools.public_labels import cse_metadata_matches, label_connections
from tools.training_data import sha256


def failed_authentication_evidence(directory):
    evidence = {}
    for name in ("ssh.log", "ftp.log"):
        path = directory / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            attempts = row.get("auth_attempts")
            if name == "ssh.log" and row.get("auth_success") is False and isinstance(attempts, int) and attempts > 0:
                evidence.setdefault(row["uid"], []).append({"file": name, "auth_success": False, "auth_attempts": attempts})
            if name == "ftp.log" and row.get("command") == "PASS" and row.get("reply_code") == 530:
                evidence.setdefault(row["uid"], []).append({"file": name, "command": "PASS", "reply_code": 530})
    return evidence


def scenario_match(conn, specification):
    matches = []
    for rule in specification["scenarios"]:
        start = datetime.fromisoformat(rule["start_utc"].replace("Z", "+00:00")).timestamp()
        finish = datetime.fromisoformat(rule["end_utc"].replace("Z", "+00:00")).timestamp()
        if (conn["id.orig_h"] in rule["attackers"] and conn["id.resp_h"] == rule["victim"]
                and protocol_number(conn) == rule["protocol"] and conn["id.resp_p"] == rule["destination_port"]
                and start <= conn["ts"] and conn["ts"] + conn.get("duration", 0) <= finish):
            matches.append(rule)
    if len(matches) != 1:
        return None
    rule = matches[0]
    return {"label": rule["label"], "source_labels": [rule["name"]],
            "evidence": [{"scenario": rule["name"], "documentation": specification["documentation"],
                          "originator": conn["id.orig_h"], "responder": conn["id.resp_h"],
                          "destination_port": rule["destination_port"], "start_utc": rule["start_utc"], "end_utc": rule["end_utc"]}],
            "matching": "Published attacker, victim, protocol and service; entire observed connection lies within the verified-clock campaign window."}


def label_campaigns(conn_path, reference_csv, specification_path, output, source):
    connections = [json.loads(line) for line in conn_path.read_text().splitlines() if line.strip()]
    specification = json.loads(specification_path.read_text())
    metadata, clock = cse_metadata_matches(connections, reference_csv)
    if clock["utc_offset_hours_modulo_12"] != specification["clock_offset_hours_modulo_12_required"]:
        raise ValueError("Observed source clock differs from the reviewed campaign specification.")
    # Positive labels here require the published endpoint/service window. Retain
    # unique row-level benign matches only when they do not conflict with it.
    lookup = {uid: row for uid, row in metadata.items() if row["label"] == "BENIGN"}
    conflicts, unobserved = set(), set()
    authentication = failed_authentication_evidence(conn_path.parent)
    for conn in connections:
        campaign = scenario_match(conn, specification)
        if campaign is None:
            continue
        if specification.get("require_failed_authentication_evidence") and conn["uid"] not in authentication:
            lookup.pop(conn["uid"], None)
            unobserved.add(conn["uid"])
            continue
        if conn["uid"] in authentication:
            campaign["authentication_evidence"] = authentication[conn["uid"]]
            campaign["matching"] += " Observed failed-authentication evidence is also required."
        previous = metadata.get(conn["uid"])
        if previous is not None and previous["label"] != campaign["label"]:
            lookup.pop(conn["uid"], None)
            conflicts.add(conn["uid"])
        else:
            lookup[conn["uid"]] = campaign
    def match(conn, index):
        if conn["uid"] in unobserved:
            return None, "campaign_without_failed_authentication_evidence"
        if conn["uid"] in conflicts:
            return None, "scenario_and_row_label_conflict"
        result = index.get(conn["uid"])
        return result, None if result else "outside_reviewed_campaign_and_no_metadata_match"
    return label_connections(conn_path, reference_csv, output, source, list(metadata.values()), lookup, match,
                             {"clock_alignment": clock, "scenario_specification_sha256": sha256(specification_path),
                              "scenario_labeler_sha256": sha256(Path(__file__)), "scenario_specification": specification,
                              "protocol_evidence_sha256": {name: sha256(conn_path.parent / name) for name in
                                                          ("ssh.log", "ftp.log") if (conn_path.parent / name).exists()},
                              "source_label_row_count_scope": "unique metadata anchors only; campaign labels use independent published endpoint/time evidence",
                              "campaign_limitations": ["Authentication outcomes are network-analyzer evidence, not host authentication audit logs.",
                                                       "Entire connections must lie inside the window; boundaries are not widened to increase coverage.",
                                                       "Conflicting publisher-row labels remain unreviewed."]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn", type=Path, required=True)
    parser.add_argument("--reference-csv", type=Path, required=True)
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    print(json.dumps(label_campaigns(args.conn, args.reference_csv, args.scenarios, args.output, args.source), indent=2))


if __name__ == "__main__":
    main()
