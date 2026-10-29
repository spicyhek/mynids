"""Label homelab connections BENIGN only where an operator allowlist rule explains them.

This is a weaker label tier than per-flow review: a rule says "this kind of traffic is
expected here", not "this connection was inspected". Every label records its rule and
protocol evidence; unexplained connections stay unlabeled and are summarized for review.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime
import ipaddress
import json
from pathlib import Path

from sensor.zeek_features_v2 import is_tunnel_carrier
from sensor.zeek_to_cicids import parse_zeek_json_line, protocol_number
from tools.capture_session import verify_session
from tools.training_data import sha256, write_json

ESTABLISHED_STATES = ("SF", "S1", "S2", "S3", "RSTO", "RSTR")
RULE_KEYS = {"name", "rationale", "proto", "orig_hosts", "resp_hosts", "orig_ports", "resp_ports", "services",
             "conn_states", "tls_server_names", "http", "dns_query_suffixes"}
HTTP_KEYS = {"hosts", "uri_prefix", "status_codes", "user_agent_prefix"}
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": (1, 58)}
GUARD_SECONDS = 60.0


def timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [record for record in map(parse_zeek_json_line, handle) if record is not None]


def load_policy(path: Path) -> dict:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != 1 or not isinstance(policy.get("label_tier"), str) or not policy["label_tier"]:
        raise ValueError("Policy requires schema_version 1 and a label_tier.")
    session = policy.get("session", {})
    if not all(isinstance(session.get(key), str) and session[key].strip()
               for key in ("session_id", "manifest_sha256", "attestation")):
        raise ValueError("Policy must pin the session ID and manifest hash and state the operator attestation.")
    networks = {}
    for name, cidrs in policy.get("networks", {}).items():
        networks[name] = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs]
    names = set()
    for rule in policy.get("rules", []):
        unknown = set(rule) - RULE_KEYS
        if unknown:
            raise ValueError(f"Rule {rule.get('name')!r} has unknown keys {sorted(unknown)}; check for typos.")
        if not rule.get("name") or not rule.get("rationale") or rule["name"] in names:
            raise ValueError("Every rule needs a unique name and a rationale.")
        names.add(rule["name"])
        if set(rule.get("http", {})) - HTTP_KEYS:
            raise ValueError(f"Rule {rule['name']!r} has unknown http keys.")
        if set(rule.get("proto", [])) - set(PROTOCOLS):
            raise ValueError(f"Rule {rule['name']!r} has an unknown protocol.")
        for key in ("orig_hosts", "resp_hosts"):
            rule[key] = [network for entry in rule.get(key, []) for network in
                         (networks[entry] if entry in networks else [ipaddress.ip_network(entry, strict=True)])]
    if not names:
        raise ValueError("Policy has no rules.")
    exclusions = policy.setdefault("exclusions", {})
    for key in ("max_distinct_destination_ports_per_minute", "max_distinct_destination_hosts_per_minute"):
        if not isinstance(exclusions.get(key), int) or exclusions[key] < 1:
            raise ValueError(f"exclusions.{key} must be a positive integer; the scan guard cannot be disabled.")
    policy["_networks"] = networks
    return policy


def in_networks(address: str, networks: list) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip.version == network.version and ip in network for network in networks)


def network_name(address: str, networks: dict) -> str:
    for name, members in networks.items():
        if in_networks(address, members):
            return name
    return "other"


def suffix_match(name: str | None, patterns: list[str]) -> bool:
    """"example.com" is exact; ".example.com" matches subdomains only."""
    if not name:
        return False
    name = name.lower().rstrip(".")
    return any(name.endswith(pattern.lower()) if pattern.startswith(".") else name == pattern.lower().rstrip(".")
               for pattern in patterns)


def match_rule(conn: dict, rule: dict, evidence: dict) -> dict | None:
    """Return the evidence that satisfied every condition of rule, or None."""
    if "proto" in rule:
        allowed = {number for name in rule["proto"] for number in
                   (PROTOCOLS[name] if isinstance(PROTOCOLS[name], tuple) else (PROTOCOLS[name],))}
        if protocol_number(conn) not in allowed:
            return None
    if conn.get("conn_state") not in rule.get("conn_states", ESTABLISHED_STATES):
        return None
    if rule["orig_hosts"] and not in_networks(conn["id.orig_h"], rule["orig_hosts"]):
        return None
    if rule["resp_hosts"] and not in_networks(conn["id.resp_h"], rule["resp_hosts"]):
        return None
    if "orig_ports" in rule and conn["id.orig_p"] not in rule["orig_ports"]:
        return None
    if "resp_ports" in rule and conn["id.resp_p"] not in rule["resp_ports"]:
        return None
    if "services" in rule and conn.get("service") not in rule["services"]:
        return None
    found = {}
    uid = conn["uid"]
    if "tls_server_names" in rule:
        names = evidence["ssl"].get(uid, [])
        # Every TLS session on the connection must name an allowed server; no SNI is not a match.
        if not names or not all(suffix_match(name, rule["tls_server_names"]) for name in names):
            return None
        found["tls_server_names"] = sorted(set(names))
    if "http" in rule:
        spec, transactions = rule["http"], evidence["http"].get(uid, [])
        if not transactions:
            return None
        for row in transactions:
            if ("hosts" in spec and not suffix_match(row.get("host"), spec["hosts"])
                    or "uri_prefix" in spec and not str(row.get("uri") or "").startswith(spec["uri_prefix"])
                    or "status_codes" in spec and row.get("status_code") not in spec["status_codes"]
                    or "user_agent_prefix" in spec
                    and not str(row.get("user_agent") or "").startswith(spec["user_agent_prefix"])):
                return None
        found["http"] = [{key: row.get(key) for key in ("host", "uri", "status_code", "user_agent")}
                         for row in transactions]
    if "dns_query_suffixes" in rule:
        queries = evidence["dns"].get(uid, [])
        if not queries or not all(suffix_match(query, rule["dns_query_suffixes"]) for query in queries):
            return None
        found["dns_queries"] = sorted(set(queries))
    return found


def scan_guard(connections: list[dict], limits: dict) -> dict[str, str]:
    """Originators that ever exceed the per-minute fan-out limits; all their connections stay unlabeled."""
    flagged = {}
    history = defaultdict(deque)
    for conn in sorted(connections, key=lambda row: row["ts"]):
        window = history[conn["id.orig_h"]]
        window.append((conn["ts"], conn["id.resp_h"], conn["id.resp_p"]))
        while window[0][0] < conn["ts"] - GUARD_SECONDS:
            window.popleft()
        # Distinct ports (not host:port pairs): a client reaching many sites on 443 is not a port scan.
        ports, hosts = len({p for _, _, p in window}), len({h for _, h, _ in window})
        if ports > limits["max_distinct_destination_ports_per_minute"]:
            flagged.setdefault(conn["id.orig_h"], "fan_out_destination_ports")
        if hosts > limits["max_distinct_destination_hosts_per_minute"]:
            flagged.setdefault(conn["id.orig_h"], "fan_out_destination_hosts")
    return flagged


def exclusion_windows(session: Path, exclusions: dict) -> list[tuple[float, float, str]]:
    pad = float(exclusions.get("pad_seconds", 5))
    if pad < 0:
        raise ValueError("pad_seconds must be nonnegative.")
    windows = [(timestamp(w["start_utc"]) - pad, timestamp(w["end_utc"]) + pad, f"window:{w['reason']}")
               for w in exclusions.get("windows", [])]
    wanted = set(exclusions.get("activities", []))
    begins = {}
    events = [json.loads(line) for line in (session / "activity.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    matched = set()
    for event in events:
        if event["event"] == "activity_begin" and (event["name"] in wanted or event["activity_id"] in wanted):
            begins[event["activity_id"]] = event
        elif event["event"] == "activity_end" and event["activity_id"] in begins:
            begin = begins.pop(event["activity_id"])
            matched |= {begin["name"], begin["activity_id"]}
            windows.append((timestamp(begin["recorded_at_utc"]) - pad, timestamp(event["recorded_at_utc"]) + pad,
                            f"activity:{begin['name']}"))
    if wanted - matched:
        raise ValueError(f"Excluded activities are not closed activities in the journal: {sorted(wanted - matched)}")
    return windows


def label_session(session: Path, zeek: Path, policy_path: Path, output: Path, source: str) -> dict:
    if output.exists():
        raise ValueError("Label output already exists; choose a new version directory.")
    if not source.strip() or len(source) > 128:
        raise ValueError("Source name must be 1-128 characters.")
    policy = load_policy(policy_path)
    integrity = verify_session(session)
    manifest = json.loads((session / "session-manifest.json").read_text(encoding="utf-8"))
    if (sha256(session / "session-manifest.json") != policy["session"]["manifest_sha256"]
            or manifest["session_id"] != policy["session"]["session_id"]):
        raise ValueError("Policy is pinned to a different session or manifest.")
    connections = read_log(zeek / "conn.log")
    if not connections:
        raise ValueError("conn.log is empty or missing.")
    evidence = {"ssl": defaultdict(list), "http": defaultdict(list), "dns": defaultdict(list)}
    for row in read_log(zeek / "ssl.log"):
        evidence["ssl"][row["uid"]].append(row.get("server_name"))
    for row in read_log(zeek / "http.log"):
        evidence["http"][row["uid"]].append(row)
    for row in read_log(zeek / "dns.log"):
        if row.get("query"):
            evidence["dns"][row["uid"]].append(row["query"])
    windows = exclusion_windows(session, policy["exclusions"])
    # Outer VXLAN carriers are encapsulation, not observations (as in zeek-conn-window-v2); they never
    # count toward the guard either, since node-to-node tunnels fan out by source port only.
    flagged = scan_guard([c for c in connections if not is_tunnel_carrier(c)], policy["exclusions"])
    networks = policy["_networks"]

    labeled, provenance = [], []
    counts, by_rule, unmatched = Counter(), Counter(), Counter()
    seen = set()
    for conn in connections:
        counts["connections"] += 1
        if conn["uid"] in seen:
            raise ValueError(f"Duplicate uid in conn.log: {conn['uid']}")
        seen.add(conn["uid"])
        if is_tunnel_carrier(conn):
            counts["excluded_tunnel_carrier"] += 1
            continue
        start, end = conn["ts"], conn["ts"] + float(conn.get("duration") or 0)
        window = next((reason for low, high, reason in windows if start <= high and end >= low), None)
        if window:
            counts[f"excluded_{window.split(':')[0]}"] += 1
            continue
        if conn["id.orig_h"] in flagged:
            counts["excluded_scan_guard"] += 1
            continue
        matches = {}
        for rule in policy["rules"]:
            found = match_rule(conn, rule, evidence)
            if found is not None:
                matches[rule["name"]] = found
        if not matches:
            counts["unmatched"] += 1
            tls = evidence["ssl"].get(conn["uid"])
            http = evidence["http"].get(conn["uid"])
            unmatched[(conn["proto"], network_name(conn["id.orig_h"], networks),
                       network_name(conn["id.resp_h"], networks), conn["id.resp_p"], conn.get("service"),
                       conn.get("conn_state"), (tls or [None])[0] or ((http or [{}])[0].get("host")))] += 1
            continue
        counts["labeled"] += 1
        by_rule.update(matches.keys())
        labeled.append({"source": source, "label": "BENIGN", "label_tier": policy["label_tier"], "conn": conn})
        provenance.append({"uid": conn["uid"], "label": "BENIGN", "label_tier": policy["label_tier"],
                           "rules": sorted(matches), "evidence": {name: value for name, value in matches.items() if value}})

    output.mkdir(parents=True)
    (output / "reviewed.jsonl").write_text("".join(json.dumps(row) + "\n" for row in labeled), encoding="utf-8")
    (output / "reviewed-label-provenance.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in provenance), encoding="utf-8")
    report = {
        "schema_version": 1, "source": source, "label_tier": policy["label_tier"],
        "session_id": manifest["session_id"], "session_integrity": integrity,
        "attestation": policy["session"]["attestation"], "counts": dict(counts),
        "labeled_by_rule": dict(by_rule), "scan_guard_originators": flagged,
        "exclusion_windows": [{"start": low, "end": high, "reason": reason} for low, high, reason in windows],
        "unmatched_groups": [{"count": count, "proto": key[0], "orig_network": key[1], "resp_network": key[2],
                              "resp_port": key[3], "service": key[4], "conn_state": key[5], "name": key[6]}
                             for key, count in unmatched.most_common(100)],
        "inputs_sha256": {"policy": sha256(policy_path), "session_manifest": policy["session"]["manifest_sha256"],
                          **{name: sha256(zeek / name) for name in ("conn.log", "ssl.log", "http.log", "dns.log")
                             if (zeek / name).exists()}},
        "labeler_sha256": sha256(Path(__file__)),
        "outputs_sha256": {name: sha256(output / name) for name in ("reviewed.jsonl", "reviewed-label-provenance.jsonl")},
        "limitations": [
            "Allowlist labels assert the traffic type is expected on this network, not that each flow was inspected.",
            "Unmatched connections are unlabeled, not suspicious; grow the policy only from reviewed explanations.",
            "The operator attestation covers deliberate activity only; compromised hosts would not be detected by it.",
            "Keep this tier distinguishable from strictly reviewed labels in recipes and reports.",
        ],
    }
    write_json(output / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--session", type=Path, required=True, help="Sealed capture_session bundle.")
    parser.add_argument("--zeek", type=Path, required=True, help="Zeek JSON log directory for that capture.")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New label version directory.")
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        report = label_session(args.session, args.zeek, args.policy, args.output, args.source)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"Labeling refused: {exc}\n")
    print(json.dumps({key: report[key] for key in ("counts", "labeled_by_rule", "scan_guard_originators")}, indent=2))


if __name__ == "__main__":
    main()
