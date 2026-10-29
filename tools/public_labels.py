"""Conservative source-label parsing and tuple/time joins; never label from predictions."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, UTC
import io
import json
import math
from pathlib import Path
import re
import zipfile

from app.schemas import FlowRecord
from sensor.zeek_to_cicids import conn_record_to_flow, protocol_number
from tools.training_data import sha256, write_json


def tuple_key(src, sport, dst, dport, proto):
    endpoints = sorted(((str(src), int(sport)), (str(dst), int(dport))))
    return int(proto), endpoints[0], endpoints[1]


def conn_key(conn):
    return tuple_key(conn["id.orig_h"], conn["id.orig_p"], conn["id.resp_h"], conn["id.resp_p"], protocol_number(conn))


def cic_class(label):
    normalized = re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()
    if normalized == "benign":
        return "BENIGN"
    if normalized in {"ftp patator", "ssh patator", "ftp bruteforce", "ssh bruteforce"}:
        return "BRUTE_FORCE"
    if normalized.startswith("web attack"):
        if normalized.endswith("brute force"):
            return "BRUTE_FORCE"
        if normalized.endswith("xss") or normalized.endswith("sql injection"):
            return "OTHER_ATTACK"
    if normalized == "infiltration":
        return "OTHER_ATTACK"
    if normalized in {"bot", "botnet"}:
        return "BOTNET"
    if normalized.startswith("dos ") or normalized.startswith("ddos "):
        return "DOS_DDOS"
    return None


def iot_class(coarse, detailed):
    if coarse == "Benign" and detailed == "-":
        return "BENIGN"
    if coarse != "Malicious":
        return None
    # Explicit behavior mapping for the starter scenarios. Unknown/composite labels
    # stay unreviewed rather than becoming BOTNET solely because a host is infected.
    return {"C&C": "BOTNET", "DDoS": "DOS_DDOS", "PartOfAHorizontalPortScan": "OTHER_ATTACK"}.get(detailed)


def read_iot_labels(path):
    fields = None
    with path.open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            if line.startswith("#fields"):
                fields = re.split(r"\t| {3,}", line.rstrip("\r\n"))[1:]
            elif line.startswith("#") or not line.strip():
                continue
            else:
                values = re.split(r"\t| {3,}", line.rstrip("\r\n"))
                if fields is None or len(fields) != len(values):
                    raise ValueError(f"IoT label field mismatch at line {number}.")
                row = dict(zip(fields, values))
                proto = protocol_number(row)
                yield {"key": tuple_key(row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"], proto),
                       "ts": float(row["ts"]), "duration": 0 if row["duration"] == "-" else float(row["duration"]),
                       "label": iot_class(row["label"], row.get("detailed-label", row.get("det_label"))),
                       "source_label": row["label"], "source_detail": row.get("detailed-label", row.get("det_label")),
                       "evidence": {"file": path.name, "line": number, "source_uid": row["uid"]}}


def read_cic_labels(archive_path, members=None):
    """Read label metadata only; CICFlowMeter feature columns never become model inputs."""
    with zipfile.ZipFile(archive_path) as archive:
        selected = members if members is not None else [name for name in archive.namelist() if name.endswith(".csv")]
        for name in selected:
            with archive.open(name) as source:
                # Original generated-label files use cp1252 en-dashes in attack names.
                reader = csv.DictReader(io.TextIOWrapper(source, encoding="cp1252", newline=""))
                reader.fieldnames = [field.strip() for field in reader.fieldnames]
                for number, row in enumerate(reader, 2):
                    if all(value in (None, "") for value in row.values()):
                        yield {"blank": True, "evidence": {"file": name, "line": number}}
                        continue
                    label = row["Label"].strip()
                    try:
                        key = tuple_key(row["Source IP"].strip(), row["Source Port"], row["Destination IP"].strip(),
                                        row["Destination Port"], row["Protocol"])
                        stamp = datetime.strptime(row["Timestamp"].strip(), "%d/%m/%Y %H:%M").replace(tzinfo=UTC).timestamp()
                        duration = float(row["Flow Duration"]) / 1_000_000
                    except (ValueError, TypeError) as exc:
                        raise ValueError(f"Invalid label metadata: {name}:{number}") from exc
                    yield {"key": key, "local_minute_as_utc": stamp, "duration": duration,
                           "label": cic_class(label), "source_label": label, "timestamp_text": row["Timestamp"],
                           "evidence": {"file": name, "line": number}}


def make_index(rows):
    index = defaultdict(list)
    for row in rows:
        if not row.get("blank"):
            index[row["key"]].append(row)
    for entries in index.values():
        entries.sort(key=lambda row: row["ts"])
    return dict(index)


def match_iot(conn, index, tolerance=0.001):
    entries = index.get(conn_key(conn), [])
    start, finish = conn["ts"], conn["ts"] + conn.get("duration", 0)
    anchors = [row for row in entries if abs(row["ts"] - start) <= tolerance]
    if not anchors:
        return None, "no_unique_time_anchor"
    # Detect a newer Zeek version merging source observations with different labels.
    overlaps = [row for row in entries if row["ts"] <= finish + tolerance
                and row["ts"] + row["duration"] >= start - tolerance]
    labels = {row["label"] for row in [*anchors, *overlaps]}
    if None in labels or len(labels) != 1:
        return None, "ambiguous_or_unmapped_source_labels"
    return {"label": anchors[0]["label"], "evidence": [row["evidence"] for row in anchors],
            "overlapping_source_evidence": [row["evidence"] for row in overlaps],
            "source_labels": sorted({row["source_detail"] for row in [*anchors, *overlaps]}),
            "matching": "bidirectional 5-tuple and start timestamp within 1 ms; overlapping source labels agree"}, None


def infer_cic_clock(connections, rows, *, minimum_anchors=20, minimum_agreement=0.95):
    sources, observed = defaultdict(list), defaultdict(list)
    for row in rows:
        sources[row["key"]].append(row)
    for conn in connections:
        observed[conn_key(conn)].append(conn)
    offsets = Counter()
    for key, entries in sources.items():
        matches = observed.get(key, [])
        if len(entries) != 1 or len(matches) != 1:
            continue
        delta = matches[0]["ts"] - entries[0]["local_minute_as_utc"]
        hour = math.floor(delta / 3600)
        if -0.001 <= delta - hour * 3600 < 60.001:
            offsets[hour] += 1
    folded = Counter()
    for hour, count in offsets.items():
        folded[hour % 12] += count
    if not folded:
        raise ValueError("No unique tuple/time anchors establish the CIC source clock.")
    hour, support = folded.most_common(1)[0]
    agreement = support / sum(folded.values())
    if support < minimum_anchors or agreement < minimum_agreement:
        raise ValueError("CIC source clock is ambiguous or has insufficient independent anchors.")
    return {"utc_offset_hours_modulo_12": hour, "supporting_unique_tuple_anchors": support,
            "accepted_unique_tuple_anchors": sum(offsets.values()), "agreement": agreement,
            "observed_hour_offsets": {str(k): v for k, v in sorted(offsets.items())},
            "method": "Unique tuples in both sources; CSV minute containment; 12-hour ambiguity checked against capture bounds."}


def cic_index(rows, clock, connections):
    first = min(conn["ts"] for conn in connections) - 60
    last = max(conn["ts"] + conn.get("duration", 0) for conn in connections) + 60
    expanded = []
    for row in rows:
        if not math.isfinite(row["duration"]) or row["duration"] < 0:
            continue
        base = row["local_minute_as_utc"] + clock["utc_offset_hours_modulo_12"] * 3600
        possible = [base]
        if datetime.fromtimestamp(row["local_minute_as_utc"], UTC).hour < 12:
            possible.append(base + 12 * 3600)
        for start in possible:
            if first <= start <= last:
                expanded.append({**row, "ts": start})
    return make_index(expanded)


def match_cic(conn, index):
    entries = index.get(conn_key(conn), [])
    start = conn["ts"]
    finish = start + conn.get("duration", 0)
    anchors = [row for row in entries if row["ts"] - 0.001 <= start < row["ts"] + 60.001]
    if not anchors:
        return None, "no_csv_minute_anchor"
    overlaps = [row for row in entries if row["ts"] <= finish + 0.001
                and row["ts"] + 60 + row["duration"] >= start - 0.001]
    labels = {row["label"] for row in [*anchors, *overlaps]}
    if None in labels or len(labels) != 1:
        return None, "ambiguous_or_unmapped_source_labels"
    return {"label": anchors[0]["label"], "evidence": [row["evidence"] for row in anchors],
            "overlapping_source_evidence": [row["evidence"] for row in overlaps],
            "source_labels": sorted({row["source_label"] for row in [*anchors, *overlaps]}),
            "matching": "bidirectional 5-tuple, aligned CSV minute, and agreeing overlapping source labels"}, None


def label_connections(conn_path, labels_path, output, source, source_rows, index, matcher, extra=None):
    if output.exists():
        raise ValueError("Label output exists; choose a new review version.")
    counts, reasons = Counter(), Counter()
    output.mkdir(parents=True)
    with (output / "reviewed.jsonl").open("w", encoding="utf-8") as reviewed, \
         (output / "provenance.jsonl").open("w", encoding="utf-8") as provenance, \
         (output / "unmatched.jsonl").open("w", encoding="utf-8") as unmatched, \
         (output / "rejections.jsonl").open("w", encoding="utf-8") as rejected:
        seen = set()
        total = 0
        for number, line in enumerate(conn_path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            total += 1
            conn = json.loads(line)
            try:
                flow = FlowRecord.model_validate(conn_record_to_flow(conn))
                if flow.flow_id in seen:
                    raise ValueError("Duplicate observation.")
                seen.add(flow.flow_id)
            except (ValueError, TypeError, OverflowError) as exc:
                rejected.write(json.dumps({"line": number, "uid": conn.get("uid"), "reason": str(exc), "conn": conn}) + "\n")
                reasons["conversion_rejection"] += 1
                continue
            match, reason = matcher(conn, index)
            if match is None:
                reasons[reason] += 1
                unmatched.write(json.dumps({"line": number, "uid": conn["uid"], "reason": reason, "conn": conn}) + "\n")
                continue
            reviewed.write(json.dumps({"source": source, "label": match["label"], "conn": conn}) + "\n")
            provenance.write(json.dumps({"uid": conn["uid"], "flow_id": flow.flow_id, **match,
                                         "source_label_file": labels_path.name,
                                         "prediction_used_for_labeling": False}) + "\n")
            counts[match["label"]] += 1
    report = {"source": source, "conn_records": total, "reviewed_records": sum(counts.values()), "class_counts": dict(counts),
              "unmatched_or_rejected": dict(reasons), "source_label_rows": len(source_rows),
              "labeling_code_sha256": sha256(Path(__file__)),
              "input_sha256": {"conn.log": sha256(conn_path), "source_labels": sha256(labels_path)},
              "output_sha256": {name: sha256(output / name) for name in
                                ("reviewed.jsonl", "provenance.jsonl", "unmatched.jsonl", "rejections.jsonl")},
              "limitations": ["Labels inherit the publisher's ground truth and its limitations.",
                              "UIDs from different Zeek runs are never used as join keys.",
                              "Unknown source labels, conflicting overlaps, and unmatched observations remain unreviewed.",
                              "Malware family/host infection does not automatically label all connections BOTNET."], **(extra or {})}
    assert report["reviewed_records"] + sum(reasons.values()) == total
    write_json(output / "report.json", report)
    return report


def label_iot(conn_path: Path, labels_path: Path, output: Path, source: str):
    rows = list(read_iot_labels(labels_path))
    return label_connections(conn_path, labels_path, output, source, rows, make_index(rows), match_iot)


def label_cic(conn_path: Path, labels_path: Path, output: Path, source: str):
    connections = [json.loads(line) for line in conn_path.read_text().splitlines() if line.strip()]
    rows = [json.loads(line) for line in labels_path.read_text().splitlines() if line.strip()]
    for row in rows:
        key = row["key"]
        row["key"] = key[0], tuple(key[1]), tuple(key[2])
    clock = infer_cic_clock(connections, rows)
    return label_connections(conn_path, labels_path, output, source, rows,
                             cic_index(rows, clock, connections), match_cic, {"clock_alignment": clock})


def cse_signature(conn):
    return (protocol_number(conn), conn["id.resp_p"], conn["orig_pkts"], conn["resp_pkts"],
            round(conn.get("duration", 0) * 1_000_000))


def cse_metadata_matches(connections, labels_path, *, minimum_anchors=20):
    counts = Counter(cse_signature(conn) for conn in connections)
    unique = {cse_signature(conn): conn for conn in connections
              if counts[cse_signature(conn)] == 1 and conn.get("duration", 0) > 0}
    matched, duplicates = {}, set()
    with labels_path.open(encoding="utf-8-sig", newline="") as handle:
        for number, row in enumerate(csv.DictReader(handle), 2):
            try:
                key = (int(row["Protocol"]), int(row["Dst Port"]), int(row["Tot Fwd Pkts"]),
                       int(row["Tot Bwd Pkts"]), int(float(row["Flow Duration"])))
            except (ValueError, OverflowError):
                continue
            if key in unique:
                if key in matched:
                    duplicates.add(key)
                else:
                    matched[key] = {"line": number, "timestamp": row["Timestamp"], "source_label": row["Label"]}
    anchors, offsets = [], Counter()
    for key, row in matched.items():
        if key in duplicates:
            continue
        local = datetime.strptime(row["timestamp"], "%d/%m/%Y %H:%M:%S").replace(tzinfo=UTC).timestamp()
        delta = unique[key]["ts"] - local
        hour = round(delta / 3600)
        if -0.001 <= delta - hour * 3600 < 1.001:
            anchors.append((unique[key], row, hour))
            offsets[hour % 12] += 1
    if not offsets:
        raise ValueError("No unique CSE metadata anchors establish the clock.")
    hour, support = offsets.most_common(1)[0]
    if support < minimum_anchors or support / sum(offsets.values()) < 0.99:
        raise ValueError("CSE metadata clock is ambiguous or insufficiently supported.")
    lookup = {}
    for conn, row, offset in anchors:
        label = cic_class(row["source_label"])
        if offset % 12 != hour or label is None:
            continue
        lookup[conn["uid"]] = {"label": label, "evidence": [{"file": labels_path.name, "line": row["line"],
                                                            "source_timestamp": row["timestamp"]}],
                               "source_labels": [row["source_label"]],
                               "matching": "Signature unique in both sources: protocol, destination port, directional packet counts, exact microsecond duration; aligned source second agrees."}
    return lookup, {"utc_offset_hours_modulo_12": hour, "supporting_unique_signature_anchors": support,
                    "accepted_unique_signature_anchors": sum(offsets.values()), "agreement": support / sum(offsets.values()),
                    "duplicate_source_signatures_excluded": len(duplicates),
                    "caveat": "This source CSV lacks IP addresses/source ports; joins use globally unique packet/duration metadata and time, not endpoint tuples."}


def label_cse(conn_path: Path, labels_path: Path, output: Path, source: str):
    connections = [json.loads(line) for line in conn_path.read_text().splitlines() if line.strip()]
    lookup, clock = cse_metadata_matches(connections, labels_path)
    def match(conn, index):
        result = index.get(conn["uid"])
        return result, None if result is not None else "no_unique_metadata_and_time_match"
    return label_connections(conn_path, labels_path, output, source, list(lookup.values()), lookup, match,
                             {"clock_alignment": clock, "source_label_row_count_scope": "uniquely matched metadata only"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn", type=Path, required=True)
    labels = parser.add_mutually_exclusive_group(required=True)
    labels.add_argument("--iot-labels", type=Path)
    labels.add_argument("--cic-labels", type=Path, help="Source metadata emitted by subset_public_capture.")
    labels.add_argument("--cse-csv", type=Path, help="CICIDS2018 label CSV; features are never used as model inputs.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.iot_labels:
        result = label_iot(args.conn, args.iot_labels, args.output, args.source)
    elif args.cic_labels:
        result = label_cic(args.conn, args.cic_labels, args.output, args.source)
    else:
        result = label_cse(args.conn, args.cse_csv, args.output, args.source)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
