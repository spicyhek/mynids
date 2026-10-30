from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import sys
import time
import random
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request

if __package__ in (None, ""):
    # Preserve the existing `python /app/sensor/zeek_to_cicids.py` entry point.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.validation import MAX_BATCH_SIZE, validate_event_time, validate_features


PROTOCOL_NUMBERS = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "icmp6": 58,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert Zeek conn.log JSON records into CICIDS-style feature batches."
    )
    parser.add_argument(
        "--source-name", default=os.getenv("NIDS_SOURCE_NAME"),
        help="Stable, unique sensor identity (preferred over source-prefix/NODE_NAME).",
    )
    parser.add_argument(
        "--log-path",
        required=True,
        help="Path to Zeek conn.log in JSON-lines format.",
    )
    parser.add_argument(
        "--endpoint",
        required=True,
        help="Private NIDS ingestion endpoint.",
    )
    parser.add_argument(
        "--state-file",
        required=True,
        help="Path used to persist the last-read file offset.",
    )
    parser.add_argument(
        "--source-prefix",
        default="zeek-worker",
        help="Prefix for the logical source name included in emitted flow batches.",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("NIDS_INGEST_TOKEN", ""),
        help="Private ingestion token.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Maximum number of converted flows to place in a single request.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=5.0,
        help="Polling interval when no new Zeek records are available.",
    )
    parser.add_argument(
        "--features-v2", action="store_true",
        default=os.getenv("NIDS_EXPORT_FEATURES_V2", "").lower() in ("1", "true", "yes"),
        help="Also send zeek-conn-window-v2 features for shadow evaluation (upgrade the server first).",
    )
    return parser.parse_args()


class FeatureV2Stream:
    """Feed each conn.log line to the v2 window state at most once, in log-write order.

    Lines re-read after a failed export were already counted, so they are sent without
    features_v2 rather than counted twice.
    """

    def __init__(self) -> None:
        from sensor.zeek_features_v2 import CONTRACT_ID, Extractor  # Avoids a circular import.

        self.contract = CONTRACT_ID
        self.extractor = Extractor()
        self.identity: str | None = None
        self.offset = 0

    def reset(self, identity: str) -> None:
        self.identity, self.offset = identity, 0

    def process(self, identity: str, end_offset: int, record: dict[str, Any]) -> dict[str, Any] | None:
        if identity != self.identity:
            self.reset(identity)
        if end_offset <= self.offset:
            return None
        self.offset = end_offset
        try:
            return self.extractor.process(record)
        except (ValueError, KeyError, TypeError, OverflowError):
            return None  # v2 rejected the record before touching window state; v1 is unaffected.


def is_decoded_tunnel_carrier(record: dict[str, Any]) -> bool:
    """An outer connection Zeek decoded (service "vxlan"); its inner flows carry the same packets."""
    return "vxlan" in str(record.get("service") or "").split(",")


def parse_zeek_json_line(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("Zeek log line must decode to an object.")
    return parsed


def to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        raise ValueError("Zeek numeric fields cannot be booleans.")
    if value in (None, "-", ""):
        return default
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Zeek numeric field is invalid.") from exc
    if not math.isfinite(result):
        raise ValueError("Zeek numeric field must be finite.")
    return result


def to_int(value: Any, default: int = 0) -> int:
    number = to_float(value, float(default))
    if number < 0 or number > 2**53 - 1 or int(number) != number:
        raise ValueError("Zeek count/port must be a nonnegative safe integer.")
    return int(number)


def safe_div(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator / denominator)


def safe_non_negative(value: float) -> float:
    if value < 0:
        raise ValueError("Zeek duration and byte counts must be nonnegative.")
    return value


def history_count(history: str, letters: str) -> int:
    return sum(history.count(letter) for letter in letters)


def protocol_number(record: dict[str, Any]) -> int:
    text = str(record.get("proto")).lower()
    if text not in PROTOCOL_NUMBERS:
        raise ValueError(f"Unsupported Zeek protocol: {text}")
    # Zeek uses proto="icmp" for both IP families. ip_proto is the actual
    # IP protocol number, so prefer it over the transport category.
    value = record.get("ip_proto")
    if value not in (None, "-", ""):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Zeek ip_proto must be an integer from 0 to 255.")
        number = to_int(value)
        if number > 255:
            raise ValueError("Zeek ip_proto must be an integer from 0 to 255.")
        allowed = (1, 58) if text == "icmp" else (PROTOCOL_NUMBERS[text],)
        if number not in allowed:
            raise ValueError("Zeek ip_proto disagrees with its transport category.")
        return number
    # Older Zeek logs may omit ip_proto. Infer ICMPv6 from the available
    # endpoints; records without either endpoint retain the legacy fallback.
    if text == "icmp":
        versions = {
            ipaddress.ip_address(record[name]).version
            for name in ("id.orig_h", "id.resp_h")
            if record.get(name) not in (None, "-", "")
        }
        if len(versions) > 1:
            raise ValueError("Zeek ICMP endpoints have different IP versions.")
        if versions == {6}:
            return 58
    return PROTOCOL_NUMBERS[text]


def direction_stats(total_bytes: float, packets: int) -> tuple[float, float, float, float]:
    if packets <= 0:
        return 0.0, 0.0, 0.0, 0.0
    mean = safe_div(total_bytes, float(packets))
    return mean, mean, mean, 0.0


def iat_stats(duration_us: float, packets: int) -> tuple[float, float, float, float, float]:
    if packets <= 1:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    total = duration_us
    mean = safe_div(duration_us, float(packets - 1))
    return total, mean, 0.0, mean, mean


def normalize_timestamp(ts_value: float) -> tuple[float, str]:
    ts = to_float(ts_value)
    dt = validate_event_time(datetime.fromtimestamp(ts, tz=UTC))
    return ts * 1_000_000.0, dt.isoformat().replace("+00:00", "Z")


def conn_record_to_flow(record: dict[str, Any]) -> dict[str, Any]:
    for name in ("uid", "ts", "orig_pkts", "resp_pkts", "id.orig_p", "id.resp_p", "proto"):
        if record.get(name) in (None, "-", ""):
            raise ValueError(f"Missing required Zeek field: {name}")
    uid = record["uid"]
    if not isinstance(uid, str) or not uid or len(uid) > 160 or any(c.isspace() for c in uid):
        raise ValueError("Invalid Zeek uid.")
    for name in ("id.orig_p", "id.resp_p"):
        if to_int(record[name]) > 65535:
            raise ValueError("Zeek port exceeds 65535.")
    duration_s = safe_non_negative(to_float(record.get("duration")))
    duration_us = duration_s * 1_000_000.0
    timestamp_us, event_time = normalize_timestamp(to_float(record.get("ts")))

    orig_pkts = to_int(record.get("orig_pkts"))
    resp_pkts = to_int(record.get("resp_pkts"))
    total_pkts = orig_pkts + resp_pkts

    orig_ip_bytes = safe_non_negative(to_float(record.get("orig_ip_bytes", record.get("orig_bytes"))))
    resp_ip_bytes = safe_non_negative(to_float(record.get("resp_ip_bytes", record.get("resp_bytes"))))
    orig_bytes = safe_non_negative(to_float(record.get("orig_bytes")))
    resp_bytes = safe_non_negative(to_float(record.get("resp_bytes")))
    total_ip_bytes = orig_ip_bytes + resp_ip_bytes

    fwd_pkt_len_mean, fwd_pkt_len_min, fwd_pkt_len_max, fwd_pkt_len_std = direction_stats(
        orig_ip_bytes,
        orig_pkts,
    )
    bwd_pkt_len_mean, bwd_pkt_len_min, bwd_pkt_len_max, bwd_pkt_len_std = direction_stats(
        resp_ip_bytes,
        resp_pkts,
    )

    pkt_len_mean = safe_div(total_ip_bytes, float(total_pkts)) if total_pkts else 0.0
    positive_packet_lengths = [value for value in (fwd_pkt_len_min, bwd_pkt_len_min) if value > 0]
    pkt_len_min = min(positive_packet_lengths) if positive_packet_lengths else 0.0
    pkt_len_max = max(fwd_pkt_len_max, bwd_pkt_len_max)
    pkt_len_std = 0.0
    pkt_len_var = 0.0

    flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = iat_stats(duration_us, total_pkts)
    fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = iat_stats(duration_us, orig_pkts)
    bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = iat_stats(duration_us, resp_pkts)

    history = str(record.get("history") or "")
    fwd_header_len = safe_non_negative(orig_ip_bytes - orig_bytes)
    bwd_header_len = safe_non_negative(resp_ip_bytes - resp_bytes)

    features = {
        "dst_port": float(to_int(record.get("id.resp_p"))),
        "protocol": float(protocol_number(record)),
        "timestamp": float(timestamp_us),
        "flow_duration": float(duration_us),
        "tot_fwd_pkts": float(orig_pkts),
        "tot_bwd_pkts": float(resp_pkts),
        "totlen_fwd_pkts": float(orig_ip_bytes),
        "totlen_bwd_pkts": float(resp_ip_bytes),
        "fwd_pkt_len_max": float(fwd_pkt_len_max),
        "fwd_pkt_len_min": float(fwd_pkt_len_min),
        "fwd_pkt_len_mean": float(fwd_pkt_len_mean),
        "fwd_pkt_len_std": float(fwd_pkt_len_std),
        "bwd_pkt_len_max": float(bwd_pkt_len_max),
        "bwd_pkt_len_min": float(bwd_pkt_len_min),
        "bwd_pkt_len_mean": float(bwd_pkt_len_mean),
        "bwd_pkt_len_std": float(bwd_pkt_len_std),
        "flow_byts_s": safe_div(total_ip_bytes, duration_s),
        "flow_pkts_s": safe_div(float(total_pkts), duration_s),
        "flow_iat_mean": float(flow_iat_mean),
        "flow_iat_std": float(flow_iat_std),
        "flow_iat_max": float(flow_iat_max),
        "flow_iat_min": float(flow_iat_min),
        "fwd_iat_tot": float(fwd_iat_tot),
        "fwd_iat_mean": float(fwd_iat_mean),
        "fwd_iat_std": float(fwd_iat_std),
        "fwd_iat_max": float(fwd_iat_max),
        "fwd_iat_min": float(fwd_iat_min),
        "bwd_iat_tot": float(bwd_iat_tot),
        "bwd_iat_mean": float(bwd_iat_mean),
        "bwd_iat_std": float(bwd_iat_std),
        "bwd_iat_max": float(bwd_iat_max),
        "bwd_iat_min": float(bwd_iat_min),
        # conn.log history is compressed connection history, not a TCP flag counter.
        "fwd_psh_flags": 0.0,
        "bwd_psh_flags": 0.0,
        "fwd_urg_flags": 0.0,
        "bwd_urg_flags": 0.0,
        "fwd_header_len": float(fwd_header_len),
        "bwd_header_len": float(bwd_header_len),
        "fwd_pkts_s": safe_div(float(orig_pkts), duration_s),
        "bwd_pkts_s": safe_div(float(resp_pkts), duration_s),
        "pkt_len_min": float(pkt_len_min),
        "pkt_len_max": float(pkt_len_max),
        "pkt_len_mean": float(pkt_len_mean),
        "pkt_len_std": float(pkt_len_std),
        "pkt_len_var": float(pkt_len_var),
        "fin_flag_cnt": float(history_count(history, "Ff")),
        "syn_flag_cnt": float(history_count(history, "SsHh")),
        "rst_flag_cnt": float(history_count(history, "Rr")),
        "psh_flag_cnt": 0.0,
        "ack_flag_cnt": float(history_count(history, "Aa")),
        "urg_flag_cnt": 0.0,
        "cwe_flag_count": 0.0,
        "ece_flag_cnt": 0.0,
        "down_up_ratio": safe_div(float(resp_pkts), float(orig_pkts)),
        "pkt_size_avg": float(pkt_len_mean),
        "fwd_seg_size_avg": float(fwd_pkt_len_mean),
        "bwd_seg_size_avg": float(bwd_pkt_len_mean),
        "fwd_byts_b_avg": 0.0,
        "fwd_pkts_b_avg": 0.0,
        "fwd_blk_rate_avg": 0.0,
        "bwd_byts_b_avg": 0.0,
        "bwd_pkts_b_avg": 0.0,
        "bwd_blk_rate_avg": 0.0,
        "subflow_fwd_pkts": float(orig_pkts),
        "subflow_fwd_byts": float(orig_ip_bytes),
        "subflow_bwd_pkts": float(resp_pkts),
        "subflow_bwd_byts": float(resp_ip_bytes),
        "init_fwd_win_byts": 0.0,
        "init_bwd_win_byts": 0.0,
        "fwd_act_data_pkts": float(orig_pkts),
        "fwd_seg_size_min": float(fwd_pkt_len_min),
        "active_mean": float(duration_us if total_pkts else 0.0),
        "active_std": 0.0,
        "active_max": float(duration_us if total_pkts else 0.0),
        "active_min": float(duration_us if total_pkts else 0.0),
        "idle_mean": 0.0,
        "idle_std": 0.0,
        "idle_max": 0.0,
        "idle_min": 0.0,
        "src_port": float(to_int(record.get("id.orig_p"))),
    }
    validate_features(features)

    return {
        # Timestamp protects against a UID namespace being reused after sensor resets.
        "flow_id": f"{uid}:{event_time}",
        "event_time": event_time,
        "features": features,
    }


def load_state(state_file: Path) -> dict[str, Any]:
    if not state_file.exists():
        return {"offset": 0}
    try:
        parsed = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or type(parsed.get("offset")) is not int or parsed["offset"] < 0:
            raise ValueError("Invalid checkpoint offset")
        return parsed
    except (ValueError, UnicodeError):
        # Replaying is safe because identities are durably deduplicated by the API.
        print("Invalid checkpoint: replaying available log with server deduplication.", file=sys.stderr)
        return {"offset": 0}


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_state(state_file: Path, offset: int, **metadata: Any) -> None:
    atomic_json(state_file, {"offset": offset, **metadata})


V2_FIELDS = ("features_v2", "window_warm", "window_degraded")


def without_v2(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in flow.items() if key not in V2_FIELDS} for flow in flows]


def send_payload(endpoint: str, token: str, source_name: str, flows: list[dict[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {"source": source_name, "flows": flows}
    if any("features_v2" in flow for flow in flows):
        from sensor.zeek_features_v2 import CONTRACT_ID

        payload["features_v2_contract"] = CONTRACT_ID
    body = json.dumps(payload, allow_nan=False).encode("utf-8")
    req = request.Request(endpoint, data=body, headers={
        "Content-Type": "application/json", "X-Ingest-Token": token,
    }, method="POST")
    with request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def validate_ack(response: Any, source: str, flows: list[dict]) -> None:
    if not isinstance(response, dict):
        raise ValueError("Invalid ingest acknowledgment")
    for key in ("received", "inserted", "duplicates"):
        if type(response.get(key)) is not int or response[key] < 0:
            raise ValueError("Invalid ingest acknowledgment counters")
    if (response.get("source") != source or response["received"] != len(flows)
            or response["inserted"] + response["duplicates"] != len(flows)
            or response.get("flow_ids") != [flow["flow_id"] for flow in flows]):
        raise ValueError("Ingest acknowledgment does not account for the complete batch")


def quarantine(state_file: Path, reason: str, record: Any) -> None:
    # Bounded diagnostic journal containing rejected records for investigation.
    path = state_file.with_suffix(state_file.suffix + ".quarantine.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size >= 1_048_576:
        os.replace(path, path.with_suffix(path.suffix + ".1"))
    representation = json.dumps(record, default=lambda value: value.decode("utf-8", errors="replace")
                                if isinstance(value, bytes) else str(value))
    entry = {"time": datetime.now(UTC).isoformat(), "reason": reason[:500],
             "record_hash": hashlib.sha256(representation.encode()).hexdigest(),
             "record": representation[:65536], "truncated": len(representation) > 65536}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(f"Quarantined invalid record: {reason}", file=sys.stderr, flush=True)


def deliver(endpoint: str, token: str, source: str, flows: list[dict], state_file: Path) -> int:
    try:
        response = send_payload(endpoint, token, source, flows)
        validate_ack(response, source, flows)
        return len(flows)
    except error.HTTPError as exc:
        if exc.code not in (409, 413, 422):
            raise
        if exc.code == 422 and any("features_v2" in flow for flow in flows):
            # A server without shadow support rejects the extra fields; never lose v1 flows for them.
            print("Ingest rejected features_v2; resending this batch without them.", file=sys.stderr, flush=True)
            return deliver(endpoint, token, source, without_v2(flows), state_file)
        if len(flows) > 1:
            middle = len(flows) // 2
            return (deliver(endpoint, token, source, flows[:middle], state_file)
                    + deliver(endpoint, token, source, flows[middle:], state_file))
        quarantine(state_file, f"Ingest rejected record with HTTP {exc.code}", flows[0])
        return 0


def file_identity(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_dev}:{stat.st_ino}"


def anchor(handle: Any, offset: int) -> str:
    position = handle.tell()
    handle.seek(0)
    digest = hashlib.sha256(handle.read(min(offset, 4096)))
    start = max(0, offset - 4096)
    handle.seek(start)
    digest.update(handle.read(offset - start))
    handle.seek(position)
    return digest.hexdigest()


def export_log_once(*, log_path: Path, endpoint: str, state_file: Path,
                    source_name: str, token: str, batch_size: int,
                    features_v2: FeatureV2Stream | None = None) -> int:
    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {MAX_BATCH_SIZE}")
    spool = state_file.with_suffix(state_file.suffix + ".pending.json")
    exported = 0

    def drain() -> None:
        nonlocal exported
        pending = json.loads(spool.read_text(encoding="utf-8"))
        if pending["source"] != source_name or pending["endpoint"] != endpoint:
            raise ValueError("Pending batch belongs to a different source/endpoint; restore its configuration first.")
        exported += deliver(endpoint, token, source_name, pending["flows"], state_file)
        atomic_json(state_file, pending["checkpoint"])
        spool.unlink()

    if spool.exists():
        drain()
    state = load_state(state_file)
    if state.get("source", source_name) != source_name:
        raise ValueError("Checkpoint belongs to another source; use its original stable identity.")
    if not log_path.exists():
        return exported
    current_identity = file_identity(log_path)
    read_path = log_path
    previous_identity = state.get("identity")
    if previous_identity and previous_identity != current_identity:
        # Drain a renamed file before switching to its replacement, even after restart.
        candidates = [p for p in log_path.parent.glob(log_path.stem + "*")
                      if p.is_file() and file_identity(p) == previous_identity]
        if candidates:
            read_path = candidates[0]
        else:
            raise OSError("Unread rotated log is unavailable; restore it beside the current log before retrying.")
    identity = file_identity(read_path)
    offset = state["offset"]
    with read_path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if f"{opened.st_dev}:{opened.st_ino}" != identity:
            raise OSError("Log rotated while opening it; retry with the preserved checkpoint.")
        # A checkpoint anchor also detects copy-truncate followed by rapid regrowth.
        if opened.st_size < offset or (state.get("anchor") and anchor(handle, offset) != state["anchor"]):
            offset = 0
            if features_v2 is not None:
                features_v2.reset(identity)  # Truncated and regrown: these are new lines.
        handle.seek(offset)
        flows: list[dict] = []

        def checkpoint(*, eof: bool = False) -> dict:
            return {"offset": offset, "identity": identity, "source": source_name,
                    "anchor": anchor(handle, offset), "eof": eof}

        def flush() -> None:
            nonlocal flows
            if flows:
                atomic_json(spool, {"source": source_name, "endpoint": endpoint,
                                    "flows": flows, "checkpoint": checkpoint()})
                drain()
                flows = []
            else:
                atomic_json(state_file, checkpoint())

        complete_eof = False
        while True:
            start = handle.tell()
            line = handle.readline(1_048_577)
            if not line:
                complete_eof = True
                break
            if len(line) > 1_048_576:
                raise ValueError("Zeek log line exceeds 1 MiB; checkpoint retained.")
            if not line.endswith(b"\n"):
                # A writer may still be appending this record. Never acknowledge its bytes.
                handle.seek(start)
                break
            offset = handle.tell()
            try:
                parsed = parse_zeek_json_line(line.decode("utf-8"))
                if parsed is not None:
                    # v2 sees every valid record first, as offline preparation does, even one v1 rejects.
                    v2 = features_v2.process(identity, offset, parsed) if features_v2 is not None else None
                    if is_decoded_tunnel_carrier(parsed):
                        continue  # Sending it as well as its inner flows would count each packet twice.
                    flow = conn_record_to_flow(parsed)
                    if v2 is not None:
                        flow.update(features_v2=v2["features"], window_warm=v2["window_warm"],
                                    window_degraded=v2["window_degraded"])
                    flows.append(flow)
            except (ValueError, OverflowError, OSError) as exc:
                quarantine(state_file, str(exc), line)
            if len(flows) >= batch_size:
                flush()
        flush()
        atomic_json(state_file, checkpoint(eof=complete_eof))
        if read_path != log_path and complete_eof:
            save_state(state_file, 0, identity=current_identity, source=source_name)
    return exported


def main() -> int:
    args = parse_args()
    node_name = os.getenv("NODE_NAME")
    source_name = args.source_name or (f"{args.source_prefix}-{node_name}" if node_name else None)
    if not args.token or not source_name or not 1 <= args.batch_size <= MAX_BATCH_SIZE or args.poll_seconds <= 0:
        print("Token, stable source identity, positive poll interval and batch size 1..1000 are required.", file=sys.stderr)
        return 2
    failures = 0
    stream = FeatureV2Stream() if args.features_v2 else None
    while True:
        try:
            exported = export_log_once(
                log_path=Path(args.log_path), endpoint=args.endpoint, state_file=Path(args.state_file),
                source_name=source_name, token=args.token, batch_size=args.batch_size, features_v2=stream,
            )
            failures = 0
            if exported:
                print(f"Acknowledged {exported} flow(s).", flush=True)
        except (OSError, ValueError, error.URLError) as exc:
            failures += 1
            print(f"Export failed; checkpoint/pending batch retained: {exc}", file=sys.stderr, flush=True)
        delay = min(60.0, args.poll_seconds * 2 ** min(failures, 6))
        time.sleep(delay + (random.uniform(0, delay * 0.1) if failures else 0))


if __name__ == "__main__":
    raise SystemExit(main())
