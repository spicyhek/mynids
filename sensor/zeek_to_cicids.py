from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request


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
    return parser.parse_args()


def parse_zeek_json_line(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("Zeek log line must decode to an object.")
    return parsed


def to_float(value: Any, default: float = 0.0) -> float:
    if value in (None, "-", ""):
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(result):
        return default
    return result


def to_int(value: Any, default: int = 0) -> int:
    return int(round(to_float(value, float(default))))


def safe_div(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator / denominator)


def safe_non_negative(value: float) -> float:
    return value if value > 0 else 0.0


def history_count(history: str, letters: str) -> int:
    return sum(history.count(letter) for letter in letters)


def protocol_number(proto: Any) -> int:
    if proto is None:
        return 0
    text = str(proto).lower()
    return PROTOCOL_NUMBERS.get(text, 0)


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
    dt = datetime.fromtimestamp(ts, tz=UTC).replace(microsecond=0)
    return ts * 1_000_000.0, dt.isoformat().replace("+00:00", "Z")


def conn_record_to_flow(record: dict[str, Any]) -> dict[str, Any]:
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
        "protocol": float(protocol_number(record.get("proto"))),
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
        "fwd_psh_flags": float(history_count(history, "P")),
        "bwd_psh_flags": float(history_count(history, "p")),
        "fwd_urg_flags": float(history_count(history, "U")),
        "bwd_urg_flags": float(history_count(history, "u")),
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
        "psh_flag_cnt": float(history_count(history, "Pp")),
        "ack_flag_cnt": float(history_count(history, "Aa")),
        "urg_flag_cnt": float(history_count(history, "Uu")),
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

    return {
        "event_time": event_time,
        "features": features,
    }


def load_state(state_file: Path) -> dict[str, Any]:
    if not state_file.exists():
        return {"offset": 0}
    try:
        parsed = json.loads(state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"offset": 0}
    if not isinstance(parsed, dict):
        return {"offset": 0}
    return {"offset": int(parsed.get("offset", 0))}


def save_state(state_file: Path, offset: int) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"offset": offset}), encoding="utf-8")


def send_payload(endpoint: str, token: str, source_name: str, flows: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {"source": source_name, "flows": flows}
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Ingest-Token": token,
        },
        method="POST",
    )
    with request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def export_log_once(
    *,
    log_path: Path,
    endpoint: str,
    state_file: Path,
    source_name: str,
    token: str,
    batch_size: int,
) -> int:
    state = load_state(state_file)
    offset = int(state.get("offset", 0))
    if not log_path.exists():
        return 0
    file_size = log_path.stat().st_size
    if file_size < offset:
        offset = 0

    exported = 0
    pending_batch: list[tuple[int, dict[str, Any]]] = []

    def flush_batch() -> bool:
        nonlocal exported, pending_batch
        if not pending_batch:
            return True
        flows = [flow for _, flow in pending_batch]
        try:
            response = send_payload(endpoint, token, source_name, flows)
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            print(f"HTTP error from ingest API: {exc.code} {detail}", file=sys.stderr, flush=True)
            return False
        except error.URLError as exc:
            print(f"Connection error posting Zeek batch: {exc.reason}", file=sys.stderr, flush=True)
            return False

        exported += len(flows)
        save_state(state_file, pending_batch[-1][0])
        print(
            f"Posted {len(flows)} flow(s) from Zeek conn.log: stored={response.get('stored', 0)}",
            flush=True,
        )
        pending_batch = []
        return True

    with log_path.open("r", encoding="utf-8") as handle:
        handle.seek(offset)
        while True:
            line = handle.readline()
            if not line:
                break
            offset = handle.tell()
            try:
                parsed = parse_zeek_json_line(line)
            except json.JSONDecodeError as exc:
                print(f"Skipping malformed Zeek JSON: {exc}", file=sys.stderr, flush=True)
                continue
            except ValueError as exc:
                print(f"Skipping unsupported Zeek line: {exc}", file=sys.stderr, flush=True)
                continue
            if parsed is None:
                continue
            pending_batch.append((offset, conn_record_to_flow(parsed)))
            if len(pending_batch) >= batch_size and not flush_batch():
                return exported

    if not flush_batch():
        return exported

    if exported == 0:
        save_state(state_file, offset)
    return exported


def main() -> int:
    args = parse_args()
    if not args.token:
        print("Startup error: --token or NIDS_INGEST_TOKEN is required.", file=sys.stderr)
        return 2
    log_path = Path(args.log_path)
    state_file = Path(args.state_file)
    node_name = os.getenv("NODE_NAME", "unknown-node")
    source_name = f"{args.source_prefix}-{node_name}"

    print(
        f"Watching Zeek log {log_path} and posting CICIDS batches to {args.endpoint}",
        flush=True,
    )

    while True:
        exported = export_log_once(
            log_path=log_path,
            endpoint=args.endpoint,
            state_file=state_file,
            source_name=source_name,
            token=args.token,
            batch_size=max(args.batch_size, 1),
        )
        if exported:
            print(f"Exported {exported} flow(s) from Zeek conn.log", flush=True)
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
