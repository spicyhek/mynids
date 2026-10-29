"""Contract zeek-conn-window-v2: compact conn.log features plus causal per-host window counts.

See training/FEATURE_CONTRACT_V2.md. This module does not change the v1 converter,
exporter, or API; it is used for offline dataset preparation and shadow evaluation.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
import heapq
import ipaddress
from typing import Any

from app.validation import validate_features
from sensor.zeek_to_cicids import (normalize_timestamp, protocol_number, safe_div, safe_non_negative,
                                   to_float, to_int)

CONTRACT_ID = "zeek-conn-window-v2"
WINDOW_SECONDS = 60.0
TUNNEL_PORTS = frozenset({4789, 8472})  # VXLAN carriers: standard and Linux/flannel default.
CONN_STATES = ("S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")
FAILED_STATES = frozenset({"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR", "OTH"})
# Zeek history letters: upper case is the originator, lower case the responder; "^" is a direction flip.
ORIG_HISTORY = "SHADFRCGTWIQ^"
RESP_HISTORY = "shadfrcgtwiq"

CONNECTION_FEATURES = (
    "dst_port", "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "fwd_ip_bytes", "bwd_ip_bytes", "fwd_payload_bytes", "bwd_payload_bytes",
    "fwd_header_bytes", "bwd_header_bytes", "bytes_per_s", "bwd_fwd_pkt_ratio",
    "fwd_mean_pkt_bytes", "bwd_mean_pkt_bytes", "missed_bytes",
    *(f"conn_state_{state}" for state in CONN_STATES),
    *(f"hist_orig_{'flip' if letter == '^' else letter}" for letter in ORIG_HISTORY),
    *(f"hist_resp_{letter}" for letter in RESP_HISTORY),
)
WINDOW_FEATURES = (
    "src_conns", "src_distinct_dst_hosts", "src_distinct_dst_ports", "src_same_service_conns",
    "src_failed_frac", "src_mean_bwd_payload", "dst_conns", "dst_distinct_src_hosts", "dst_failed_frac",
    "svc_distinct_src_hosts",
)
FEATURE_ORDER = (*CONNECTION_FEATURES, *WINDOW_FEATURES)


def _host(record: dict[str, Any], name: str) -> str:
    value = record.get(name)
    if value in (None, "-", ""):
        raise ValueError(f"Missing required Zeek field: {name}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid Zeek address: {name}") from exc


def is_failed(record: dict[str, Any]) -> bool:
    state = record.get("conn_state")
    if state in ("RSTO", "RSTR"):
        # A reset after both sides sent payload is how many long sessions end, not a failed attempt.
        return not (to_float(record.get("orig_bytes")) > 0 and to_float(record.get("resp_bytes")) > 0)
    return state in FAILED_STATES


def is_tunnel_carrier(record: dict[str, Any]) -> bool:
    """Outer VXLAN connections are carriers, not observations; inner flows are classified instead."""
    return str(record.get("proto")).lower() == "udp" and to_int(record.get("id.resp_p")) in TUNNEL_PORTS


def connection_features(record: dict[str, Any]) -> dict[str, float]:
    for name in ("uid", "ts", "orig_pkts", "resp_pkts", "id.orig_p", "id.resp_p", "proto"):
        if record.get(name) in (None, "-", ""):
            raise ValueError(f"Missing required Zeek field: {name}")
    for name in ("id.orig_p", "id.resp_p"):
        if to_int(record[name]) > 65535:
            raise ValueError("Zeek port exceeds 65535.")
    duration_s = safe_non_negative(to_float(record.get("duration")))
    orig_pkts, resp_pkts = to_int(record.get("orig_pkts")), to_int(record.get("resp_pkts"))
    orig_ip_bytes = safe_non_negative(to_float(record.get("orig_ip_bytes", record.get("orig_bytes"))))
    resp_ip_bytes = safe_non_negative(to_float(record.get("resp_ip_bytes", record.get("resp_bytes"))))
    orig_bytes = safe_non_negative(to_float(record.get("orig_bytes")))
    resp_bytes = safe_non_negative(to_float(record.get("resp_bytes")))
    state = record.get("conn_state")
    if state in ("-", ""):
        state = None
    if state is not None and state not in CONN_STATES:
        raise ValueError(f"Unknown Zeek conn_state: {state!r}")
    history = str(record.get("history") or "")
    features = {
        "dst_port": float(to_int(record["id.resp_p"])),
        "protocol": float(protocol_number(record)),
        "flow_duration": duration_s * 1_000_000.0,
        "tot_fwd_pkts": float(orig_pkts),
        "tot_bwd_pkts": float(resp_pkts),
        "fwd_ip_bytes": orig_ip_bytes,
        "bwd_ip_bytes": resp_ip_bytes,
        "fwd_payload_bytes": orig_bytes,
        "bwd_payload_bytes": resp_bytes,
        # Zeek payload counts can exceed IP bytes when packets were missed; clamp rather than reject.
        "fwd_header_bytes": max(orig_ip_bytes - orig_bytes, 0.0),
        "bwd_header_bytes": max(resp_ip_bytes - resp_bytes, 0.0),
        "bytes_per_s": safe_div(orig_ip_bytes + resp_ip_bytes, duration_s),
        "bwd_fwd_pkt_ratio": safe_div(float(resp_pkts), float(orig_pkts)),
        "fwd_mean_pkt_bytes": safe_div(orig_ip_bytes, float(orig_pkts)),
        "bwd_mean_pkt_bytes": safe_div(resp_ip_bytes, float(resp_pkts)),
        "missed_bytes": safe_non_negative(to_float(record.get("missed_bytes"))),
    }
    features.update({f"conn_state_{name}": float(state == name) for name in CONN_STATES})
    features.update({f"hist_orig_{'flip' if letter == '^' else letter}": float(history.count(letter))
                     for letter in ORIG_HISTORY})
    features.update({f"hist_resp_{letter}": float(history.count(letter)) for letter in RESP_HISTORY})
    return features


class _Key:
    """Aggregates for one window key, kept exact by evicting a min-heap of end times."""
    __slots__ = ("heap", "peers", "ports", "services", "failed", "bwd_payload")

    def __init__(self) -> None:
        self.heap: list[tuple[float, int, tuple]] = []
        self.peers: Counter = Counter()
        self.ports: Counter = Counter()
        self.services: Counter = Counter()
        self.failed = 0
        self.bwd_payload = 0.0

    def add(self, end: float, sequence: int, entry: tuple) -> None:
        heapq.heappush(self.heap, (end, sequence, entry))
        self._apply(entry, 1)

    def evict(self, cutoff: float, limit: int) -> bool:
        """Drop entries that ended before cutoff; returns True if the per-key cap also dropped live ones."""
        while self.heap and self.heap[0][0] < cutoff:
            self._apply(heapq.heappop(self.heap)[2], -1)
        capped = False
        while len(self.heap) >= limit:
            self._apply(heapq.heappop(self.heap)[2], -1)
            capped = True
        return capped

    def _apply(self, entry: tuple, sign: int) -> None:
        peer, port, failed, bwd_payload = entry
        for counter, value in ((self.peers, peer), (self.ports, port), (self.services, (peer, port))):
            counter[value] += sign
            if counter[value] <= 0:
                del counter[value]
        self.failed += sign * failed
        self.bwd_payload += sign * bwd_payload


class WindowState:
    """Causal window over records in log-write order.

    The clock is a watermark: the largest end time (ts + duration) seen so far. A record
    sees every earlier-written record that ended within WINDOW_SECONDS of the watermark,
    plus itself. It never sees records written after it, so offline file-order replay
    reproduces online export exactly.
    """

    def __init__(self, window_seconds: float = WINDOW_SECONDS, max_keys: int = 100_000,
                 max_entries_per_key: int = 200_000) -> None:
        if window_seconds <= 0 or max_keys < 1 or max_entries_per_key < 1:
            raise ValueError("Window length and capacity limits must be positive.")
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.max_entries_per_key = max_entries_per_key
        self._maps: dict[str, OrderedDict] = {"src": OrderedDict(), "dst": OrderedDict(), "svc": OrderedDict()}
        self._first_end: float | None = None
        self._watermark = float("-inf")
        self._sequence = 0

    def _key(self, kind: str, key: Any, cutoff: float) -> tuple[_Key, bool]:
        table = self._maps[kind]
        degraded = False
        if key in table:
            table.move_to_end(key)
        else:
            while len(table) >= self.max_keys:
                _, oldest = table.popitem(last=False)
                # Losing a key that still holds live entries undercounts its future windows.
                degraded |= any(end >= cutoff for end, _, _ in oldest.heap)
            table[key] = _Key()
        degraded |= table[key].evict(cutoff, self.max_entries_per_key)
        return table[key], degraded

    def observe(self, record: dict[str, Any]) -> tuple[dict[str, float], bool, bool]:
        """Return (window features, warm, degraded) for record, then add it to the window."""
        src, dst = _host(record, "id.orig_h"), _host(record, "id.resp_h")
        port = to_int(record["id.resp_p"])
        end = to_float(record["ts"]) + safe_non_negative(to_float(record.get("duration")))
        failed = int(is_failed(record))
        bwd_payload = safe_non_negative(to_float(record.get("resp_bytes")))
        if self._first_end is None:
            self._first_end = end
        self._watermark = max(self._watermark, end)
        cutoff = self._watermark - self.window_seconds
        warm = self._watermark - self._first_end >= self.window_seconds

        s, degraded_s = self._key("src", src, cutoff)
        d, degraded_d = self._key("dst", dst, cutoff)
        v, degraded_v = self._key("svc", (dst, port), cutoff)
        # Aggregates include the current record exactly once, even if it ended before the cutoff.
        src_conns = len(s.heap) + 1
        dst_conns = len(d.heap) + 1
        features = {
            "src_conns": float(src_conns),
            "src_distinct_dst_hosts": float(len(s.peers) + (dst not in s.peers)),
            "src_distinct_dst_ports": float(len(s.ports) + (port not in s.ports)),
            "src_same_service_conns": float(s.services[(dst, port)] + 1),
            "src_failed_frac": (s.failed + failed) / src_conns,
            "src_mean_bwd_payload": (s.bwd_payload + bwd_payload) / src_conns,
            "dst_conns": float(dst_conns),
            "dst_distinct_src_hosts": float(len(d.peers) + (src not in d.peers)),
            "dst_failed_frac": (d.failed + failed) / dst_conns,
            "svc_distinct_src_hosts": float(len(v.peers) + (src not in v.peers)),
        }
        if end >= cutoff:
            self._sequence += 1
            s.add(end, self._sequence, (dst, port, failed, bwd_payload))
            d.add(end, self._sequence, (src, port, failed, bwd_payload))
            v.add(end, self._sequence, (src, 0, failed, bwd_payload))
        return features, warm, degraded_s or degraded_d or degraded_v


class Extractor:
    """Convert conn.log records, in log-write order, into v2 flows."""

    def __init__(self, state: WindowState | None = None) -> None:
        self.state = state or WindowState()

    def process(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Return a v2 flow, or None for a tunnel carrier that is not an observation."""
        if is_tunnel_carrier(record):
            return None
        uid = record.get("uid")
        if not isinstance(uid, str) or not uid or len(uid) > 160 or any(c.isspace() for c in uid):
            raise ValueError("Invalid Zeek uid.")
        # Validate the whole record before it can change window state.
        features = connection_features(record)
        _, event_time = normalize_timestamp(to_float(record.get("ts")))
        window, warm, degraded = self.state.observe(record)
        features.update(window)
        validate_features(features)
        return {
            # Same identity as v1, so v1 and v2 observations of one connection align.
            "flow_id": f"{uid}:{event_time}",
            "event_time": event_time,
            "features": {name: float(features[name]) for name in FEATURE_ORDER},
            "window_warm": warm,
            "window_degraded": degraded,
        }
