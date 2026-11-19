"""Alert-side rules applied to v2 operational labels after the model runs.

Lone unanswered SYN: a single TCP connection attempt that got no reply at all (Zeek conn_state S0, history
only "S"), from a source that is neither scanning nor flooding in the 60 s window. baseline-v2 labels these
BOTNET because its BOTNET training rows are dominated by malware calling dead command servers, which look the
same; on the live network they are retries to an unreachable outside service (an NTP server that is down, a
Grafana Cloud or Cloudflare blip). Dropping those training rows only moved the pattern to other attack classes
(candidate-v6, 2026-11-10), so the decision is made here instead.

Accepted blind spot: a compromised host calling a dead command server once in a while is not alerted. The model
detected that only for the botnet families it was trained on.

Thresholds sit far from real scans and floods. On the training and validation data no homelab drill matches,
and 5 of 15,393 CIC-IDS2018 DoS rows do. The worst live benign case reached 6 same-service connections,
10 destination hosts and 4 destination ports in its window; a SYN flood source makes ~165 same-service
connections and a scanner thousands of destination hosts.
"""
from __future__ import annotations

from typing import Mapping

LONE_SYN_RULE_ID = "lone-syn-rule"

# BOTNET predictions are recorded but not counted as attacks. BOTNET detection is family-specific (every held-out
# botnet group scored 0), the homelab has no botnet ground truth, and every BOTNET alert so far was benign: lone
# unanswered SYNs live, and regular small HTTP GETs to :8080 in the 2026-11-10 held-out test (30 of 46 benign false
# alarms), which look like the Ares C2 polls in its training data.
BOTNET_REASON = "botnet_detection_not_validated"
# Why v2 could not judge a flow in v2 mode (stored as unvalidated rather than taking the Keras fallback label).
NO_V2_FEATURES_REASON = "no_v2_features"
V2_UNAVAILABLE_REASON = "v2_unavailable"
MAX_SAME_SERVICE_CONNS = 10
MAX_DISTINCT_DST_HOSTS = 20
MAX_DISTINCT_DST_PORTS = 5
MAX_DST_DISTINCT_SRC_HOSTS = 2

_HISTORY_FEATURES_OTHER_THAN_SYN = (
    *(f"hist_orig_{letter}" for letter in ("H", "A", "D", "F", "R", "C", "G", "T", "W", "I", "Q", "flip")),
    *(f"hist_resp_{letter}" for letter in "shadfrcgtwiq"),
)


def is_lone_unanswered_syn(features: Mapping[str, float]) -> bool:
    """True for a zeek-conn-window-v2 feature vector of a lone unanswered SYN (see module docstring)."""
    try:
        return (features["protocol"] == 6 and features["conn_state_S0"] == 1 and features["tot_bwd_pkts"] == 0
                and features["hist_orig_S"] >= 1
                and all(features[name] == 0 for name in _HISTORY_FEATURES_OTHER_THAN_SYN)
                and features["src_same_service_conns"] <= MAX_SAME_SERVICE_CONNS
                and features["src_distinct_dst_hosts"] <= MAX_DISTINCT_DST_HOSTS
                and features["src_distinct_dst_ports"] <= MAX_DISTINCT_DST_PORTS
                and features["dst_distinct_src_hosts"] <= MAX_DST_DISTINCT_SRC_HOSTS)
    except KeyError:
        return False  # Not a v2 vector; never suppress what the rule cannot judge.


# Routine ICMPv6: IPv6 neighbor discovery, multicast listener reports, pings and error messages are ~10 % of live
# flows (2026-11-16..17: 40,351 of 373,509) and were all stored unvalidated, because neither model was trained on
# ICMPv6 attacks: baseline-v2's ICMPv6 training rows are 8,895 benign homelab flows, so its label there is always
# BENIGN and proves nothing. This rule validates them instead, on message type and volume.
#
# Router Advertisements (134) and Redirects (137) are never cleared: a rogue router looks routine by volume, and
# the app never sees addresses, so only an allowlist at the sensor could tell the real router apart. Floods and
# sweeps fail the volume checks. Live maxima over the 48 h: src_conns 67, src_distinct_dst_hosts 63,
# src_same_service_conns 1, dst_distinct_src_hosts 10, 594 packets in one flow (an MLD report over 29 min). Each
# limit has about 3x headroom; an ND flood or an IPv6 ping sweep makes hundreds to thousands per source a minute.
ICMPV6_RULE_ID = "icmpv6-rule"
ROUTINE_ICMPV6_TYPES = frozenset({
    1, 2, 3, 4,          # destination unreachable, packet too big, time exceeded, parameter problem
    128, 129,            # echo request, echo reply
    130, 131, 132, 143,  # multicast listener query, report, done; MLDv2 report
    133, 135, 136,       # router solicitation, neighbor solicitation, neighbor advertisement
})
ICMPV6_MAX_SRC_CONNS = 200
ICMPV6_MAX_DISTINCT_DST_HOSTS = 150
ICMPV6_MAX_SAME_SERVICE_CONNS = 10
ICMPV6_MAX_DST_DISTINCT_SRC_HOSTS = 30
ICMPV6_MAX_FLOW_PKTS = 1000
ICMPV6_MAX_PKTS_PER_S = 10.0  # Only for flows of ICMPV6_RATE_MIN_PKTS or more; tiny flows have meaningless rates.
ICMPV6_RATE_MIN_PKTS = 20


def is_routine_icmpv6(features: Mapping[str, float], features_v2: Mapping[str, float]) -> bool:
    """True for an ICMPv6 flow of a routine message type at routine volume (see the comment above).

    The message type is the v1 `src_port` (Zeek puts the ICMP type in id.orig_p); v2's `dst_port` is only the
    counterpart type or code. The volume checks use v2's 60 s window for the sending host.
    """
    try:
        if features_v2["protocol"] != 58 or int(features["src_port"]) not in ROUTINE_ICMPV6_TYPES:
            return False
        packets = features_v2["tot_fwd_pkts"] + features_v2["tot_bwd_pkts"]
        seconds = features_v2["flow_duration"] / 1_000_000.0
        if packets > ICMPV6_MAX_FLOW_PKTS or (
                packets >= ICMPV6_RATE_MIN_PKTS and (seconds <= 0 or packets / seconds > ICMPV6_MAX_PKTS_PER_S)):
            return False
        return (features_v2["src_conns"] <= ICMPV6_MAX_SRC_CONNS
                and features_v2["src_distinct_dst_hosts"] <= ICMPV6_MAX_DISTINCT_DST_HOSTS
                and features_v2["src_same_service_conns"] <= ICMPV6_MAX_SAME_SERVICE_CONNS
                and features_v2["dst_distinct_src_hosts"] <= ICMPV6_MAX_DST_DISTINCT_SRC_HOSTS)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False  # Never clear what the rule cannot judge.
