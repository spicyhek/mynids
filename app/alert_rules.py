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


# Lone refused or aborted attempt: a TCP connection that carried no payload either way and ended within 3 packets,
# either refused by the responder (conn_state REJ, history "Sr") or reset by the originator right after the
# handshake (RSTO, history "ShR"). Like a lone unanswered SYN it is one failed attempt, not an attack, unless the
# source is scanning or flooding, which the window checks catch. Live false positives it clears (2026-11-25):
# OTHER_ATTACK on the control plane's DNS retries over TCP that the router refuses (11-15 same-service
# connections, because UDP queries to the same resolver count too), and DOS_DDOS on a Tailscale DERP probe the
# client cut short (21 same-service connections, 10 destination hosts and 5 ports from the busy control plane).
#
# The thresholds sit above those cases and below scans and floods. In the training data a homelab SYN flood source
# reaches a median of 752 same-service connections a window and a homelab port scan a median of 66 ports; only the
# first few attempts of each burst fall under the limits, and the rest still alert.
REFUSED_RULE_ID = "refused-attempt-rule"
REFUSED_MAX_PKTS = 3
REFUSED_MAX_SAME_SERVICE_CONNS = 30
REFUSED_MAX_DISTINCT_DST_HOSTS = 20
REFUSED_MAX_DISTINCT_DST_PORTS = 5
REFUSED_MAX_DST_DISTINCT_SRC_HOSTS = 2
_REFUSED_ALLOWED_HISTORY = frozenset({"hist_orig_S", "hist_orig_R", "hist_resp_h", "hist_resp_r"})
_ALL_HISTORY_FEATURES = (
    *(f"hist_orig_{letter}" for letter in ("S", "H", "A", "D", "F", "R", "C", "G", "T", "W", "I", "Q", "flip")),
    *(f"hist_resp_{letter}" for letter in "shadfrcgtwiq"),
)


def is_lone_refused_attempt(features: Mapping[str, float]) -> bool:
    """True for a zeek-conn-window-v2 vector of a lone refused or aborted TCP attempt (see the comment above)."""
    try:
        if features["protocol"] != 6 or features["fwd_payload_bytes"] or features["bwd_payload_bytes"]:
            return False
        if features["tot_fwd_pkts"] + features["tot_bwd_pkts"] > REFUSED_MAX_PKTS or features["hist_orig_S"] < 1:
            return False
        refused = features["conn_state_REJ"] == 1 and features["hist_resp_r"] >= 1
        aborted = (features["conn_state_RSTO"] == 1 and features["hist_resp_h"] >= 1
                   and features["hist_orig_R"] >= 1)
        if not (refused or aborted):
            return False
        if any(features[name] for name in _ALL_HISTORY_FEATURES if name not in _REFUSED_ALLOWED_HISTORY):
            return False
        return (features["src_same_service_conns"] <= REFUSED_MAX_SAME_SERVICE_CONNS
                and features["src_distinct_dst_hosts"] <= REFUSED_MAX_DISTINCT_DST_HOSTS
                and features["src_distinct_dst_ports"] <= REFUSED_MAX_DISTINCT_DST_PORTS
                and features["dst_distinct_src_hosts"] <= REFUSED_MAX_DST_DISTINCT_SRC_HOSTS)
    except (KeyError, TypeError):
        return False  # Not a v2 vector; never suppress what the rule cannot judge.


# Authenticated SSH: the sensor flags a connection whose SSH login Zeek's analyzer saw succeed
# (sensor/ssh_auth.py). The model cannot see login results, so bursts of the operator's own key-authenticated
# sessions to the control plane look like password guessing: 6 sessions in 65 s raised BRUTE_FORCE on
# 2026-11-25, and on live-regression-v1 10 of the 14 alerts left after the other rules were such sessions
# (BRUTE_FORCE, and DOS_DDOS when Windows ssh ended them with a reset). Zeek set auth_success on none of the
# ~96,000 guessing sessions in the training data, and on 139 of 140 live sessions (the 140th was a real failed
# login, which still alerts).
#
# Accepted blind spot: a successful login is never an alert by itself, including the one that ends a guessing
# run; the failed guesses before it still alert. Logins with stolen credentials were never detectable here.
SSH_AUTH_RULE_ID = "ssh-auth-rule"


def is_authenticated_ssh(flow: Mapping) -> bool:
    """True for a flow the sensor marked as a successful SSH login (see the comment above)."""
    return flow.get("ssh_auth_success") is True


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
