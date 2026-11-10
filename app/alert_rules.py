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
