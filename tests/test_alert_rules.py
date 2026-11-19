"""Alert-side rule: lone unanswered SYNs are not alerts; scans, floods and answered connections still are."""
from __future__ import annotations

from dataclasses import replace
import unittest

from app.alert_rules import is_lone_unanswered_syn, is_routine_icmpv6
from app.config import Settings
from sensor.zeek_features_v2 import Extractor
from sensor.zeek_to_cicids import conn_record_to_flow

SYN = {"ts": 1710200000.25, "uid": "Csyn", "id.orig_h": "192.168.1.122", "id.orig_p": 49955,
       "id.resp_h": "44.226.81.87", "id.resp_p": 443, "proto": "tcp", "conn_state": "S0", "missed_bytes": 0,
       "history": "S", "orig_pkts": 1, "orig_ip_bytes": 60, "resp_pkts": 0, "resp_ip_bytes": 0}


def features(*records: dict) -> dict:
    """v2 features of the last record, after the earlier ones filled the window."""
    extractor = Extractor()
    for record in records[:-1]:
        extractor.process(record)
    return extractor.process(records[-1])["features"]


class LoneUnansweredSynTests(unittest.TestCase):
    def test_single_unanswered_syn_and_its_retries_match(self):
        self.assertTrue(is_lone_unanswered_syn(features(SYN)))
        retries = [{**SYN, "uid": f"C{i}", "ts": SYN["ts"] + 5 * i, "id.orig_p": 49955 + i, "orig_pkts": 3}
                   for i in range(3)]
        self.assertTrue(is_lone_unanswered_syn(features(*retries)))

    def test_syn_flood_and_scans_do_not_match(self):
        flood = [{**SYN, "uid": f"C{i}", "ts": SYN["ts"] + i / 100, "id.orig_p": 40000 + i} for i in range(50)]
        self.assertFalse(is_lone_unanswered_syn(features(*flood)))
        port_scan = [{**SYN, "uid": f"C{i}", "ts": SYN["ts"] + i / 10, "id.resp_p": 1 + i} for i in range(20)]
        self.assertFalse(is_lone_unanswered_syn(features(*port_scan)))
        host_sweep = [{**SYN, "uid": f"C{i}", "ts": SYN["ts"] + i / 10, "id.resp_h": f"203.0.113.{i}"}
                      for i in range(30)]
        self.assertFalse(is_lone_unanswered_syn(features(*host_sweep)))
        many_sources = [{**SYN, "uid": f"C{i}", "ts": SYN["ts"] + i / 10, "id.orig_h": f"198.51.100.{i}"}
                        for i in range(5)]
        self.assertFalse(is_lone_unanswered_syn(features(*many_sources)))

    def test_answered_or_reset_connections_do_not_match(self):
        for change in ({"conn_state": "REJ", "history": "Sr", "resp_pkts": 1, "resp_ip_bytes": 40},
                       {"conn_state": "RSTO", "history": "ShR", "resp_pkts": 1, "resp_ip_bytes": 44},
                       {"conn_state": "SF", "history": "ShADadFf", "resp_pkts": 6, "resp_ip_bytes": 900},
                       {"proto": "udp", "history": "D"}):
            with self.subTest(change=change):
                self.assertFalse(is_lone_unanswered_syn(features({**SYN, **change})))

    def test_vectors_it_cannot_judge_never_match(self):
        vector = features(SYN)
        del vector["src_same_service_conns"]
        self.assertFalse(is_lone_unanswered_syn(vector))

    def test_setting_must_be_true_or_false(self):
        with self.assertRaisesRegex(ValueError, "NIDS_SUPPRESS_LONE_UNANSWERED_SYN"):
            replace(Settings(), suppress_lone_unanswered_syn="yes")

    def test_undecided_and_botnet_settings_are_validated(self):
        with self.assertRaisesRegex(ValueError, "NIDS_V2_UNDECIDED"):
            replace(Settings(), v2_undecided="drop")
        with self.assertRaisesRegex(ValueError, "NIDS_BOTNET_ALERTS"):
            replace(Settings(), botnet_alerts="off")
        self.assertEqual((Settings().v2_undecided, Settings().botnet_alerts), ("unvalidated", "unvalidated"))


# A neighbor solicitation to a solicited-node multicast address, as the live sensor logs it (type in id.orig_p).
NS = {"ts": 1794894552.5, "uid": "Cns", "id.orig_h": "2600:1700:38c0:a2e0::1", "id.orig_p": 135,
      "id.resp_h": "ff02::1:ff00:577", "id.resp_p": 136, "proto": "icmp", "conn_state": "OTH", "missed_bytes": 0,
      "history": "", "orig_pkts": 1, "orig_ip_bytes": 72, "resp_pkts": 0, "resp_ip_bytes": 0, "ip_proto": 58}


def icmpv6(*records: dict) -> tuple[dict, dict]:
    """(v1 features, v2 features) of the last record, after the earlier ones filled the window."""
    return conn_record_to_flow(records[-1])["features"], features(*records)


class RoutineIcmpv6Tests(unittest.TestCase):
    def test_routine_housekeeping_matches(self):
        for change in ({},  # neighbor solicitation
                       {"id.orig_p": 136, "id.resp_p": 135, "id.resp_h": "fe80::2ecf:67ff:feae:7107"},
                       {"id.orig_p": 143, "id.resp_p": 0, "id.resp_h": "ff02::16"},  # MLDv2 report
                       {"id.orig_p": 133, "id.resp_p": 134, "id.resp_h": "ff02::2"},  # router solicitation
                       {"id.orig_p": 128, "id.resp_p": 129, "resp_pkts": 1, "resp_ip_bytes": 104, "duration": 0.01},
                       {"id.orig_p": 1, "id.resp_p": 4}):  # port unreachable
            with self.subTest(change=change):
                self.assertTrue(is_routine_icmpv6(*icmpv6({**NS, **change})))
        # A long-lived MLD report flow like the largest live one: 594 packets over 29 minutes.
        mld = {**NS, "id.orig_p": 143, "id.resp_p": 0, "id.resp_h": "ff02::16", "orig_pkts": 594,
               "orig_ip_bytes": 594 * 76, "duration": 1757.8}
        self.assertTrue(is_routine_icmpv6(*icmpv6(mld)))

    def test_router_messages_are_never_cleared(self):
        for icmp_type in (134, 137):  # router advertisement, redirect
            with self.subTest(icmp_type=icmp_type):
                self.assertFalse(is_routine_icmpv6(*icmpv6({**NS, "id.orig_p": icmp_type, "id.resp_p": 0})))

    def test_floods_and_sweeps_do_not_match(self):
        ns_flood = [{**NS, "uid": f"C{i}", "ts": NS["ts"] + i / 100, "id.resp_h": f"ff02::1:ff00:{i:x}"}
                    for i in range(250)]
        self.assertFalse(is_routine_icmpv6(*icmpv6(*ns_flood)))
        ping_sweep = [{**NS, "uid": f"C{i}", "ts": NS["ts"] + i / 10, "id.orig_p": 128, "id.resp_p": 129,
                       "id.resp_h": f"2600:1700:38c0:a2e0::{i:x}"} for i in range(160)]
        self.assertFalse(is_routine_icmpv6(*icmpv6(*ping_sweep)))
        many_sources = [{**NS, "uid": f"C{i}", "ts": NS["ts"] + i / 10, "id.orig_h": f"fe80::{i:x}"}
                        for i in range(40)]
        self.assertFalse(is_routine_icmpv6(*icmpv6(*many_sources)))
        ping_flood = {**NS, "id.orig_p": 128, "id.resp_p": 129, "orig_pkts": 900, "orig_ip_bytes": 900 * 104,
                      "resp_pkts": 900, "resp_ip_bytes": 900 * 104, "duration": 3.0}
        self.assertFalse(is_routine_icmpv6(*icmpv6(ping_flood)))
        fast = {**ping_flood, "orig_pkts": 40, "resp_pkts": 40, "duration": 1.0}  # 80 packets in 1 s
        self.assertFalse(is_routine_icmpv6(*icmpv6(fast)))

    def test_flows_it_cannot_judge_never_match(self):
        v1, v2 = icmpv6(NS)
        self.assertFalse(is_routine_icmpv6({k: v for k, v in v1.items() if k != "src_port"}, v2))
        self.assertFalse(is_routine_icmpv6(v1, {k: v for k, v in v2.items() if k != "src_conns"}))
        icmp4 = {**NS, "id.orig_h": "192.168.1.1", "id.resp_h": "192.168.1.122", "id.orig_p": 8, "id.resp_p": 0,
                 "ip_proto": 1}
        self.assertFalse(is_routine_icmpv6(*icmpv6(icmp4)))

    def test_icmpv6_setting_must_be_true_or_false(self):
        with self.assertRaisesRegex(ValueError, "NIDS_VALIDATE_ROUTINE_ICMPV6"):
            replace(Settings(), validate_routine_icmpv6="maybe")
        self.assertEqual(Settings().validate_routine_icmpv6, "true")


if __name__ == "__main__":
    unittest.main()
