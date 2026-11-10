"""Alert-side rule: lone unanswered SYNs are not alerts; scans, floods and answered connections still are."""
from __future__ import annotations

from dataclasses import replace
import unittest

from app.alert_rules import is_lone_unanswered_syn
from app.config import Settings
from sensor.zeek_features_v2 import Extractor

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


if __name__ == "__main__":
    unittest.main()
