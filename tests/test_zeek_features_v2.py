"""Contract zeek-conn-window-v2: per-connection encoding and causal window semantics."""
from __future__ import annotations

import random
import unittest

from sensor.zeek_features_v2 import (CONTRACT_ID, FEATURE_ORDER, WINDOW_FEATURES, Extractor, WindowState,
                                     connection_features)

BASE = {
    "ts": 1710200000.25, "uid": "CbXwre3xQ4example", "id.orig_h": "10.0.0.15", "id.orig_p": 52344,
    "id.resp_h": "10.0.0.25", "id.resp_p": 443, "proto": "tcp", "duration": 1.5,
    "orig_bytes": 4096, "resp_bytes": 2048, "conn_state": "SF", "missed_bytes": 0,
    "history": "ShADadFf", "orig_pkts": 12, "orig_ip_bytes": 4920, "resp_pkts": 8, "resp_ip_bytes": 2864,
}


def conn(sequence: int, **changes) -> dict:
    return {**BASE, "uid": f"C{sequence}", "ts": BASE["ts"] + sequence, "duration": 0.0, **changes}


class ConnectionFeatureTests(unittest.TestCase):
    def test_contract_has_no_constant_or_site_identity_inputs(self):
        self.assertEqual(CONTRACT_ID, "zeek-conn-window-v2")
        self.assertEqual(len(FEATURE_ORDER), len(set(FEATURE_ORDER)))
        for name in ("timestamp", "src_port", "idle_mean", "fwd_psh_flags", "init_fwd_win_byts"):
            self.assertNotIn(name, FEATURE_ORDER)
        self.assertLessEqual(len(FEATURE_ORDER), 80)  # FlowRecord's feature limit.

    def test_values_and_direction_specific_history(self):
        features = connection_features(BASE)
        self.assertEqual(features["fwd_header_bytes"], 824)
        self.assertEqual(features["bwd_header_bytes"], 816)
        self.assertEqual(features["flow_duration"], 1_500_000)
        self.assertEqual(features["fwd_mean_pkt_bytes"], 410)
        self.assertEqual(features["conn_state_SF"], 1)
        self.assertEqual(sum(features[f"conn_state_{s}"] for s in ("S0", "REJ", "OTH")), 0)
        # "ShADadFf": originator S, A, D, F; responder h, a, d, f.
        self.assertEqual((features["hist_orig_S"], features["hist_resp_s"]), (1, 0))
        self.assertEqual((features["hist_orig_H"], features["hist_resp_h"]), (0, 1))
        self.assertEqual((features["hist_orig_F"], features["hist_resp_f"]), (1, 1))

    def test_missing_state_is_all_zero_but_unknown_state_is_rejected(self):
        features = connection_features({**BASE, "conn_state": "-"})
        self.assertFalse(any(value for name, value in features.items() if name.startswith("conn_state_")))
        with self.assertRaisesRegex(ValueError, "Unknown Zeek conn_state"):
            connection_features({**BASE, "conn_state": "XX"})

    def test_payload_larger_than_ip_bytes_clamps_header(self):
        features = connection_features({**BASE, "orig_bytes": 9000, "missed_bytes": 5000})
        self.assertEqual(features["fwd_header_bytes"], 0)
        self.assertEqual(features["missed_bytes"], 5000)


class WindowTests(unittest.TestCase):
    def test_flow_shape_and_v1_identity(self):
        flow = Extractor().process(BASE)
        self.assertEqual(list(flow["features"]), list(FEATURE_ORDER))
        self.assertEqual(flow["flow_id"], "CbXwre3xQ4example:2024-03-11T23:33:20.250000Z")
        self.assertEqual(flow["features"]["src_conns"], 1)
        self.assertFalse(flow["window_warm"])
        self.assertFalse(flow["window_degraded"])

    def test_brute_force_shape_counts_same_service_and_failures(self):
        extractor = Extractor()
        for i in range(10):
            flow = extractor.process(conn(i, conn_state="REJ" if i % 2 else "SF"))
        features = flow["features"]
        self.assertEqual(features["src_conns"], 10)
        self.assertEqual(features["src_same_service_conns"], 10)
        self.assertEqual(features["src_distinct_dst_ports"], 1)
        self.assertEqual(features["src_failed_frac"], 0.5)

    def test_reset_after_payload_is_not_a_failed_connection(self):
        extractor = Extractor()
        long_session = extractor.process(conn(0, conn_state="RSTO"))
        refused = extractor.process(conn(1, conn_state="RSTO", resp_bytes=0, **{"id.orig_h": "192.0.2.9"}))
        self.assertEqual(long_session["features"]["src_failed_frac"], 0)
        self.assertEqual(refused["features"]["src_failed_frac"], 1)

    def test_scan_and_distributed_shapes(self):
        scan = Extractor()
        for port in range(1, 21):
            flow = scan.process(conn(port, **{"id.resp_p": port, "conn_state": "S0"}))
        self.assertEqual(flow["features"]["src_distinct_dst_ports"], 20)
        self.assertEqual(flow["features"]["src_failed_frac"], 1)
        flood = Extractor()
        for i in range(15):
            flow = flood.process(conn(i, **{"id.orig_h": f"192.0.2.{i + 1}"}))
        self.assertEqual(flow["features"]["dst_distinct_src_hosts"], 15)
        self.assertEqual(flow["features"]["svc_distinct_src_hosts"], 15)
        self.assertEqual(flow["features"]["src_conns"], 1)

    def test_old_connections_leave_the_window_and_warmup_is_reported(self):
        extractor = Extractor()
        first = extractor.process(conn(0))
        second = extractor.process(conn(30))
        third = extractor.process(conn(61))
        self.assertEqual((first["features"]["src_conns"], second["features"]["src_conns"]), (1, 2))
        self.assertEqual(third["features"]["src_conns"], 2)  # conn(0) ended 61 s before the watermark.
        self.assertEqual([f["window_warm"] for f in (first, second, third)], [False, False, True])

    def test_late_logged_old_connection_counts_itself_once_and_is_not_retained(self):
        extractor = Extractor()
        extractor.process(conn(100))
        stale = extractor.process(conn(1))
        self.assertEqual(stale["features"]["src_conns"], 2)
        self.assertEqual(extractor.process(conn(101))["features"]["src_conns"], 2)

    def test_tunnel_carriers_and_invalid_records_do_not_change_state(self):
        extractor = Extractor()
        self.assertIsNone(extractor.process(conn(0, proto="udp", **{"id.resp_p": 8472})))
        self.assertIsNone(extractor.process(conn(1, proto="udp", **{"id.resp_p": 4789})))
        with self.assertRaises(ValueError):
            extractor.process(conn(2, **{"id.resp_h": "not-an-address"}))
        with self.assertRaises(ValueError):
            extractor.process(conn(3, conn_state="XX"))
        self.assertEqual(extractor.process(conn(4))["features"]["src_conns"], 1)

    def test_key_capacity_reports_degraded_windows(self):
        extractor = Extractor(WindowState(max_keys=2))
        for i in range(3):
            flow = extractor.process(conn(i, **{"id.orig_h": f"192.0.2.{i + 1}", "id.resp_h": f"198.51.100.{i + 1}"}))
        self.assertTrue(flow["window_degraded"])
        capped = Extractor(WindowState(max_entries_per_key=3))
        flags = [capped.process(conn(i))["window_degraded"] for i in range(5)]
        self.assertEqual(flags, [False, False, False, True, True])

    def test_incremental_counts_match_brute_force_recomputation(self):
        rng = random.Random(20261029)
        hosts = [f"10.0.0.{i}" for i in range(1, 6)]
        written, extractor = [], Extractor()
        for i in range(400):
            # Out-of-order end times exercise the watermark, as Zeek inactivity timeouts do.
            record = conn(i, ts=BASE["ts"] + i * 0.5 - rng.uniform(0, 20), duration=rng.uniform(0, 5),
                          conn_state=rng.choice(["SF", "S0", "REJ", "RSTO"]), resp_bytes=rng.randrange(0, 500),
                          **{"id.orig_h": rng.choice(hosts), "id.resp_h": rng.choice(hosts),
                             "id.resp_p": rng.choice([22, 80, 443])})
            flow = extractor.process(record)
            end = lambda r: r["ts"] + r["duration"]
            watermark = max(end(r) for r in [*written, record])
            live = [r for r in written if end(r) >= watermark - 60] + [record]
            src = [r for r in live if r["id.orig_h"] == record["id.orig_h"]]
            dst = [r for r in live if r["id.resp_h"] == record["id.resp_h"]]
            # BASE has orig_bytes > 0, so an RSTO is failed only when the responder sent nothing.
            failed = lambda rows: sum(r["conn_state"] in ("S0", "REJ") or r["conn_state"] == "RSTO"
                                      and not r["resp_bytes"] for r in rows) / len(rows)
            expected = {
                "src_conns": len(src), "src_distinct_dst_hosts": len({r["id.resp_h"] for r in src}),
                "src_distinct_dst_ports": len({r["id.resp_p"] for r in src}),
                "src_same_service_conns": sum((r["id.resp_h"], r["id.resp_p"])
                                              == (record["id.resp_h"], record["id.resp_p"]) for r in src),
                "src_failed_frac": failed(src), "src_mean_bwd_payload": sum(r["resp_bytes"] for r in src) / len(src),
                "dst_conns": len(dst), "dst_distinct_src_hosts": len({r["id.orig_h"] for r in dst}),
                "dst_failed_frac": failed(dst),
                "svc_distinct_src_hosts": len({r["id.orig_h"] for r in dst if r["id.resp_p"] == record["id.resp_p"]}),
            }
            for name in WINDOW_FEATURES:
                self.assertAlmostEqual(flow["features"][name], expected[name], places=9, msg=f"{i} {name}")
            if end(record) >= watermark - 60:
                written.append(record)


if __name__ == "__main__":
    unittest.main()
