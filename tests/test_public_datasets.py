from copy import deepcopy
import csv
from datetime import datetime, UTC
import io
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
import zipfile

from tools.public_labels import (cic_class, cic_index, conn_key, cse_metadata_matches, infer_cic_clock, iot_class,
                                 make_index, match_cic, match_iot, read_iot_labels)
from tools.subset_public_capture import capture_blocks, packet_key, subset
from tools.label_scenarios import failed_authentication_evidence, scenario_match


def ethernet(src="192.0.2.1", sport=1234, dst="192.0.2.2", dport=22, fragment=0):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 24, 1, fragment, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + struct.pack("!HH", sport, dport)


def block(kind, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def pcapng(packets, endian="<", resolution=6):
    header = block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1), endian)
    options = struct.pack(endian + "HH", 9, 1) + bytes([resolution]) + b"\x00" * 3 + b"\x00" * 4
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + options, endian)
    raw = header + interface
    for tick, packet in packets:
        raw += block(6, struct.pack(endian + "IIIII", 0, tick >> 32, tick & 0xffffffff, len(packet), len(packet)) + packet, endian)
    return raw


class PublicDatasetTests(unittest.TestCase):
    def test_iot_mixed_separators_and_exact_behavior_mapping(self):
        header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\ttunnel_parents   label   detailed-label\n"
        row = "1533042911.474174\tu1\t192.0.2.1\t1234\t192.0.2.2\t22\ttcp\t1.0\t(empty)   Malicious   C&C\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.txt"
            path.write_text(header + row)
            result = list(read_iot_labels(path))[0]
        self.assertEqual(result["label"], "BOTNET")
        self.assertEqual(result["source_detail"], "C&C")
        self.assertEqual(iot_class("Malicious", "DDoS"), "DOS_DDOS")
        self.assertIsNone(iot_class("Malicious", "unknown-malware-family"))
        self.assertIsNone(iot_class("Benign", "C&C"))

    def test_label_join_uses_tuple_and_time_not_uid_and_rejects_conflicts(self):
        conn = {"id.orig_h": "192.0.2.1", "id.orig_p": 1234, "id.resp_h": "192.0.2.2", "id.resp_p": 22,
                "proto": "tcp", "ts": 1600000000.123456, "duration": 5, "uid": "new-zeek-uid"}
        row = {"key": conn_key(conn), "ts": conn["ts"], "duration": 1, "label": "BOTNET",
               "source_detail": "C&C", "evidence": {"source_uid": "old-zeek-uid", "line": 1}}
        result, reason = match_iot(conn, make_index([row]))
        self.assertIsNone(reason)
        self.assertEqual(result["label"], "BOTNET")
        reversed_conn = {**conn, "id.orig_h": conn["id.resp_h"], "id.orig_p": conn["id.resp_p"],
                         "id.resp_h": conn["id.orig_h"], "id.resp_p": conn["id.orig_p"]}
        self.assertEqual(match_iot(reversed_conn, make_index([row]))[0]["label"], "BOTNET")
        conflict = {**deepcopy(row), "ts": conn["ts"] + 2, "label": "BENIGN", "source_detail": "-"}
        self.assertEqual(match_iot(conn, make_index([row, conflict]))[1], "ambiguous_or_unmapped_source_labels")
        self.assertIsNone(match_iot({**conn, "ts": conn["ts"] + 0.1}, make_index([row]))[0])

    def test_bruteforce_is_distinct_from_web_exploitation(self):
        for label in ("FTP-Patator", "SSH-Patator", "Web Attack – Brute Force"):
            self.assertEqual(cic_class(label), "BRUTE_FORCE")
        for label in ("Web Attack – XSS", "Web Attack – Sql Injection", "Infiltration"):
            self.assertEqual(cic_class(label), "OTHER_ATTACK")
        self.assertIsNone(cic_class("UNKNOWN"))

    def test_pcapng_endianness_and_timestamp_resolution(self):
        for endian in ("<", ">"):
            for resolution in (6, 9, 0x80 | 10):
                with self.subTest(endian=endian, resolution=resolution):
                    unit = 2**10 if resolution & 0x80 else 10**resolution
                    raw = pcapng([(1600000000 * unit + unit // 2, ethernet())], endian, resolution)
                    events = list(capture_blocks(io.BytesIO(raw)))
                    self.assertEqual(b"".join(event[0] for event in events), raw)
                    packet = next(event for event in events if event[1] is not None)
                    self.assertAlmostEqual(packet[2], 1600000000.5)
                    self.assertEqual(packet[1], ethernet())

    def test_packet_tuple_is_bidirectional_and_fragments_are_context(self):
        self.assertEqual(packet_key(ethernet(), 1), packet_key(ethernet("192.0.2.2", 22, "192.0.2.1", 1234), 1))
        self.assertIsNone(packet_key(ethernet(fragment=0x2000), 1))

    def test_subset_keeps_all_selected_tuple_packets_and_skips_blank_csv_rows(self):
        packets = [(1600000000000000, ethernet()), (1600000001000000, ethernet(sport=9999)),
                   (1600000100000000, ethernet("192.0.2.2", 22, "192.0.2.1", 1234))]
        original = pcapng(packets)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            capture = base / "original.pcap"
            capture.write_bytes(original)
            labels = base / "labels.zip"
            header = "Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Label\n"
            csv = header + "192.0.2.1,1234,192.0.2.2,22,6,13/9/2020 12:26,1000000,SSH-Patator\n" + ",,,,,,,\n"
            with zipfile.ZipFile(labels, "w") as archive:
                archive.writestr("labels.csv", csv)
            report = subset(capture, labels, ["labels.csv"], base / "subset", per_label=1)
            self.assertEqual(report["empty_csv_rows"], 1)
            self.assertEqual(report["subset_packets"], 2)
            selected_packets = [event for event in capture_blocks(io.BytesIO((base / "subset/subset.pcap").read_bytes())) if event[1] is not None]
            self.assertEqual([event[1] for event in selected_packets], [packets[0][1], packets[2][1]])
            self.assertEqual(capture.read_bytes(), original)
            self.assertEqual(report["source_capture_bytes"], len(original))

    def test_incomplete_pcapng_fails_instead_of_fabricating_packet_data(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            list(capture_blocks(io.BytesIO(pcapng([(1600000000000000, ethernet())])[:-1])))

    def test_cic_clock_is_established_by_unique_tuples_and_resolves_12_hour_time(self):
        connections, labels = [], []
        morning = 1499158800  # Synthetic naive local-clock origin; only relative alignment matters here.
        for i in range(30):
            base = morning + i * 60
            conn = {"id.orig_h": "192.0.2.1", "id.orig_p": 1000 + i, "id.resp_h": "192.0.2.2", "id.resp_p": 22,
                    "proto": "tcp", "ts": base + (3 if i < 15 else 15) * 3600 + 20, "duration": 1}
            label = {"key": conn_key(conn), "local_minute_as_utc": base, "duration": 1, "label": "BRUTE_FORCE",
                     "source_label": "SSH-Patator", "evidence": {"line": i}}
            connections.append(conn)
            labels.append(label)
        clock = infer_cic_clock(connections, labels)
        self.assertEqual(clock["utc_offset_hours_modulo_12"], 3)
        self.assertEqual(clock["agreement"], 1)
        self.assertEqual(clock["observed_hour_offsets"], {"3": 15, "15": 15})
        result, reason = match_cic(connections[0], cic_index(labels, clock, connections))
        self.assertIsNone(reason)
        self.assertEqual(result["label"], "BRUTE_FORCE")
        self.assertEqual(match_cic(connections[-1], cic_index(labels, clock, connections))[0]["label"], "BRUTE_FORCE")
        with self.assertRaisesRegex(ValueError, "insufficient"):
            infer_cic_clock(connections[:2], labels[:2])

    def test_cic_conflicting_same_minute_labels_are_not_resolved_using_predictions(self):
        conn = {"id.orig_h": "192.0.2.1", "id.orig_p": 1000, "id.resp_h": "192.0.2.2", "id.resp_p": 80,
                "proto": "tcp", "ts": 1600000020, "duration": 1}
        row = {"key": conn_key(conn), "ts": 1600000000, "duration": 1, "label": "BENIGN", "source_label": "BENIGN", "evidence": {"line": 1}}
        conflict = {**row, "label": "OTHER_ATTACK", "source_label": "Web Attack – XSS", "evidence": {"line": 2}}
        self.assertEqual(match_cic(conn, make_index([row, conflict]))[1], "ambiguous_or_unmapped_source_labels")

    def test_cse_requires_unique_metadata_and_aligned_time_and_excludes_duplicates(self):
        source_rows, connections = [], []
        origin = datetime(2018, 2, 15, 8, 0, tzinfo=UTC).timestamp()
        for i in range(30):
            connections.append({"proto": "tcp", "id.resp_p": 80, "orig_pkts": 2 + i, "resp_pkts": 1,
                                "duration": (1000000 + i) / 1000000, "ts": origin + i + 4 * 3600 + 0.25,
                                "uid": f"synthetic-{i}"})
            source_rows.append({"Protocol": 6, "Dst Port": 80, "Tot Fwd Pkts": 2 + i, "Tot Bwd Pkts": 1,
                                "Flow Duration": 1000000 + i,
                                "Timestamp": datetime.fromtimestamp(origin + i, UTC).strftime("%d/%m/%Y %H:%M:%S"),
                                "Label": "DoS attacks-Slowloris"})
        # Identical source signatures are rejected even when their labels agree.
        source_rows.append(dict(source_rows[0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.csv"
            with path.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(source_rows[0]))
                writer.writeheader()
                writer.writerows(source_rows)
            lookup, clock = cse_metadata_matches(connections, path)
            self.assertEqual(clock["utc_offset_hours_modulo_12"], 4)
            self.assertEqual(clock["agreement"], 1)
            self.assertEqual(len(lookup), 29)
            self.assertNotIn("synthetic-0", lookup)
            self.assertTrue(all(row["label"] == "DOS_DDOS" for row in lookup.values()))
            self.assertNotIn("synthetic-1", cse_metadata_matches([
                {**conn, "ts": conn["ts"] + (10 if conn["uid"] == "synthetic-1" else 0)}
                for conn in connections], path)[0])

    def test_campaign_requires_exact_roles_service_and_complete_time_containment(self):
        rule = {"documentation": "https://example.test/published-schedule", "scenarios": [
            {"name": "synthetic campaign", "label": "BRUTE_FORCE", "attackers": ["192.0.2.1"],
             "victim": "192.0.2.2", "protocol": 6, "destination_port": 22,
             "start_utc": "2018-02-14T18:01:00Z", "end_utc": "2018-02-14T19:31:00Z"}]}
        start = datetime(2018, 2, 14, 18, 1, tzinfo=UTC).timestamp()
        conn = {"id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2", "id.resp_p": 22,
                "proto": "tcp", "ts": start + 1, "duration": 1}
        self.assertEqual(scenario_match(conn, rule)["label"], "BRUTE_FORCE")
        for changed in ({"id.orig_h": "192.0.2.3"}, {"id.resp_p": 80}, {"ts": start - 1},
                        {"duration": 91 * 60}, {"proto": "udp"}):
            self.assertIsNone(scenario_match({**conn, **changed}, rule))

    def test_failed_authentication_evidence_excludes_success_unknown_and_refused_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "ssh.log").write_text("\n".join(json.dumps(row) for row in [
                {"uid": "failed", "auth_success": False, "auth_attempts": 2},
                {"uid": "successful", "auth_success": True, "auth_attempts": 1},
                {"uid": "unknown"}, {"uid": "unobserved", "auth_success": False, "auth_attempts": 0}]))
            (p / "ftp.log").write_text("\n".join(json.dumps(row) for row in [
                {"uid": "ftp-failed", "command": "PASS", "reply_code": 530},
                {"uid": "ftp-success", "command": "PASS", "reply_code": 230}]))
            self.assertEqual(set(failed_authentication_evidence(p)), {"failed", "ftp-failed"})


if __name__ == "__main__":
    unittest.main()
