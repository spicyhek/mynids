"""Evidence integrity and failure handling; fixtures contain synthetic packets only."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.capture_session import (ACTIVE, activity_state, append_event, audit_pcap,
                                   begin_activity, capture, capture_statistics, digest, end_activity,
                                   metadata, packet_files, read_events, run_activity,
                                   seal_session, tcpdump_command, verify_session, write_json)


class CaptureSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.session = Path(self.temporary.name)
        write_json(self.session / "capture.json", {"session_id": "synthetic-only", "status": "capturing",
                                                  "purpose": "train", "quality_flags": [], "pcap_files": []})
        append_event(self.session, {"event": "session_created"})

    def activity(self, **changes):
        return begin_activity(self.session, name="synthetic-workload", source="192.0.2.1",
                              destination="192.0.2.2", protocol="tcp", port=22, **changes)

    def finish_capture(self):
        info = metadata(self.session)
        info["status"] = "finished"
        write_json(self.session / "capture.json", info)

    def pcap(self, name="traffic.pcap", endian="<", nano=False, records=None):
        magic = {(False, "<"): b"\xd4\xc3\xb2\xa1", (False, ">"): b"\xa1\xb2\xc3\xd4",
                 (True, "<"): b"\x4d\x3c\xb2\xa1", (True, ">"): b"\xa1\xb2\x3c\x4d"}[(nano, endian)]
        content = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 262144, 1)
        for payload, original in records or [(b"synthetic-packet", 16)]:
            content += struct.pack(endian + "IIII", 1700000000, 100, len(payload), original) + payload
        path = self.session / name
        path.write_bytes(content)
        return path

    def test_tcpdump_retains_packet_bytes_without_ring_overwrite_or_filter(self):
        command = tcpdump_command("/usr/bin/tcpdump", "eth0", self.session, "operator")
        self.assertEqual(command[command.index("-s") + 1], "0")
        self.assertIn("-U", command)
        self.assertIn("-C", command)
        self.assertNotIn("-W", command)
        self.assertNotIn("-c", command)
        self.assertEqual(command[-2:], ["-Z", "operator"])

    def test_activity_has_utc_endpoints_and_no_automatic_truth_label(self):
        started = self.activity(note="operator evidence, not truth")
        self.assertTrue(started["recorded_at_utc"].endswith("+00:00"))
        self.assertEqual(started["destination_port"], 22)
        self.assertEqual(started["label_status"], "unreviewed")
        self.assertNotIn("label", started)
        end_activity(self.session, started["activity_id"], "completed")
        self.assertEqual(len(activity_state(read_events(self.session))[1]), 1)
        with self.assertRaisesRegex(ValueError, "not open"):
            end_activity(self.session, started["activity_id"], "completed")

    def test_activity_cannot_begin_after_capture_stops(self):
        self.finish_capture()
        with self.assertRaisesRegex(ValueError, "READY"):
            self.activity()

    def test_parallel_terminals_append_complete_journal_events(self):
        script = Path(__file__).resolve().parents[1] / "tools/capture_session.py"
        processes = [subprocess.Popen([sys.executable, str(script), "note", "--session", str(self.session),
                                       "--text", f"synthetic-terminal-{i}"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(6)]
        for process in processes:
            _, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
        notes = [event["text"] for event in read_events(self.session) if event["event"] == "operator_note"]
        self.assertEqual(set(notes), {f"synthetic-terminal-{i}" for i in range(6)})
        self.assertEqual(len(notes), 6)

    def test_workload_records_exit_code_and_literal_arguments_without_shell(self):
        with patch("tools.capture_session.os.geteuid", return_value=1000, create=True):
            result = run_activity(self.session,
                                  [sys.executable, "-c", "import sys; print(sys.argv[1]); sys.exit(7)", "$(literal); &"],
                                  name="fixture", source="192.0.2.1", destination="192.0.2.2")
        self.assertEqual(result, 7)
        events = read_events(self.session)
        ended = events[-1]
        self.assertEqual(ended["outcome"], "failed")
        self.assertEqual(ended["exit_code"], 7)
        self.assertEqual((self.session / ended["output_files"]["stdout"]).read_text().strip(), "$(literal); &")

    def test_workload_timeout_is_closed_as_aborted(self):
        with patch("tools.capture_session.os.geteuid", return_value=1000, create=True):
            result = run_activity(self.session, [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1,
                                  name="fixture", source="192.0.2.1", destination="192.0.2.2")
        self.assertEqual(result, 124)
        self.assertEqual(read_events(self.session)[-1]["outcome"], "aborted")
        self.assertEqual(activity_state(read_events(self.session))[0], {})

    def test_missing_workload_executable_records_failure(self):
        with patch("tools.capture_session.os.geteuid", return_value=1000, create=True):
            result = run_activity(self.session, [str(self.session / "missing-executable")],
                                  name="fixture", source="192.0.2.1", destination="192.0.2.2")
        self.assertEqual(result, 127)
        self.assertEqual(read_events(self.session)[-1]["outcome"], "failed")

    def test_workloads_do_not_inherit_capture_root_privileges(self):
        with patch("tools.capture_session.os.geteuid", return_value=0, create=True):
            with self.assertRaisesRegex(ValueError, "without sudo"):
                run_activity(self.session, [sys.executable], name="fixture", source="host", destination="host")

    def test_pcap_audit_endianness_resolution_and_packet_hash(self):
        for endian in ("<", ">"):
            for nano in (True, False):
                path = self.pcap(endian=endian, nano=nano)
                result = audit_pcap(path)
                self.assertEqual(result["packets"], 1)
                self.assertEqual(result["sha256"], digest(path))
                self.assertEqual(result["snapshot_truncated_packets"], 0)
                self.assertFalse(result["incomplete_record"])

    def test_pcap_audit_distinguishes_snapshot_and_incomplete_record(self):
        path = self.pcap(records=[(b"short", 50)])
        self.assertEqual(audit_pcap(path)["snapshot_truncated_packets"], 1)
        with path.open("ab") as handle:
            handle.write(struct.pack("<IIII", 1700000001, 0, 5, 5) + b"ab")
        result = audit_pcap(path)
        self.assertEqual(result["packets"], 1)
        self.assertTrue(result["incomplete_record"])
        with path.open("ab") as handle:
            handle.write(b"cde" + b"partial-header")
        self.assertTrue(audit_pcap(path)["incomplete_record"])

    def test_pcap_audit_rejects_invalid_length(self):
        with self.assertRaisesRegex(ValueError, "packet header"):
            audit_pcap(self.pcap(records=[(b"too-long", 1)]))

    def test_rotations_are_ordered_numerically(self):
        for name in ("traffic.pcap10", "traffic.pcap", "traffic.pcap2", "traffic.pcap1"):
            self.pcap(name)
        (self.session / "traffic.pcap.notes").write_text("not capture data")
        self.assertEqual([p.name for p in packet_files(self.session)],
                         ["traffic.pcap", "traffic.pcap1", "traffic.pcap2", "traffic.pcap10"])

    def test_statistics_do_not_substitute_filter_counts_for_captured_packets(self):
        stats = capture_statistics("1 packet captured\n9 packets received by filter\n2 packets dropped by kernel\n")
        self.assertEqual(stats, {"captured": 1, "received_by_filter": 9, "dropped_by_kernel": 2})
        self.assertIsNone(capture_statistics("tcpdump failed")["dropped_by_kernel"])

    def test_seal_requires_capture_finished_and_all_activities_closed(self):
        for status in ACTIVE:
            info = metadata(self.session)
            info["status"] = status
            write_json(self.session / "capture.json", info)
            with self.assertRaisesRegex(ValueError, "finalization"):
                seal_session(self.session)
        info["status"] = "capturing"
        write_json(self.session / "capture.json", info)
        started = self.activity()
        self.finish_capture()
        with self.assertRaisesRegex(ValueError, "open activities"):
            seal_session(self.session)
        end_activity(self.session, started["activity_id"], "unknown")
        manifest = seal_session(self.session)
        self.assertEqual(manifest["label_status"], "unreviewed")
        self.assertEqual(manifest["finished_activities"], 1)
        self.assertEqual(verify_session(self.session)["integrity"], "verified")
        with self.assertRaisesRegex(ValueError, "sealed"):
            append_event(self.session, {"event": "operator_note", "text": "late mutation"})

    def test_seal_checks_pcap_hash_and_verification_detects_changed_or_added_evidence(self):
        path = self.pcap()
        info = metadata(self.session)
        info.update(status="finished", pcap_files=[audit_pcap(path)])
        write_json(self.session / "capture.json", info)
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "changed after capture"):
            seal_session(self.session)
        path.write_bytes(path.read_bytes()[:-7])
        seal_session(self.session)
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            verify_session(self.session)
        path.write_bytes(path.read_bytes()[:-7])
        (self.session / "unexpected.txt").write_text("added later")
        with self.assertRaisesRegex(ValueError, "file set"):
            verify_session(self.session)

    def test_activity_crossing_capture_boundary_is_flagged(self):
        started = self.activity()
        end_activity(self.session, started["activity_id"], "completed")
        info = metadata(self.session)
        info.update(status="finished", ready_utc="2000-01-01T00:00:00+00:00", ended_utc="2000-01-01T00:01:00+00:00")
        write_json(self.session / "capture.json", info)
        self.assertIn("capture boundaries", seal_session(self.session)["quality_flags"][0])

    @unittest.skipUnless(sys.platform == "linux", "Linux capture orchestration uses a synthetic fake tcpdump.")
    def test_foreground_capture_duration_and_storage_stops_flush_and_audit(self):
        # No network socket or live packet capture: this executable writes a fixture.
        import os
        executable = self.session / "fake-tcpdump"
        executable.write_text("#!/usr/bin/env python3\n"
                              "import pathlib,signal,struct,sys,time\n"
                              "p=pathlib.Path(sys.argv[sys.argv.index('-w')+1])\n"
                              "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
                              "print('listening on lo',file=sys.stderr,flush=True)\n"
                              "p.write_bytes(b'\\xd4\\xc3\\xb2\\xa1'+struct.pack('<HHIIII',2,4,0,0,262144,1)+"
                              "(struct.pack('<IIII',1700000000,0,65536,65536)+bytes(65536))*32)\n"
                              "try:\n while True: time.sleep(0.1)\n"
                              "finally: print('32 packets captured\\n32 packets received by filter\\n0 packets dropped by kernel',file=sys.stderr)\n")
        executable.chmod(0o700)
        owner = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="fixture-user")
        old_mask = os.umask(0o077)
        self.addCleanup(os.umask, old_mask)
        for reason, duration, budget in (("duration_reached", 1, 10), ("pcap_budget_reached", 10, 1)):
            with self.subTest(reason=reason):
                args = SimpleNamespace(owner=None, interface="lo", duration=duration, max_mib=budget, min_free_mib=1,
                                       rotate_mb=1, output_root=self.session / reason, purpose="train")
                with patch("tools.capture_session.os.geteuid", return_value=0), patch("pwd.getpwuid", return_value=owner), \
                        patch("tools.capture_session.os.chown"), patch("tools.capture_session.shutil.which", return_value=str(executable)), \
                        patch("tools.capture_session.inspect_command", return_value={"stdout": "yes\n", "exit_code": 0}):
                    self.assertEqual(capture(args), 0)
                sessions = list(args.output_root.iterdir())
                self.assertEqual(len(sessions), 1)
                info = metadata(sessions[0])
                self.assertEqual(info["status"], "finished")
                self.assertEqual(info["stop_reason"], reason)
                self.assertEqual(info["pcap_files"][0]["packets"], 32)
                self.assertFalse(info["quality_flags"])


if __name__ == "__main__":
    unittest.main()
