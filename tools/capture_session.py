#!/usr/bin/env python3
"""Capture Linux traffic and journal operator activity using only Python's standard library.

Copy this file to the sensor host; it does not import the NIDS or run inference.
Only the foreground ``capture`` command needs sudo. All other commands run as
the ordinary operator, including commands recorded by ``run``.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

MIB = 1024 * 1024
MANIFEST = "session-manifest.json"
ACTIVE = ("starting", "capturing", "finalizing")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(MIB), b""):
            value.update(chunk)
    return value.hexdigest()


def inherit_owner(path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parent = path.parent.stat()
        os.chown(path, parent.st_uid, parent.st_gid)


def write_json(path, value):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        os.chmod(temporary, 0o600)
        inherit_owner(temporary)
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def metadata(session):
    return json.loads((session / "capture.json").read_text(encoding="utf-8"))


@contextmanager
def journal_lock(session):
    """Serialize concurrent SSH terminals; also usable by local Windows tests."""
    with (session / ".journal.lock").open("a+b") as handle:
        os.chmod(session / ".journal.lock", 0o600)
        inherit_owner(session / ".journal.lock")
        if os.name == "nt":
            import msvcrt
            if handle.seek(0, 2) == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def read_events(session):
    path = session / "activity.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def activity_state(events):
    active, finished = {}, set()
    for event in events:
        if event["event"] == "activity_begin":
            activity_id = event["activity_id"]
            if activity_id in active or activity_id in finished:
                raise ValueError("Duplicate activity ID in journal.")
            active[activity_id] = event
        elif event["event"] == "activity_end":
            activity_id = event["activity_id"]
            if activity_id not in active:
                raise ValueError("Activity end has no open activity.")
            del active[activity_id]
            finished.add(activity_id)
    return active, finished


def append_unlocked(session, event):
    if (session / MANIFEST).exists():
        raise ValueError("Session is sealed; its evidence must not be edited.")
    row = {"recorded_at_utc": utc_now(), "monotonic_ns": time.monotonic_ns(),
           "journal_host": socket.gethostname(), "operator": getpass.getuser(), **event}
    with (session / "activity.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
        os.chmod(session / "activity.jsonl", 0o600)
        inherit_owner(session / "activity.jsonl")
        handle.write(json.dumps(row, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return row


def append_event(session, event):
    with journal_lock(session):
        return append_unlocked(session, event)


def begin_activity(session, name, source, destination, protocol="unknown", port=None, note="", command=None):
    if not all(isinstance(value, str) and value.strip() for value in (name, source, destination)):
        raise ValueError("Name, source and destination must be recorded.")
    if port is not None and not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535.")
    with journal_lock(session):
        if metadata(session)["status"] != "capturing":
            raise ValueError("Begin an activity only after capture reports READY.")
        return append_unlocked(session, {"event": "activity_begin", "activity_id": uuid.uuid4().hex,
                               "name": name, "source": source, "destination": destination,
                               "protocol": protocol, "destination_port": port, "note": note,
                               "command": command, "label_status": "unreviewed"})


def end_activity(session, activity_id, outcome, **details):
    if outcome not in ("completed", "failed", "aborted", "unknown"):
        raise ValueError("Unknown activity outcome.")
    with journal_lock(session):
        active, _ = activity_state(read_events(session))
        if activity_id not in active:
            raise ValueError("Activity ID is not open; use status to inspect the journal.")
        return append_unlocked(session, {"event": "activity_end", "activity_id": activity_id,
                                         "outcome": outcome, **details})


def stop_process(process, grace=10):
    """Terminate only this tool's new process group, flushing tcpdump with SIGINT."""
    forced = False
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL if os.name != "nt" else signal.SIGTERM):
        if process.poll() is not None:
            break
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            else:
                process.terminate()
            process.wait(timeout=grace)
        except ProcessLookupError:
            break
        except subprocess.TimeoutExpired:
            forced = True
    if process.poll() is None:
        raise RuntimeError("Child did not stop; capture must not be sealed as complete.")
    return forced


def run_activity(session, command, *, timeout=600, **activity):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ValueError("Run workloads as your ordinary user, without sudo.")
    if not command or timeout <= 0:
        raise ValueError("Provide a command after -- and a positive timeout.")
    started = begin_activity(session, command=command, **activity)
    activity_id = started["activity_id"]
    paths = {name: session / f"activity-{activity_id}.{name}.log" for name in ("stdout", "stderr")}
    process, exit_code, outcome, error = None, None, "failed", None
    try:
        with paths["stdout"].open("xb") as stdout, paths["stderr"].open("xb") as stderr:
            for path in paths.values():
                os.chmod(path, 0o600)
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=os.name == "posix")
            exit_code = process.wait(timeout=timeout)
            outcome = "completed" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired:
        error, exit_code, outcome = "Workload timeout", 124, "aborted"
    except KeyboardInterrupt:
        error, exit_code, outcome = "Operator interrupted workload", 130, "aborted"
    except OSError as exc:
        error, exit_code = str(exc), 127
    finally:
        if process is not None and process.poll() is None:
            stop_process(process, grace=5)
        end_activity(session, activity_id, outcome, exit_code=exit_code, error=error,
                     output_files={name: path.name for name, path in paths.items()})
    return exit_code


def tcpdump_command(executable, interface, session, owner, rotate_mb=100):
    # -C without -W creates new numbered files instead of overwriting a ring.
    return [executable, "-n", "-p", "-i", interface, "-s", "0", "-B", "32768", "-U",
            "-C", str(rotate_mb), "-w", str(session / "traffic.pcap"), "-Z", owner]


def packet_files(session):
    return sorted((p for p in session.iterdir() if re.fullmatch(r"traffic\.pcap\d*", p.name)),
                  key=lambda p: int(p.name.removeprefix("traffic.pcap") or "0"))


def audit_pcap(path):
    """Audit classic tcpdump PCAP, counting snapshot and partial-record truncation."""
    result = {"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path),
              "packets": 0, "snapshot_truncated_packets": 0, "incomplete_record": False,
              "first_packet_epoch": None, "last_packet_epoch": None}
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
               b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError(f"{path.name}: expected a complete classic PCAP header.")
        endian, resolution = formats[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or not snaplen:
            raise ValueError(f"{path.name}: unsupported PCAP header.")
        result.update(snaplen=snaplen, linktype=network & 0xFFFF)
        while record := handle.read(16):
            if len(record) != 16:
                result["incomplete_record"] = True
                break
            sec, fraction, included, original = struct.unpack(endian + "IIII", record)
            if fraction >= resolution or included > original or included > snaplen:
                raise ValueError(f"{path.name}: invalid packet header.")
            remaining = result["bytes"] - handle.tell()
            if included > remaining:
                result["incomplete_record"] = True
                break
            handle.seek(included, 1)
            timestamp = sec + fraction / resolution
            if result["first_packet_epoch"] is None:
                result["first_packet_epoch"] = timestamp
            result["last_packet_epoch"] = timestamp
            result["packets"] += 1
            result["snapshot_truncated_packets"] += int(included < original)
    return result


def capture_statistics(text):
    names = {"captured": "captured", "received_by_filter": "received by filter",
             "dropped_by_kernel": "dropped by kernel"}
    return {key: int(found[-1]) if (found := re.findall(r"(?m)^(\d+) packets? " + value + r"\s*$", text)) else None
            for key, value in names.items()}


def inspect_command(arguments):
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=5)
        return {"exit_code": result.returncode, "stdout": result.stdout[:32000], "stderr": result.stderr[:4000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"unavailable": str(exc)}


def capture(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Capture runs on Linux: sudo python3 capture_session.py capture ...")
    import pwd
    owner = pwd.getpwnam(args.owner) if args.owner else pwd.getpwuid(int(os.environ.get("SUDO_UID", "0")))
    if owner.pw_uid == 0:
        raise ValueError("Invoke sudo from your normal account, or pass --owner USER.")
    if args.interface == "any" or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.interface):
        raise ValueError("Specify the sensor's actual interface, such as eth0; do not use any.")
    if not (Path("/sys/class/net") / args.interface).exists():
        raise ValueError("Capture interface does not exist.")
    if min(args.duration, args.max_mib, args.min_free_mib, args.rotate_mb) <= 0:
        raise ValueError("Duration, disk budget, free-space reserve and rotation size must be positive.")
    executable = shutil.which("tcpdump")
    if executable is None:
        raise ValueError("tcpdump is required on the capture host.")
    os.umask(0o077)
    root = args.output_root.expanduser().resolve()
    if root.exists():
        if root.stat().st_uid != owner.pw_uid:
            raise ValueError("Existing output root must belong to the capture owner; choose a directory in their home.")
    else:
        root.mkdir(mode=0o700)
        os.chown(root, owner.pw_uid, owner.pw_gid)
    if shutil.disk_usage(root).free < (args.min_free_mib + args.rotate_mb) * MIB:
        raise ValueError("Insufficient disk space above the requested reserve.")
    session = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    session.mkdir(mode=0o700)
    os.chown(session, owner.pw_uid, owner.pw_gid)
    command = tcpdump_command(executable, args.interface, session, owner.pw_name, args.rotate_mb)
    source = session / "capture-framework.py"
    source.write_bytes(Path(__file__).read_bytes())
    inherit_owner(source)
    info = {"schema_version": 1, "session_id": session.name, "status": "starting", "purpose": args.purpose,
            "label_status": "unreviewed", "owner": owner.pw_name, "hostname": socket.gethostname(),
            "interface": args.interface, "duration_seconds_requested": args.duration,
            "pcap_budget_mib": args.max_mib, "min_free_mib": args.min_free_mib,
            "started_utc": None, "ended_utc": None, "tcpdump_command": command,
            "framework_sha256": digest(source), "tcpdump_version": inspect_command([executable, "--version"]),
            "interface_before": inspect_command(["ip", "-j", "address", "show", "dev", args.interface]),
            "clock_before": inspect_command(["timedatectl", "show", "--property=NTPSynchronized", "--value"]),
            "visibility": "Only packets visible on this interface; whole-LAN visibility is not assumed.",
            "limits": "Disk limits are polled and can overshoot; numbered PCAP files are never reused."}
    write_json(session / "capture.json", info)
    append_event(session, {"event": "session_created", "purpose": args.purpose})
    print(f"SESSION={session}\nWaiting for tcpdump readiness...", flush=True)
    interrupted = []
    old_handlers = {sig: signal.signal(sig, lambda number, frame: interrupted.append(number))
                    for sig in (signal.SIGINT, signal.SIGTERM)}
    process, reason, forced, failure = None, "capture_failed", False, None
    try:
        log_path = session / "capture.log"
        with log_path.open("xb") as log:
            inherit_owner(log_path)
            info["started_utc"] = utc_now()
            started = time.monotonic()
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True,
                                       env={**os.environ, "LC_ALL": "C"})
            while process.poll() is None:
                elapsed = time.monotonic() - started
                if info["status"] == "starting" and "listening on" in log_path.read_text(errors="replace"):
                    info.update(status="capturing", ready_utc=utc_now())
                    with journal_lock(session):
                        write_json(session / "capture.json", info)
                        append_unlocked(session, {"event": "capture_ready"})
                    print(f"READY: journal activities in another terminal using --session {session}", flush=True)
                if interrupted or (session / "stop-request.json").exists():
                    reason = "operator_stop"
                    break
                if elapsed >= args.duration:
                    reason = "duration_reached"
                    break
                if sum(p.stat().st_size for p in packet_files(session)) >= args.max_mib * MIB:
                    reason = "pcap_budget_reached"
                    break
                if shutil.disk_usage(session).free <= args.min_free_mib * MIB:
                    reason = "free_space_reserve_reached"
                    break
                if info["status"] == "starting" and elapsed > 10:
                    reason = "readiness_timeout"
                    break
                time.sleep(0.25)
            if process.poll() is not None:
                reason = "unexpected_capture_exit"
    except OSError as exc:
        failure = str(exc)
    finally:
        if process is not None:
            forced = stop_process(process)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        info.update(status="finalizing", ended_utc=utc_now(), stop_reason=reason, forced_stop=forced,
                    capture_exit_code=process.returncode if process else None)
        write_json(session / "capture.json", info)
    audits, flags = [], []
    if failure:
        flags.append(f"Capture error: {failure}")
    for path in packet_files(session):
        try:
            audits.append(audit_pcap(path))
        except ValueError as exc:
            flags.append(str(exc))
    log_path = session / "capture.log"
    statistics = capture_statistics(log_path.read_text(errors="replace") if log_path.exists() else "")
    if not audits or not sum(row["packets"] for row in audits):
        flags.append("No complete packets captured.")
    if statistics["dropped_by_kernel"] is None or statistics["dropped_by_kernel"] > 0:
        flags.append("Kernel packet-drop count is missing or nonzero.")
    if statistics["captured"] != sum(row["packets"] for row in audits):
        flags.append("PCAP packet counts do not match tcpdump captured count.")
    if any(row["snapshot_truncated_packets"] or row["incomplete_record"] for row in audits):
        flags.append("Snapshot truncation or an incomplete final record was detected.")
    if any(row["linktype"] != 1 for row in audits):
        flags.append("Non-Ethernet capture: confirm compatibility with the production extraction path.")
    if info["clock_before"].get("stdout", "").strip() != "yes":
        flags.append("Clock synchronization was not confirmed; independently verify timing.")
    if forced or info["capture_exit_code"] != 0 or reason in ("readiness_timeout", "unexpected_capture_exit"):
        flags.append("Capture did not finish cleanly.")
    info.update(status="finished" if not flags else "needs_review", pcap_files=audits,
                tcpdump_statistics=statistics, quality_flags=flags,
                interface_after=inspect_command(["ip", "-j", "address", "show", "dev", args.interface]))
    with journal_lock(session):
        write_json(session / "capture.json", info)
        append_unlocked(session, {"event": "capture_finished", "stop_reason": reason, "quality_flags": flags})
    print(json.dumps({"session": str(session), "stop_reason": reason, "quality_flags": flags,
                      "packets": sum(row["packets"] for row in audits), "next": "Close activities, then seal."}, indent=2))
    return 0 if not flags else 2


def seal_session(session):
    with journal_lock(session):
        if (session / MANIFEST).exists():
            raise ValueError("Session is already sealed.")
        info = metadata(session)
        if info["status"] in ACTIVE:
            raise ValueError("Stop capture and wait for finalization before sealing.")
        active, finished = activity_state(read_events(session))
        if active:
            raise ValueError("Close open activities before sealing; do not invent successful outcomes.")
        flags = list(info.get("quality_flags", []))
        events = read_events(session)
        ready, ended = info.get("ready_utc"), info.get("ended_utc")
        if ready and ended:
            boundary = (datetime.fromisoformat(ready), datetime.fromisoformat(ended))
            if any(event["event"] in ("activity_begin", "activity_end") and
                   not boundary[0] <= datetime.fromisoformat(event["recorded_at_utc"]) <= boundary[1]
                   for event in events):
                flags.append("An activity crosses capture boundaries; do not assume its entire connection was observed.")
        files = {}
        for path in sorted(session.iterdir()):
            if path.name == ".journal.lock":
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError("Session bundle must contain only regular evidence files.")
            files[path.name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        for pcap in info.get("pcap_files", []):
            if files.get(pcap["name"], {}).get("sha256") != pcap["sha256"]:
                raise ValueError("PCAP changed after capture auditing.")
        manifest = {"schema_version": 1, "session_id": info["session_id"], "purpose": info["purpose"],
                    "sealed_utc": utc_now(), "finished_activities": len(finished), "files": files,
                    "quality_flags": flags, "label_status": "unreviewed",
                    "note": "Integrity and operator evidence only; no connection receives a ground-truth label."}
        write_json(session / MANIFEST, manifest)
    return manifest


def verify_session(session):
    manifest = json.loads((session / MANIFEST).read_text(encoding="utf-8"))
    actual = {p.name for p in session.iterdir() if p.name not in (MANIFEST, ".journal.lock")}
    if actual != set(manifest["files"]):
        raise ValueError("Session file set changed after sealing.")
    for name, expected in manifest["files"].items():
        if Path(name).name != name:
            raise ValueError("Invalid manifest filename.")
        path = session / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
            raise ValueError(f"Session integrity check failed: {name}")
    return {"integrity": "verified", "files": len(actual), "label_status": "unreviewed",
            "quality_flags": manifest["quality_flags"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    start = commands.add_parser("capture", help="Foreground Linux packet capture; requires sudo.")
    start.add_argument("--interface", required=True)
    start.add_argument("--output-root", type=Path, required=True)
    start.add_argument("--owner", help="File owner when not invoked through sudo.")
    start.add_argument("--purpose", choices=("train", "validation", "test", "unassigned"), required=True)
    start.add_argument("--duration", type=int, default=1800, help="Seconds; default 30 minutes.")
    start.add_argument("--max-mib", type=int, default=1024, help="Polled PCAP storage budget; may overshoot.")
    start.add_argument("--min-free-mib", type=int, default=1024)
    start.add_argument("--rotate-mb", type=int, default=100, help="tcpdump decimal MB per numbered file.")
    for name in ("begin", "run", "end", "note", "status", "stop", "seal", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--session", type=Path, required=True)
        if name in ("begin", "run"):
            sub.add_argument("--name", required=True)
            sub.add_argument("--source", required=True, help="Actual traffic originator/device address.")
            sub.add_argument("--destination", required=True)
            sub.add_argument("--protocol", choices=("tcp", "udp", "icmp", "icmp6", "mixed", "unknown"), default="unknown")
            sub.add_argument("--port", type=int)
            sub.add_argument("--note", default="")
        if name == "run":
            sub.add_argument("--timeout", type=float, default=600)
            sub.add_argument("command", nargs=argparse.REMAINDER)
        if name == "end":
            sub.add_argument("--id", required=True)
            sub.add_argument("--outcome", choices=("completed", "failed", "aborted", "unknown"), required=True)
            sub.add_argument("--note", default="")
        if name == "note":
            sub.add_argument("--text", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "capture":
            return capture(args)
        session = args.session.expanduser().resolve()
        if args.action in ("begin", "run"):
            values = {name: getattr(args, name) for name in ("name", "source", "destination", "protocol", "port", "note")}
            if args.action == "run":
                command = args.command[1:] if args.command[:1] == ["--"] else args.command
                return run_activity(session, command, timeout=args.timeout, **values)
            result = begin_activity(session, **values)
        elif args.action == "end":
            result = end_activity(session, args.id, args.outcome, note=args.note)
        elif args.action == "note":
            result = append_event(session, {"event": "operator_note", "text": args.text})
        elif args.action == "stop":
            with journal_lock(session):
                if metadata(session)["status"] not in ACTIVE or (session / MANIFEST).exists():
                    raise ValueError("Capture is not running.")
                result = append_unlocked(session, {"event": "stop_requested"})
                write_json(session / "stop-request.json", result)
        elif args.action == "status":
            info = metadata(session)
            with journal_lock(session):
                active, finished = activity_state(read_events(session))
            result = {"session": str(session), "status": info["status"], "purpose": info["purpose"],
                      "sealed": (session / MANIFEST).exists(), "open_activities": active,
                      "finished_activities": len(finished), "quality_flags": info.get("quality_flags", [])}
        elif args.action == "seal":
            result = seal_session(session)
        else:
            result = verify_session(session)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"Session operation failed: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
