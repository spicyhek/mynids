"""Select whole bidirectional TCP/UDP tuples from reviewed source labels, preserving packet blocks.

PCAPNG blocks follow the IETF pcapng draft. Selected tuples are kept for the
entire source capture, including packets outside a sampled label's time window.
No payloads, packet lengths, timestamps, or handshake packets are rewritten.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, UTC
import hashlib
import json
from pathlib import Path
import random
import socket
import struct

from tools.public_labels import read_cic_labels, tuple_key
from tools.training_data import sha256, write_json


def packet_key(data: bytes, linktype: int):
    """None preserves non-TCP/UDP/fragment context rather than removing needed fragments."""
    if linktype != 1:
        raise ValueError("Tuple selection currently requires Ethernet captures.")
    if len(data) < 14:
        return None
    position, ethertype = 14, int.from_bytes(data[12:14], "big")
    while ethertype in (0x8100, 0x88a8):
        if len(data) < position + 4:
            return None
        ethertype = int.from_bytes(data[position + 2:position + 4], "big")
        position += 4
    if ethertype != 0x0800 or len(data) < position + 20:
        return None
    header_length = (data[position] & 15) * 4
    if header_length < 20 or len(data) < position + header_length + 4:
        return None
    # Keep all IPv4 fragments as context, including the first fragment.
    if int.from_bytes(data[position + 6:position + 8], "big") & 0x3fff:
        return None
    protocol = data[position + 9]
    if protocol not in (6, 17):
        return None
    src = socket.inet_ntoa(data[position + 12:position + 16])
    dst = socket.inet_ntoa(data[position + 16:position + 20])
    sport, dport = struct.unpack_from("!HH", data, position + header_length)
    return tuple_key(src, sport, dst, dport, protocol)


def capture_blocks(handle):
    """Yield (original bytes, packet or None, timestamp or None, wire length, linktype)."""
    first = handle.read(4)
    modes = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if first in modes:
        endian, divisor = modes[first]
        header = first + handle.read(20)
        if len(header) != 24:
            raise ValueError("Incomplete PCAP header.")
        fields = struct.unpack(endian + "IHHIIII", header)
        snaplen, linktype = fields[-2:]
        yield header, None, None, 0, linktype
        while raw := handle.read(16):
            if len(raw) != 16:
                raise ValueError("Incomplete PCAP packet header.")
            seconds, fraction, caplen, wirelen = struct.unpack(endian + "IIII", raw)
            if caplen > snaplen or caplen > 16 * 1024**2 or fraction >= divisor or caplen > wirelen:
                raise ValueError("Invalid PCAP packet length/timestamp.")
            data = handle.read(caplen)
            if len(data) != caplen:
                raise ValueError("Incomplete PCAP packet body.")
            yield raw + data, data, seconds + fraction / divisor, wirelen, linktype
        return
    if first != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Unrecognized PCAP/PCAPNG format.")
    interfaces, endian = [], None
    prefix = first + handle.read(4)
    while prefix:
        if len(prefix) != 8:
            raise ValueError("Incomplete PCAPNG block header.")
        if prefix[:4] == b"\x0a\x0d\x0d\x0a":
            bom = handle.read(4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if endian is None:
                raise ValueError("Invalid PCAPNG section byte order.")
            length = struct.unpack(endian + "I", prefix[4:])[0]
            if length < 28 or length % 4 or length > 16 * 1024**2:
                raise ValueError("Invalid PCAPNG section length.")
            raw = prefix + bom + handle.read(length - 12)
            if len(raw) != length or struct.unpack(endian + "I", raw[-4:])[0] != length:
                raise ValueError("Incomplete or inconsistent PCAPNG section.")
            if struct.unpack_from(endian + "H", raw, 12)[0] != 1:
                raise ValueError("Unsupported PCAPNG major version.")
            interfaces = []
            yield raw, None, None, 0, 1
        else:
            if endian is None:
                raise ValueError("Missing PCAPNG section.")
            kind, length = struct.unpack(endian + "II", prefix)
            if length < 12 or length % 4 or length > 16 * 1024**2:
                raise ValueError("Invalid PCAPNG block length.")
            raw = prefix + handle.read(length - 8)
            if len(raw) != length or struct.unpack(endian + "I", raw[-4:])[0] != length:
                raise ValueError("Incomplete or inconsistent PCAPNG block.")
            body = raw[8:-4]
            if kind == 1:
                if len(body) < 8:
                    raise ValueError("Invalid interface description.")
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
                resolution, offset = 1e-6, 0
                pos = 8
                while pos + 4 <= len(body):
                    option, size = struct.unpack_from(endian + "HH", body, pos)
                    if option == 0:
                        break
                    value = body[pos + 4:pos + 4 + size]
                    if len(value) != size:
                        raise ValueError("Truncated PCAPNG interface option.")
                    if option == 9:
                        if size != 1:
                            raise ValueError("Invalid timestamp resolution.")
                        resolution = (2 if value[0] & 0x80 else 10) ** -(value[0] & 0x7f)
                    if option == 14:
                        if size != 8:
                            raise ValueError("Invalid timestamp offset.")
                        offset = struct.unpack(endian + "q", value)[0]
                    pos += 4 + ((size + 3) // 4) * 4
                interfaces.append((linktype, snaplen, resolution, offset))
                yield raw, None, None, 0, linktype
            elif kind in (2, 6):
                if len(body) < 20:
                    raise ValueError("Invalid packet block.")
                interface = struct.unpack_from(endian + ("H" if kind == 2 else "I"), body)[0]
                high, low, caplen, wirelen = struct.unpack_from(endian + "IIII", body, 4)
                if interface >= len(interfaces):
                    raise ValueError("Unknown packet interface.")
                linktype, snaplen, resolution, offset = interfaces[interface]
                if caplen > wirelen or (snaplen and caplen > snaplen) or caplen > len(body) - 20:
                    raise ValueError("Invalid captured packet length.")
                data = body[20:20 + caplen]
                yield raw, data, ((high << 32) | low) * resolution + offset, wirelen, linktype
            elif kind == 3:
                # Simple packet blocks have no timestamp; preserve verbatim as context.
                if not interfaces or len(body) < 4:
                    raise ValueError("Invalid simple packet block.")
                wirelen = struct.unpack_from(endian + "I", body)[0]
                linktype, snaplen, _, _ = interfaces[0]
                caplen = min(wirelen, snaplen) if snaplen else wirelen
                if caplen > len(body) - 4:
                    raise ValueError("Incomplete simple packet block.")
                yield raw, body[4:4 + caplen], None, wirelen, linktype
            else:
                yield raw, None, None, 0, 1
        prefix = handle.read(8)


def subset(capture: Path, archive: Path, members: list[str], output: Path, *, per_label=2000, seed=20261029,
           max_output_mib=4096):
    if output.exists():
        raise ValueError("Subset output exists; choose a new version.")
    if not 1 <= per_label <= 1000000 or max_output_mib < 1:
        raise ValueError("Invalid sample/output budget.")
    rng = random.Random(seed)
    reservoirs, source_counts = defaultdict(list), Counter()
    blank = 0
    for row in read_cic_labels(archive, members):
        if row.get("blank"):
            blank += 1
            continue
        if row["label"] is None:
            raise ValueError(f"Unmapped nonblank source label: {row['source_label']!r}")
        source_counts[row["source_label"]] += 1
        bucket = reservoirs[row["source_label"]]
        if len(bucket) < per_label:
            bucket.append(row)
        else:
            position = rng.randrange(source_counts[row["source_label"]])
            if position < per_label:
                bucket[position] = row
    selected = {row["key"] for bucket in reservoirs.values() for row in bucket if row["key"][0] in (6, 17)}
    if not selected:
        raise ValueError("No labeled TCP/UDP tuples selected.")
    output.mkdir(parents=True)
    packets = kept = truncated = context = 0
    raw_bytes = written = 0
    first = last = None
    hasher = hashlib.sha256()
    with capture.open("rb", buffering=4 * 1024**2) as handle, (output / "subset.pcap").open("xb") as target:
        for raw, data, stamp, wirelen, linktype in capture_blocks(handle):
            hasher.update(raw)
            raw_bytes += len(raw)
            keep = True
            if data is not None:
                packets += 1
                truncated += int(len(data) < wirelen)
                if stamp is not None:
                    first = stamp if first is None else min(first, stamp)
                    last = stamp if last is None else max(last, stamp)
                key = packet_key(data, linktype)
                keep = key is None or key in selected
                if keep:
                    kept += 1
                    context += int(key is None)
            if keep:
                written += len(raw)
                if written > max_output_mib * 1024**2:
                    raise ValueError("Subset exceeds its output byte budget; partial output is not a completed dataset.")
                target.write(raw)
            if packets and packets % 2000000 == 0:
                print(f"Scanned {packets:,} packets; kept {kept:,}", flush=True)
    evidence_rows = []
    for row in read_cic_labels(archive, members):
        if not row.get("blank") and row["key"] in selected:
            evidence_rows.append(row)
    (output / "source-labels.jsonl").write_text("".join(json.dumps(row) + "\n" for row in evidence_rows), encoding="utf-8")
    manifest = {"source_capture": capture.name, "source_capture_bytes": raw_bytes,
                "source_capture_sha256": hasher.hexdigest(), "source_label_archive_sha256": sha256(archive),
                "source_members": members, "source_label_counts": dict(source_counts), "empty_csv_rows": blank,
                "seed": seed, "per_original_label_reservoir_limit": per_label,
                "selected_bidirectional_tuples": len(selected), "source_packets": packets,
                "subset_packets": kept, "context_packets": context, "snaplen_truncated_source_packets": truncated,
                "first_source_packet_utc": datetime.fromtimestamp(first, UTC).isoformat() if first is not None else None,
                "last_source_packet_utc": datetime.fromtimestamp(last, UTC).isoformat() if last is not None else None,
                "subset_bytes": written, "subset_sha256": sha256(output / "subset.pcap"),
                "source_label_metadata_sha256": sha256(output / "source-labels.jsonl"),
                "subsetter_sha256": sha256(Path(__file__)),
                "ground_truth_status": "pending_tuple_time_join",
                "policy": "All packets of selected bidirectional tuples across the entire capture are preserved verbatim; non-TCP/UDP and fragments remain as context.",
                "limitations": ["This is a source-label-stratified development subset, not an estimate of real traffic prevalence.",
                                "The original PCAP/PCAPNG format, packet blocks, timestamps, lengths, and payloads are preserved.",
                                "Tuple reuse can include additional connections; final labeling must join timestamps and reject conflicts.",
                                "CIC CSV minute precision, timezone, and 12-hour ambiguity require independent clock alignment."]}
    assert raw_bytes == capture.stat().st_size
    write_json(output / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--labels-zip", type=Path, required=True)
    parser.add_argument("--member", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--per-label", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261029)
    parser.add_argument("--max-output-mib", type=int, default=4096)
    args = parser.parse_args()
    report = subset(args.capture, args.labels_zip, args.member, args.output, per_label=args.per_label, seed=args.seed,
                    max_output_mib=args.max_output_mib)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
