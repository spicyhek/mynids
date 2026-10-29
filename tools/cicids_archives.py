"""Inspect/download individual CSE-CIC-IDS2018 ZIP members using anonymous S3 byte ranges.

Requires AWS CLI. Only the selected compressed PCAP member is downloaded, never the
whole daily archive. Nothing is extracted using archive-controlled filesystem paths.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib
import zipfile

from tools.training_data import sha256, write_json

BUCKET = "cse-cic-ids2018"
REGION = "ca-central-1"
DAYS = ("Wednesday-14-02-2018", "Thursday-15-02-2018", "Wednesday-21-02-2018", "Friday-02-03-2018")


def aws(*args: str) -> dict:
    env = dict(os.environ)
    # Public dataset operations must not depend on the user's selected private AWS profile.
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)
    result = subprocess.run(["aws", "--no-cli-pager", "s3api", *args, "--no-sign-request", "--region", REGION,
                             "--cli-connect-timeout", "10", "--cli-read-timeout", "30"],
                            env=env, text=True, capture_output=True, check=False, timeout=120)
    if result.returncode:
        raise RuntimeError(f"Anonymous S3 read failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def read_range(key: str, start: int, end: int, destination: Path, etag: str) -> None:
    if destination.exists():
        raise ValueError(f"Download target already exists: {destination}")
    reply = aws("get-object", "--bucket", BUCKET, "--key", key, "--range", f"bytes={start}-{end}",
                "--if-match", etag, str(destination))
    expected_size = end - start + 1
    if reply.get("ContentLength") != expected_size or destination.stat().st_size != expected_size:
        raise ValueError("S3 byte range size mismatch.")
    if reply.get("ContentRange", "").split("/")[0] != f"bytes {start}-{end}":
        raise ValueError("S3 did not return the requested byte range.")


def parse_catalog(tail: bytes, archive_size: int) -> list[dict]:
    offset = archive_size - len(tail)
    with zipfile.ZipFile(io.BytesIO(tail)) as archive:
        return [{"name": item.filename, "compressed_bytes": item.compress_size,
                 "uncompressed_bytes": item.file_size, "header_offset": item.header_offset + offset,
                 "compression": item.compress_type, "crc32": format(item.CRC, "08x"),
                 "encrypted": bool(item.flag_bits & 1)} for item in archive.infolist() if not item.is_dir()]


def catalog(day: str, output: Path) -> dict:
    if day not in DAYS:
        raise ValueError(f"Choose one of the documented starter days: {DAYS}")
    if output.exists():
        raise ValueError("Catalog already exists; preserve it or choose a new output path.")
    key = f"Original Network Traffic and Log data/{day}/pcap.zip"
    head = aws("head-object", "--bucket", BUCKET, "--key", key)
    size, etag = head["ContentLength"], head["ETag"]
    output.parent.mkdir(parents=True, exist_ok=True)
    tail_path = output.with_name(output.name + ".zip-tail")
    start = max(0, size - 1024 * 1024)
    read_range(key, start, size - 1, tail_path, etag)
    members = parse_catalog(tail_path.read_bytes(), size)
    result = {"dataset": "CSE-CIC-IDS2018", "day": day, "bucket": BUCKET, "region": REGION, "key": key,
              "archive_bytes": size, "etag": etag, "metadata_download_bytes": size - start,
              "documentation": "https://www.unb.ca/cic/datasets/ids-2018.html", "members": members}
    write_json(output, result)
    return result


def unpack_member(compressed: Path, destination: Path, member: dict, max_output_bytes: int) -> None:
    """Validate size, deflate end, and CRC before a capture is promoted from a partial file."""
    if destination.exists():
        raise ValueError("Extraction target already exists.")
    if member["compression"] not in (0, 8) or member.get("encrypted"):
        raise ValueError("Only unencrypted stored/deflated members are supported.")
    if member["uncompressed_bytes"] > max_output_bytes:
        raise ValueError("Selected member exceeds the decompressed byte budget.")
    decompressor = zlib.decompressobj(-15) if member["compression"] == 8 else None
    total, crc = 0, 0
    with compressed.open("rb") as source, destination.open("xb") as target:
        while chunk := source.read(1024 * 1024):
            data = decompressor.decompress(chunk, min(max_output_bytes, member["uncompressed_bytes"]) - total + 1) if decompressor else chunk
            if decompressor and decompressor.unconsumed_tail:
                raise ValueError("Decompression exceeds the declared/budgeted output size.")
            total += len(data)
            if total > min(max_output_bytes, member["uncompressed_bytes"]):
                raise ValueError("Decompression exceeds the declared/budgeted output size.")
            crc = zlib.crc32(data, crc)
            target.write(data)
    if decompressor and (not decompressor.eof or decompressor.unused_data):
        raise ValueError("Compressed member is incomplete or contains unexpected trailing data.")
    if total != member["uncompressed_bytes"] or format(crc & 0xffffffff, "08x") != member["crc32"]:
        raise ValueError("Extracted member size/CRC mismatch.")


def fetch(catalog_path: Path, member_name: str, output: Path, *, max_compressed_mib=256, max_output_mib=1024) -> dict:
    if output.exists() or output.with_name(output.name + ".source.json").exists():
        raise ValueError("Capture/provenance output already exists; preserve the existing files.")
    metadata = json.loads(catalog_path.read_text())
    if metadata.get("bucket") != BUCKET or metadata.get("region") != REGION or metadata.get("day") not in DAYS:
        raise ValueError("Catalog does not describe the expected public dataset.")
    if metadata.get("key") != f"Original Network Traffic and Log data/{metadata['day']}/pcap.zip":
        raise ValueError("Catalog key differs from the expected daily archive.")
    members = [row for row in metadata["members"] if row["name"] == member_name]
    if len(members) != 1:
        raise ValueError("Select exactly one catalog member.")
    member = members[0]
    if not member_name.startswith("pcap/") or member["compression"] not in (0, 8) or member.get("encrypted"):
        raise ValueError("Expected an unencrypted capture member.")
    if not 0 < member["compressed_bytes"] <= max_compressed_mib * 1024**2 or not 0 < member["uncompressed_bytes"] <= max_output_mib * 1024**2:
        raise ValueError("Selected member exceeds the compressed/decompressed byte budget.")
    offset = member["header_offset"]
    if offset < 0 or offset + 30 + member["compressed_bytes"] > metadata["archive_bytes"]:
        raise ValueError("Invalid member offset/length.")
    output.parent.mkdir(parents=True, exist_ok=True)
    header_path = output.with_name(output.name + ".header-part")
    read_range(metadata["key"], offset, offset + 29, header_path, metadata["etag"])
    header = struct.unpack("<4s5H3I2H", header_path.read_bytes())
    if header[0] != b"PK\x03\x04" or header[2] & 1 or header[3] != member["compression"]:
        raise ValueError("ZIP local header differs from the catalog.")
    name_path = output.with_name(output.name + ".name-part")
    read_range(metadata["key"], offset + 30, offset + 29 + header[9], name_path, metadata["etag"])
    if name_path.read_bytes().decode("utf-8" if header[2] & 0x800 else "cp437") != member_name:
        raise ValueError("ZIP member filename differs from the catalog.")
    body_start = offset + 30 + header[9] + header[10]
    compressed = output.with_name(output.name + ".compressed-part")
    read_range(metadata["key"], body_start, body_start + member["compressed_bytes"] - 1, compressed, metadata["etag"])
    partial = output.with_name(output.name + ".extract-part")
    unpack_member(compressed, partial, member, max_output_mib * 1024**2)
    source = {"dataset": metadata["dataset"], "day": metadata["day"], "bucket": BUCKET, "key": metadata["key"],
              "etag": metadata["etag"], "member": member, "compressed_range_start": body_start,
              "catalog_sha256": sha256(catalog_path), "capture_sha256": sha256(partial),
              "crc_and_size_verified": True, "ground_truth_status": "unreviewed",
              "documentation": metadata["documentation"]}
    partial.rename(output)
    write_json(output.with_name(output.name + ".source.json"), source)
    # These are fixed sibling files created by this invocation, not recursively computed targets.
    for path in (header_path, name_path, compressed):
        path.unlink()
    return source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("catalog")
    listing.add_argument("--day", choices=DAYS, required=True)
    listing.add_argument("--output", type=Path, required=True)
    download = commands.add_parser("fetch")
    download.add_argument("catalog", type=Path)
    download.add_argument("--member", required=True)
    download.add_argument("--output", type=Path, required=True)
    download.add_argument("--max-compressed-mib", type=int, default=256)
    download.add_argument("--max-output-mib", type=int, default=1024)
    args = parser.parse_args()
    try:
        if args.command == "catalog":
            result = catalog(args.day, args.output)
            print(json.dumps({"day": result["day"], "files": len(result["members"]),
                              "metadata_download_bytes": result["metadata_download_bytes"]}))
        else:
            result = fetch(args.catalog, args.member, args.output, max_compressed_mib=args.max_compressed_mib,
                           max_output_mib=args.max_output_mib)
            print(json.dumps({"output": str(args.output), "sha256": result["capture_sha256"],
                              "crc_and_size_verified": result["crc_and_size_verified"]}))
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"Public capture operation failed: {exc}\n")


if __name__ == "__main__":
    main()
