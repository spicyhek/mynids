import io
from pathlib import Path
import tempfile
import unittest
import zipfile
import zlib

from tools.cicids_archives import parse_catalog, unpack_member


class PublicArchiveTests(unittest.TestCase):
    def test_catalog_and_bounded_member_extraction(self):
        payload = b"synthetic packet bytes" * 100
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as writer:
            writer.writestr("pcap/synthetic", payload)
        member = parse_catalog(archive.getvalue(), len(archive.getvalue()))[0]
        self.assertEqual(member["name"], "pcap/synthetic")
        self.assertEqual(member["header_offset"], 0)
        self.assertEqual(member["uncompressed_bytes"], len(payload))
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(payload) + compressor.flush()
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "member.deflate", Path(directory) / "capture"
            source.write_bytes(compressed)
            unpack_member(source, target, member, max_output_bytes=len(payload))
            self.assertEqual(target.read_bytes(), payload)
            with self.assertRaisesRegex(ValueError, "already exists"):
                unpack_member(source, target, member, len(payload))

    def test_declared_size_crc_and_output_budget_are_enforced(self):
        payload = b"abc" * 10000
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(payload) + compressor.flush()
        member = {"compression": 8, "uncompressed_bytes": len(payload), "crc32": format(zlib.crc32(payload), "08x")}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "compressed"
            source.write_bytes(compressed)
            with self.assertRaisesRegex(ValueError, "byte budget"):
                unpack_member(source, Path(directory) / "too-big", member, len(payload) - 1)
            with self.assertRaisesRegex(ValueError, "declared/budgeted"):
                unpack_member(source, Path(directory) / "bad-size", {**member, "uncompressed_bytes": 10}, len(payload))
            with self.assertRaisesRegex(ValueError, "size/CRC mismatch"):
                unpack_member(source, Path(directory) / "bad-crc", {**member, "crc32": "00000000"}, len(payload))

    def test_truncated_compressed_member_is_not_accepted(self):
        payload = b"packet data" * 100
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(payload) + compressor.flush()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "truncated"
            source.write_bytes(compressed[:-1])
            member = {"compression": 8, "uncompressed_bytes": len(payload), "crc32": format(zlib.crc32(payload), "08x")}
            with self.assertRaisesRegex(ValueError, "incomplete"):
                unpack_member(source, Path(directory) / "output", member, len(payload))


if __name__ == "__main__":
    unittest.main()
