from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.utils import parse_pe_codeview_records, parse_pe_metadata, sanitize_relative_source_path


class PETests(unittest.TestCase):
    def test_parse_pe_metadata_for_minimal_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.exe"
            data = bytearray(0x200)
            data[0:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 123456789, 0, 0, 0xF0, 0x22)
            struct.pack_into("<H", data, 0x98, 0x20B)
            data[0x188:0x190] = b".text\x00\x00\x00"
            path.write_bytes(bytes(data))

            metadata = parse_pe_metadata(path)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["machine"], "x64")
            self.assertEqual(metadata["optional_magic"], "PE32+")
            self.assertEqual(metadata["sections"], [".text"])

    def test_sanitize_relative_source_path_removes_windows_unsafe_chars(self) -> None:
        sanitized = sanitize_relative_source_path("turbopack:[project]/node_modules/@scope/pkg/src/file.tsx")
        self.assertEqual(sanitized, "[project]/node_modules/@scope/pkg/src/file.tsx")

    def test_parse_pe_codeview_records_reads_rsds_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.exe"
            data = bytearray(0x400)
            data[0:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 123456789, 0, 0, 0xF0, 0x22)
            struct.pack_into("<H", data, 0x98, 0x20B)
            struct.pack_into("<II", data, 0x108 + (8 * 6), 0x1000, 28)
            data[0x188:0x190] = b".rdata\x00\x00"
            struct.pack_into("<IIII", data, 0x190, 0x400, 0x1000, 0x400, 0x200)
            struct.pack_into("<IIHHIIII", data, 0x200, 0, 0, 0, 0, 2, 40, 0x101C, 0x21C)
            data[0x21C:0x220] = b"RSDS"
            guid = bytes.fromhex("78563412BC9AF0DE1122334455667788")
            data[0x220:0x230] = guid
            struct.pack_into("<I", data, 0x230, 2)
            pdb_path = b"sample.pdb\x00"
            data[0x234:0x234 + len(pdb_path)] = pdb_path
            path.write_bytes(bytes(data))

            records = parse_pe_codeview_records(path)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["format"], "RSDS")
            self.assertEqual(records[0]["pdb_path"], "sample.pdb")
            self.assertEqual(records[0]["guid"], "12345678-9ABC-DEF0-1122-334455667788")


if __name__ == "__main__":
    unittest.main()
