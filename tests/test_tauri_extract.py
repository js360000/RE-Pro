from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import brotli

from tests import _path_setup  # noqa: F401

from re_pro.tauri_extract import extract_tauri_assets, scan_tauri_asset_entries


class TauriExtractTests(unittest.TestCase):
    def test_scan_and_extract_tauri_asset_entries(self) -> None:
        image_base = 0x140000000
        rdata = bytearray(0x800)
        key = b"/assets/index-test.js"
        raw = b"console.log('hello');"
        compressed = brotli.compress(raw)

        key_offset = 0x220
        data_offset = key_offset + len(key)
        table_offset = 0x120

        rdata[key_offset : key_offset + len(key)] = key
        rdata[data_offset : data_offset + len(compressed)] = compressed
        key_va = image_base + 0x1000 + key_offset
        data_va = image_base + 0x1000 + data_offset
        struct.pack_into("<QQQQ", rdata, table_offset, key_va, len(key), data_va, len(compressed))

        sections = [
            {
                "name": ".rdata",
                "virtual_address": 0x1000,
                "raw_offset": 0,
                "raw_size": 0x400,
            }
        ]
        entries = scan_tauri_asset_entries(bytes(rdata), image_base, sections)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].key, "/assets/index-test.js")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(_make_fake_pe(bytes(rdata), image_base))
            result = extract_tauri_assets(target, root / "tauri", root / "sources")
            extracted_file = root / "tauri" / "assets" / "assets" / "index-test.js"
            self.assertEqual(result["extracted_count"], 1)
            self.assertTrue(extracted_file.exists())
            self.assertEqual(extracted_file.read_bytes(), raw)

    def test_scan_and_extract_nextjs_source_map_entries(self) -> None:
        image_base = 0x140000000
        rdata = bytearray(0x4000)
        key = b"/_next/static/chunks/app-test.js.map"
        raw = (
            b'{'
            b'"version":3,'
            b'"file":"app-test.js",'
            b'"sources":["webpack://_N_E/src/app/page.tsx"],'
            b'"sourcesContent":["export default function Page() { return null; }"]'
            b"}"
        )
        compressed = brotli.compress(raw)

        key_offset = 0x600
        data_offset = 0x900
        table_offset = 0x200

        rdata[key_offset : key_offset + len(key)] = key
        rdata[data_offset : data_offset + len(compressed)] = compressed
        key_va = image_base + 0x1000 + key_offset
        data_va = image_base + 0x1000 + data_offset
        struct.pack_into("<QQQQ", rdata, table_offset, key_va, len(key), data_va, len(compressed))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(_make_fake_pe(bytes(rdata), image_base))
            result = extract_tauri_assets(target, root / "tauri", root / "sources")
            extracted_map = root / "tauri" / "assets" / "_next" / "static" / "chunks" / "app-test.js.map"
            restored_source = root / "sources" / "app-test.js" / "_N_E" / "src" / "app" / "page.tsx"
            self.assertEqual(result["extracted_count"], 1)
            self.assertTrue(extracted_map.exists())
            self.assertTrue(restored_source.exists())


def _make_fake_pe(rdata_bytes: bytes, image_base: int) -> bytes:
    data = bytearray(max(0x1200, 0x200 + len(rdata_bytes)))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x80 + 24 + 24, image_base)
    section_offset = 0x80 + 24 + 0xF0
    data[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", data, section_offset + 8, len(rdata_bytes), 0x1000, len(rdata_bytes), 0x200)
    data[0x200 : 0x200 + len(rdata_bytes)] = rdata_bytes
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
