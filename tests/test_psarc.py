from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from re_pro.engine import ReverseEngineeringEngine
from re_pro.psarc import extract_psarc, pack_psarc_from_mapping, parse_psarc, rebuild_psarc_with_overlay
from tests import _path_setup  # noqa: F401


class PsarcArchiveTests(unittest.TestCase):
    def test_zlib_psarc_extracts_rebuilds_and_preserves_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "assets.psarc"
            pack_psarc_from_mapping(
                [
                    ("folder/config.txt", b"A" * 256),
                    ("asset.bin", bytes(range(64))),
                ],
                archive_path,
                compression="zlib",
                compression_level=9,
                block_size=64,
            )

            archive = parse_psarc(archive_path, inspect_blocks=True)
            self.assertEqual(archive.compression, "zlib")
            self.assertEqual(archive.manifest_paths, ["folder/config.txt", "asset.bin"])
            self.assertEqual(archive.entries[1].compression, "zlib")

            extract_dir = root / "extract"
            extract_result = extract_psarc(archive_path, extract_dir)
            self.assertTrue(extract_result["ok"])
            self.assertEqual((extract_dir / "folder" / "config.txt").read_bytes(), b"A" * 256)

            (extract_dir / "folder" / "config.txt").write_bytes(b"B" * 256)
            (extract_dir / "extra").mkdir()
            (extract_dir / "extra" / "new.txt").write_text("new asset\n", encoding="utf-8")
            rebuilt_path = root / "assets.rebuilt.psarc"
            rebuild = rebuild_psarc_with_overlay(archive_path, extract_dir, rebuilt_path)

            self.assertTrue(rebuild["ok"])
            self.assertEqual(rebuild["replaced_entries"], ["folder/config.txt"])
            self.assertEqual(rebuild["added_entries"], ["extra/new.txt"])
            rebuilt = parse_psarc(rebuilt_path, inspect_blocks=True)
            self.assertEqual(rebuilt.manifest_paths, ["folder/config.txt", "asset.bin", "extra/new.txt"])
            self.assertEqual(rebuilt.entries[1].compression, "zlib")

            rebuilt_extract = root / "rebuilt_extract"
            extract_psarc(rebuilt_path, rebuilt_extract)
            self.assertEqual((rebuilt_extract / "folder" / "config.txt").read_bytes(), b"B" * 256)
            self.assertEqual((rebuilt_extract / "asset.bin").read_bytes(), bytes(range(64)))
            self.assertEqual((rebuilt_extract / "extra" / "new.txt").read_text(encoding="utf-8"), "new asset\n")

    def test_lzma_psarc_extracts_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "lzma_assets.psarc"
            pack_psarc_from_mapping(
                {"script/init.lua": b"print('hello')\n" * 64},
                archive_path,
                compression="lzma",
                compression_level=9,
                block_size=128,
            )

            archive = parse_psarc(archive_path, inspect_blocks=True)
            self.assertEqual(archive.compression, "lzma")
            self.assertEqual(archive.manifest_paths, ["script/init.lua"])

            extract_dir = root / "extract"
            extract_psarc(archive_path, extract_dir)
            self.assertEqual((extract_dir / "script" / "init.lua").read_bytes(), b"print('hello')\n" * 64)

    def test_encrypted_toc_psarc_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "encrypted_toc.psarc"
            pack_psarc_from_mapping(
                {"songs/bin/generic/test.sng": b"\x01\x02\x03" * 300},
                archive_path,
                compression="zlib",
                compression_level=9,
                block_size=64,
                archive_flags=0x04,
            )

            archive = parse_psarc(archive_path, inspect_blocks=True)
            self.assertEqual(archive.archive_flags, 0x04)
            self.assertEqual(archive.manifest_paths, ["songs/bin/generic/test.sng"])

            extract_dir = root / "extract"
            extract_psarc(archive_path, extract_dir)
            self.assertEqual((extract_dir / "songs" / "bin" / "generic" / "test.sng").read_bytes(), b"\x01\x02\x03" * 300)

    def test_engine_emits_psarc_toc_and_extract_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "engine_assets.psarc"
            pack_psarc_from_mapping(
                {"scripts/boot.lua": b"booted = true\n" * 16},
                archive_path,
                compression="zlib",
                compression_level=9,
                block_size=64,
            )

            report = ReverseEngineeringEngine(output_root=root / "out").analyze(archive_path)
            run_dir = Path(report.output_dir)

            self.assertEqual(report.target_type, "console-archive")
            toc_path = run_dir / "console" / "psarc" / "psarc_toc.json"
            self.assertTrue(toc_path.exists())
            self.assertTrue((run_dir / "console" / "psarc" / "extract" / "scripts" / "boot.lua").exists())


if __name__ == "__main__":
    unittest.main()
