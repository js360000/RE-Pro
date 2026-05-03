from __future__ import annotations

import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.console_formats import detect_console_formats
from re_pro.psarc import parse_psarc, read_entry_data


REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_SAMPLE_ROOT = REPO_ROOT / "samples" / "console_real"
REAL_PSP_EBOOT = REAL_SAMPLE_ROOT / "psp" / "sony_psp_fw_6.61_EBOOT.PBP"
REAL_PS3_PKG = REAL_SAMPLE_ROOT / "ps3_pkg" / "sfm_ps3_v0.5.2.pkg"
REAL_PS3_DEBUG_PKG = REAL_SAMPLE_ROOT / "ps3_pkg" / "dump_flash_glevand.pkg"
REAL_PSARC = REAL_SAMPLE_ROOT / "psarc" / "cdlc_ai_rock_day_pc.psarc"


class RealConsoleSampleTests(unittest.TestCase):
    @unittest.skipUnless(REAL_PSP_EBOOT.exists(), "real PSP EBOOT sample not available")
    def test_real_psp_update_eboot_is_detected(self) -> None:
        detections = detect_console_formats(REAL_PSP_EBOOT, REAL_PSP_EBOOT.read_bytes()[:4 * 1024 * 1024])

        self.assertEqual(detections[0]["format_id"], "sony-psp-pbp")
        self.assertEqual(detections[0]["metadata"]["sections"][0]["name"], "param_sfo")
        self.assertTrue(any(section["name"] == "data_psar" for section in detections[0]["metadata"]["sections"]))

    @unittest.skipUnless(REAL_PS3_PKG.exists(), "real PS3 PKG sample not available")
    def test_real_ps3_pkg_header_is_detected(self) -> None:
        detections = detect_console_formats(REAL_PS3_PKG, REAL_PS3_PKG.read_bytes()[:4 * 1024 * 1024])

        self.assertEqual(detections[0]["format_id"], "sony-pkg")
        self.assertEqual(detections[0]["metadata"]["content_id"], "UP0001-PS3SFM001_00-0000000000000000")
        self.assertTrue(detections[0]["metadata"]["debug_package"])
        self.assertEqual(detections[0]["metadata"]["total_size"], REAL_PS3_PKG.stat().st_size)

    @unittest.skipUnless(REAL_PS3_DEBUG_PKG.exists(), "real PS3 debug PKG sample not available")
    def test_real_ps3_debug_pkg_header_is_detected(self) -> None:
        detections = detect_console_formats(REAL_PS3_DEBUG_PKG, REAL_PS3_DEBUG_PKG.read_bytes()[:4096])

        self.assertEqual(detections[0]["format_id"], "sony-pkg")
        self.assertEqual(detections[0]["metadata"]["revision_kind"], "debug")
        self.assertTrue(detections[0]["metadata"]["debug_package"])
        self.assertEqual(detections[0]["metadata"]["content_id"], "UP0001-DPFH00003_00-0000000000000000")

    @unittest.skipUnless(REAL_PSARC.exists(), "real PSARC sample not available")
    def test_real_rocksmith_psarc_encrypted_toc_is_readable(self) -> None:
        detection = detect_console_formats(REAL_PSARC, REAL_PSARC.read_bytes()[:4096])[0]
        archive = parse_psarc(REAL_PSARC, inspect_blocks=True)

        self.assertEqual(detection["format_id"], "sony-psarc")
        self.assertTrue(detection["metadata"]["toc_encrypted"])
        self.assertEqual(archive.archive_flags, 0x04)
        self.assertEqual(archive.compression, "zlib")
        self.assertGreaterEqual(len(archive.manifest_paths), 10)
        self.assertIn("manifests/songs_dlc_nisynclrockd/songs_dlc_nisynclrockd.hsan", archive.manifest_paths)
        self.assertEqual(len(read_entry_data(archive, archive.entries[1], max_bytes=1024 * 1024)), archive.entries[1].uncompressed_size)


if __name__ == "__main__":
    unittest.main()
