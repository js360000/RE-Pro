from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from re_pro.console_formats import detect_console_formats
from re_pro.engine import ReverseEngineeringEngine
from re_pro.psp import build_param_sfo
from tests import _path_setup  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[1]
PS2_ELF_SAMPLE = REPO_ROOT / "samples" / "OPNPS2LD.ELF"


class ConsoleFormatParserTests(unittest.TestCase):
    def test_psx_exe_header_is_mapped(self) -> None:
        payload = bytearray(0x900)
        payload[0:8] = b"PS-X EXE"
        struct.pack_into("<I", payload, 0x10, 0x80010000)
        struct.pack_into("<I", payload, 0x14, 0x80020000)
        struct.pack_into("<I", payload, 0x18, 0x80030000)
        struct.pack_into("<I", payload, 0x1C, 0x1234)
        struct.pack_into("<I", payload, 0x30, 0x801FFFF0)
        payload[0x4C:0x4C + 24] = b"Sony Computer Entertainment"

        detections = detect_console_formats(Path("BOOT.EXE"), bytes(payload))

        self.assertEqual(detections[0]["format_id"], "sony-psx-exe")
        self.assertEqual(detections[0]["architecture"], "MIPS R3000A")
        self.assertEqual(detections[0]["metadata"]["entry_point"], "0x80010000")
        self.assertEqual(detections[0]["metadata"]["payload_offset"], 0x800)

    def test_gamecube_wii_dol_sections_are_mapped(self) -> None:
        payload = bytearray(0x140)
        struct.pack_into(">I", payload, 0x00, 0x100)
        struct.pack_into(">I", payload, 0x48, 0x80003100)
        struct.pack_into(">I", payload, 0x90, 0x20)
        struct.pack_into(">I", payload, 0xD8, 0x80004000)
        struct.pack_into(">I", payload, 0xDC, 0x80)
        struct.pack_into(">I", payload, 0xE0, 0x80003100)

        detections = detect_console_formats(Path("main.dol"), bytes(payload))

        self.assertEqual(detections[0]["format_id"], "nintendo-dol")
        self.assertEqual(detections[0]["metadata"]["entry_point"], "0x80003100")
        self.assertEqual(detections[0]["metadata"]["sections"][0]["name"], ".text0")

    def test_gamecube_disc_header_exposes_main_dol_and_fst_offsets(self) -> None:
        payload = bytearray(0x500)
        payload[0:4] = b"GM8E"
        payload[4:6] = b"01"
        payload[0x20:0x20 + 12] = b"Sample Game"
        struct.pack_into(">I", payload, 0x1C, 0xC2339F3D)
        struct.pack_into(">I", payload, 0x420, 0x2440)
        struct.pack_into(">I", payload, 0x424, 0x18200)
        struct.pack_into(">I", payload, 0x428, 0x3000)

        detections = detect_console_formats(Path("game.gcm"), bytes(payload))

        self.assertEqual(detections[0]["format_id"], "nintendo-gc-wii-disc")
        self.assertEqual(detections[0]["metadata"]["game_code"], "GM8E")
        self.assertEqual(detections[0]["metadata"]["dol_offset"], 0x2440)
        self.assertEqual(detections[0]["metadata"]["fst_offset"], 0x18200)

    def test_sony_pkg_and_psarc_archives_are_identified(self) -> None:
        pkg = bytearray(0xC0)
        pkg[0:4] = b"\x7fPKG"
        struct.pack_into(">H", pkg, 0x04, 0x8000)
        struct.pack_into(">H", pkg, 0x06, 0x0001)
        struct.pack_into(">I", pkg, 0x08, 0xC0)
        struct.pack_into(">I", pkg, 0x0C, 8)
        struct.pack_into(">I", pkg, 0x10, 0xC0)
        struct.pack_into(">Q", pkg, 0x18, 0x100000)
        struct.pack_into(">Q", pkg, 0x20, 0x200)
        struct.pack_into(">Q", pkg, 0x28, 0xFF00)
        pkg[0x30:0x30 + 36] = b"UP0001-NPUB00000_00-SAMPLECONTENT"

        psarc = bytearray(0x40)
        psarc[0:4] = b"PSAR"
        psarc[4:8] = b"\x00\x01\x00\x00"
        psarc[8:12] = b"zlib"
        struct.pack_into(">I", psarc, 0x0C, 0x100)
        struct.pack_into(">I", psarc, 0x10, 0x20)
        struct.pack_into(">I", psarc, 0x14, 3)
        struct.pack_into(">I", psarc, 0x18, 0x10000)

        pkg_detection = detect_console_formats(Path("game.pkg"), bytes(pkg))[0]
        psarc_detection = detect_console_formats(Path("data.psarc"), bytes(psarc))[0]

        self.assertEqual(pkg_detection["format_id"], "sony-pkg")
        self.assertEqual(pkg_detection["metadata"]["revision_kind"], "finalized")
        self.assertFalse(pkg_detection["metadata"]["debug_package"])
        self.assertEqual(pkg_detection["metadata"]["content_id"], "UP0001-NPUB00000_00-SAMPLECONTENT")
        self.assertEqual(psarc_detection["format_id"], "sony-psarc")
        self.assertEqual(psarc_detection["metadata"]["compression"], "zlib")
        self.assertEqual(psarc_detection["metadata"]["toc_entry_count"], 3)
        self.assertFalse(psarc_detection["metadata"]["toc_encrypted"])

    def test_psp_sfo_data_psp_and_data_psar_are_identified(self) -> None:
        sfo = build_param_sfo(
            {
                "entries": [
                    {"key": "TITLE", "format_code": "0x0204", "value": "Sample PSP", "max_length": 32},
                    {"key": "UPDATER_VER", "format_code": "0x0204", "value": "6.61", "max_length": 8},
                ]
            }
        )
        data_psp = b"~PSP\x00\x08\x00\x00\x01\x01sample_mod\x00".ljust(128, b"\x00")
        data_psar = b"PSAR\x03\x00\x00\x00not-psarc".ljust(128, b"\x55")

        sfo_detection = detect_console_formats(Path("PARAM.SFO"), sfo)[0]
        psp_detection = detect_console_formats(Path("DATA.PSP"), data_psp)[0]
        psar_detection = detect_console_formats(Path("DATA.PSAR"), data_psar)[0]

        self.assertEqual(sfo_detection["format_id"], "sony-psp-param-sfo")
        self.assertEqual(sfo_detection["metadata"]["title"], "Sample PSP")
        self.assertEqual(psp_detection["format_id"], "sony-psp-data-psp")
        self.assertEqual(psp_detection["metadata"]["module_name"], "sample_mod")
        self.assertEqual(psar_detection["format_id"], "sony-psp-data-psar")
        self.assertNotEqual(psar_detection["format_id"], "sony-psarc")

    def test_nintendo_rom_headers_are_identified(self) -> None:
        nds = bytearray(0x4000)
        nds[0:12] = b"NDS SAMPLE  "
        nds[0x0C:0x10] = b"ABCD"
        nds[0x10:0x12] = b"01"
        struct.pack_into("<I", nds, 0x20, 0x4000)
        struct.pack_into("<I", nds, 0x24, 0x02000000)
        struct.pack_into("<I", nds, 0x28, 0x02000000)
        struct.pack_into("<I", nds, 0x2C, 0x1000)
        struct.pack_into("<I", nds, 0x30, 0x8000)
        struct.pack_into("<I", nds, 0x34, 0x03800000)
        struct.pack_into("<I", nds, 0x38, 0x03800000)
        struct.pack_into("<I", nds, 0x3C, 0x800)
        struct.pack_into("<I", nds, 0x84, 0x4000)
        nds[0xC0:0xC4] = b"\x24\xFF\xAE\x51"

        gba = bytearray(0xC0)
        gba[0xA0:0xAC] = b"GBA SAMPLE  "
        gba[0xAC:0xB0] = b"AGBE"
        gba[0xB0:0xB2] = b"01"
        gba[0xB2] = 0x96

        n64 = bytearray(0x80)
        n64[0:4] = b"\x80\x37\x12\x40"
        n64[0x20:0x20 + 11] = b"N64 SAMPLE "
        n64[0x3B:0x3F] = b"NSEJ"

        self.assertEqual(detect_console_formats(Path("game.nds"), bytes(nds))[0]["format_id"], "nintendo-nds-rom")
        self.assertEqual(detect_console_formats(Path("game.gba"), bytes(gba))[0]["format_id"], "nintendo-gba-rom")
        self.assertEqual(detect_console_formats(Path("game.z64"), bytes(n64))[0]["format_id"], "nintendo-n64-rom")

    def test_common_console_archives_and_compression_are_identified(self) -> None:
        fixtures = {
            "arc.u8": (b"\x55\xAA\x38\x2D" + b"\x00\x00\x00\x20" + b"\x00\x00\x00\x40" + b"\x00\x00\x01\x00" + b"\x00" * 16, "nintendo-u8"),
            "model.rarc": (b"RARC" + struct.pack(">IIIIIII", 0x100, 0x20, 0x20, 0x80, 0x80, 0, 0), "nintendo-rarc"),
            "pack.sarc": (self._build_sarc(), "nintendo-sarc"),
            "asset.szs": (b"Yaz0" + struct.pack(">III", 0x2000, 0, 0) + b"\x00" * 16, "nintendo-yaz0"),
            "movie.cpk": (b"CPK " + b"\x00" * 12 + b"@UTF" + b"\x00" * 16, "cri-cpk"),
            "sound.afs": (b"AFS\x00" + struct.pack("<I", 1) + struct.pack("<II", 0x800, 0x100), "cri-afs"),
        }

        for name, (payload, expected_format) in fixtures.items():
            with self.subTest(name=name):
                detections = detect_console_formats(Path(name), payload)
                self.assertEqual(detections[0]["format_id"], expected_format)

    @staticmethod
    def _build_sarc() -> bytes:
        payload = bytearray(0x40)
        payload[0:4] = b"SARC"
        struct.pack_into(">H", payload, 0x04, 0x14)
        payload[0x06:0x08] = b"\xFE\xFF"
        struct.pack_into(">I", payload, 0x08, 0x40)
        struct.pack_into(">I", payload, 0x0C, 0x30)
        payload[0x14:0x18] = b"SFAT"
        struct.pack_into(">H", payload, 0x18, 0x0C)
        struct.pack_into(">H", payload, 0x1A, 2)
        struct.pack_into(">I", payload, 0x1C, 0x65)
        return bytes(payload)


@unittest.skipUnless(PS2_ELF_SAMPLE.exists(), "actual PS2 ELF sample not available")
class ConsoleActualBinaryTests(unittest.TestCase):
    def test_actual_ps2_elf_is_classified_by_engine(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = ReverseEngineeringEngine(output_root=Path(temp_dir)).analyze(PS2_ELF_SAMPLE)
            run_dir = Path(report.output_dir)

            self.assertEqual(report.target_type, "console-executable")
            self.assertIn("Sony PlayStation 2 ELF executable", report.frameworks)
            manifest_path = run_dir / "console" / "console_formats.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["detections"][0]["format_id"], "sony-mips-elf")
            self.assertEqual(manifest["detections"][0]["metadata"]["elf"]["machine"], "MIPS")


if __name__ == "__main__":
    unittest.main()
