from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.psp import PBP_HEADER_SIZE
from re_pro.psp import PBP_MAGIC
from re_pro.psp import PBP_SECTION_FILENAMES
from re_pro.psp import PARAM_SFO_JSON_NAME
from re_pro.psp import build_param_sfo
from re_pro.psp import extract_pbp
from re_pro.psp import parse_param_sfo
from re_pro.psp import parse_pbp
from re_pro.psp import rebuild_pbp_with_overlay


def make_param_sfo(title: str = "Demo Game") -> bytes:
    return build_param_sfo(
        {
            "version": 0x101,
            "entries": [
                {"key": "BOOTABLE", "format_code": "0x0404", "value": 1, "max_length": 4},
                {"key": "CATEGORY", "format_code": "0x0204", "value": "MG", "max_length": 4},
                {"key": "DISC_ID", "format_code": "0x0204", "value": "TEST00001", "max_length": 16},
                {"key": "TITLE", "format_code": "0x0204", "value": title, "max_length": 32},
            ],
        }
    )


def make_pbp(path: Path, *, title: str = "Demo Game") -> None:
    sections = {
        "PARAM.SFO": make_param_sfo(title),
        "ICON0.PNG": b"\x89PNG\r\n\x1a\n",
        "ICON1.PMF": b"",
        "PIC0.PNG": b"",
        "PIC1.PNG": b"",
        "SND0.AT3": b"",
        "DATA.PSP": b"~PSP\x00\x08\x00\x00\x01\x01demo_module\x00".ljust(96, b"\x00"),
        "DATA.PSAR": b"PSAR\x03\x00\x00\x00payload".ljust(128, b"\x55"),
    }
    offsets: list[int] = []
    cursor = PBP_HEADER_SIZE
    payloads = [sections[name] for name in PBP_SECTION_FILENAMES]
    for payload in payloads:
        offsets.append(cursor)
        cursor += len(payload)
    with path.open("wb") as handle:
        handle.write(PBP_MAGIC)
        handle.write(struct.pack("<I", 0x10000))
        for offset in offsets:
            handle.write(struct.pack("<I", offset))
        for payload in payloads:
            handle.write(payload)


class PspFormatTests(unittest.TestCase):
    def test_param_sfo_round_trips_editable_values(self) -> None:
        payload = make_param_sfo("Original")
        manifest = parse_param_sfo(payload)
        self.assertEqual(manifest["values"]["TITLE"], "Original")

        manifest["values"]["TITLE"] = "A Longer Edited Title"
        rebuilt = build_param_sfo(manifest)
        reparsed = parse_param_sfo(rebuilt)

        self.assertEqual(reparsed["values"]["TITLE"], "A Longer Edited Title")
        self.assertEqual(reparsed["values"]["BOOTABLE"], 1)

    def test_pbp_extracts_sections_and_rebuilds_from_param_sfo_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pbp = root / "EBOOT.PBP"
            make_pbp(pbp, title="Before")
            overlay = root / "overlay"

            result = extract_pbp(pbp, overlay)
            self.assertTrue(result["ok"])
            self.assertTrue((overlay / "DATA.PSP").exists())
            self.assertTrue((overlay / "DATA.PSAR").exists())

            sfo_json = json.loads((overlay / PARAM_SFO_JSON_NAME).read_text(encoding="utf-8"))
            sfo_json["values"]["TITLE"] = "After"
            (overlay / PARAM_SFO_JSON_NAME).write_text(json.dumps(sfo_json, indent=2), encoding="utf-8")
            (overlay / "DATA.PSP").write_bytes((overlay / "DATA.PSP").read_bytes().replace(b"demo", b"edit", 1))
            rebuilt = root / "rebuilt.PBP"
            rebuild = rebuild_pbp_with_overlay(pbp, overlay, rebuilt)

            self.assertTrue(rebuild["ok"])
            parsed = parse_pbp(rebuilt)
            self.assertEqual(parse_param_sfo(parsed.section("PARAM.SFO").data)["values"]["TITLE"], "After")  # type: ignore[union-attr]
            self.assertIn(b"edit_module", parsed.section("DATA.PSP").data)  # type: ignore[union-attr]
            self.assertEqual(parsed.section("DATA.PSAR").data[:4], b"PSAR")  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
