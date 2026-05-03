from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from re_pro.models import AnalysisReport
from re_pro.psarc import extract_psarc
from re_pro.psarc import pack_psarc_from_mapping
from re_pro.psp import PBP_HEADER_SIZE
from re_pro.psp import PBP_MAGIC
from re_pro.psp import PBP_SECTION_FILENAMES
from re_pro.psp import build_param_sfo
from re_pro.psp import parse_param_sfo
from re_pro.psp import parse_pbp
from re_pro.workspace_browser import build_browser_workspace
from re_pro.workspace_browser import patch_browser_node_bytes
from re_pro.workspace_browser import read_browser_node
from re_pro.workspace_browser import write_browser_node


class WorkspaceBrowserTests(unittest.TestCase):
    def test_browser_workspace_prioritizes_source_extracts_archive_and_edits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            target = root / "sample.exe"
            target.write_bytes(b"MZ\x00\x01\x02\x03")
            recovered = run_dir / "recovered_sources" / "main.cpp"
            recovered.parent.mkdir(parents=True)
            recovered.write_text("int main() { return 0; }\n", encoding="utf-8")
            archive_path = root / "payload.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("assets/config.json", '{"name":"demo"}')

            report = AnalysisReport(target=str(target), output_dir=str(run_dir), target_type="portable-executable")
            report.add_recovered_source("src/main.cpp", str(recovered), "")
            report.add_artifact(str(archive_path), "archive", "ZIP payload")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            manifest = build_browser_workspace(run_dir)
            nodes = manifest["nodes"]
            self.assertEqual(nodes[0]["origin"], "recovered_source")
            source_node = next(node for node in nodes if node["relative_path"] == "source/recovered/src/main.cpp")
            archive_node = next(node for node in nodes if node["relative_path"] == "archives/ZIP_payload/assets/config.json")
            binary_node = next(node for node in nodes if node["origin"] == "target_binary")

            source_read = read_browser_node(run_dir, source_node["id"])
            self.assertIn("int main", source_read["content"])
            write_result = write_browser_node(run_dir, source_node["id"], "int main() { return 42; }\n")
            self.assertTrue(write_result["ok"])
            self.assertEqual(write_result["rebuild"]["kind"], "source_recompile")
            self.assertTrue(Path(write_result["rebuild"]["staged_path"]).exists())
            self.assertIn("return 42", Path(source_node["path"]).read_text(encoding="utf-8"))

            archive_read = read_browser_node(run_dir, archive_node["id"])
            self.assertIn('"name"', archive_read["content"])
            archive_write = write_browser_node(run_dir, archive_node["id"], '{"name":"patched"}', mode="json")
            self.assertTrue(archive_write["rebuild"]["ok"])
            with zipfile.ZipFile(archive_write["rebuild"]["rebuilt_artifact"], "r") as archive:
                self.assertEqual(archive.read("assets/config.json").decode("utf-8"), '{"name":"patched"}')
            patch_result = patch_browser_node_bytes(run_dir, binary_node["id"], 2, "DE AD")
            self.assertTrue(patch_result["ok"])
            self.assertTrue(patch_result["rebuild"]["ok"])
            self.assertEqual(Path(patch_result["rebuild"]["rebuilt_artifact"]).read_bytes()[2:4], bytes.fromhex("DEAD"))
            self.assertEqual(Path(binary_node["path"]).read_bytes()[2:4], bytes.fromhex("DEAD"))
            self.assertEqual(target.read_bytes()[2:4], b"\x00\x01")

            edits = json.loads((Path(manifest["edits_path"])).read_text(encoding="utf-8"))
            self.assertEqual(len(edits["edits"]), 3)

    def test_browser_workspace_edits_psarc_members_via_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            psarc_path = root / "game_assets.psarc"
            pack_psarc_from_mapping(
                [
                    ("scripts/main.lua", b"return 1\n" * 32),
                    ("textures/readme.txt", b"texture note\n"),
                ],
                psarc_path,
                compression="zlib",
                compression_level=9,
                block_size=64,
            )

            report = AnalysisReport(target=str(target), output_dir=str(run_dir), target_type="portable-executable")
            report.add_artifact(str(psarc_path), "archive", "PSARC assets")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            manifest = build_browser_workspace(run_dir)
            psarc_node = next(node for node in manifest["nodes"] if node["relative_path"] == "archives/PSARC_assets/scripts/main.lua")
            write_result = write_browser_node(run_dir, psarc_node["id"], "return 99\n", mode="text")

            self.assertTrue(write_result["rebuild"]["ok"])
            self.assertEqual(write_result["rebuild"]["kind"], "archive_rebuild")
            rebuilt_path = Path(write_result["rebuild"]["rebuilt_artifact"])
            self.assertEqual(rebuilt_path.suffix, ".psarc")
            rebuilt_extract = root / "rebuilt_extract"
            extract_psarc(rebuilt_path, rebuilt_extract)
            self.assertEqual((rebuilt_extract / "scripts" / "main.lua").read_text(encoding="utf-8"), "return 99\n")
            self.assertEqual((rebuilt_extract / "textures" / "readme.txt").read_bytes(), b"texture note\n")

    def test_browser_workspace_edits_pbp_param_sfo_and_data_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            pbp_path = root / "EBOOT.PBP"
            _write_sample_pbp(pbp_path, title="Before")

            report = AnalysisReport(target=str(pbp_path), output_dir=str(run_dir), target_type="console-archive")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            manifest = build_browser_workspace(run_dir)
            sfo_node = next(node for node in manifest["nodes"] if node["relative_path"].endswith("PARAM.SFO.json"))
            data_psp_node = next(node for node in manifest["nodes"] if node["relative_path"].endswith("DATA.PSP"))
            data_psar_node = next(node for node in manifest["nodes"] if node["relative_path"].endswith("DATA.PSAR"))

            sfo_payload = json.loads(read_browser_node(run_dir, sfo_node["id"])["content"])
            sfo_payload["values"]["TITLE"] = "After"
            sfo_write = write_browser_node(run_dir, sfo_node["id"], json.dumps(sfo_payload, indent=2), mode="json")

            self.assertTrue(sfo_write["rebuild"]["ok"])
            rebuilt = parse_pbp(Path(sfo_write["rebuild"]["rebuilt_artifact"]))
            self.assertEqual(parse_param_sfo(rebuilt.section("PARAM.SFO").data)["values"]["TITLE"], "After")  # type: ignore[union-attr]

            data_patch = patch_browser_node_bytes(run_dir, data_psp_node["id"], 0x0A, "65 64 69 74")
            self.assertTrue(data_patch["rebuild"]["ok"])
            rebuilt_after_data = parse_pbp(Path(data_patch["rebuild"]["rebuilt_artifact"]))
            self.assertIn(b"edit_module", rebuilt_after_data.section("DATA.PSP").data)  # type: ignore[union-attr]

            psar_write = write_browser_node(run_dir, data_psar_node["id"], "50 53 41 52 04 00 00 00", mode="hex")
            self.assertTrue(psar_write["rebuild"]["ok"])
            rebuilt_after_psar = parse_pbp(Path(psar_write["rebuild"]["rebuilt_artifact"]))
            self.assertEqual(rebuilt_after_psar.section("DATA.PSAR").data, b"PSAR\x04\x00\x00\x00")  # type: ignore[union-attr]

def _write_sample_pbp(path: Path, *, title: str) -> None:
    sections = {
        "PARAM.SFO": build_param_sfo(
            {
                "entries": [
                    {"key": "TITLE", "format_code": "0x0204", "value": title, "max_length": 32},
                    {"key": "CATEGORY", "format_code": "0x0204", "value": "MG", "max_length": 4},
                ]
            }
        ),
        "ICON0.PNG": b"\x89PNG\r\n\x1a\n",
        "ICON1.PMF": b"",
        "PIC0.PNG": b"",
        "PIC1.PNG": b"",
        "SND0.AT3": b"",
        "DATA.PSP": b"~PSP\x00\x08\x00\x00\x01\x01demo_module\x00".ljust(96, b"\x00"),
        "DATA.PSAR": b"PSAR\x03\x00\x00\x00payload".ljust(128, b"\x55"),
    }
    payloads = [sections[name] for name in PBP_SECTION_FILENAMES]
    cursor = PBP_HEADER_SIZE
    offsets = []
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


if __name__ == "__main__":
    unittest.main()
