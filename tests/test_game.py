from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.game import GameNativeAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class GameAnalyzerTests(unittest.TestCase):
    def test_imgui_and_graphics_stack_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["Dear ImGui 1.90", "imgui_impl_dx11", "glfwInit"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_imports=["d3d11.dll", "dxgi.dll"],
            )

            GameNativeAnalyzer().analyze(context, report)

            self.assertIn("Dear ImGui", report.frameworks)
            self.assertIn("Direct3D 11", report.frameworks)
            self.assertIn("DXGI", report.frameworks)
            self.assertTrue(any("game/UI stack markers" in note for note in report.notes))

    def test_gdeflate_candidate_is_extracted_when_nvcomp_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.exe"
            target.write_bytes(b"MZ")
            candidate = root / "assets" / "textures.gdeflate"
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_bytes(b"compressed")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["GDeflate", "RTX IO"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_imports=["dstorage.dll"],
            )

            def fake_decompress(source: Path, destination: Path) -> tuple[bool, str]:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"decoded")
                return True, "decoded"

            with (
                patch("re_pro.analyzers.game.nvcomp_available", return_value=(True, "1.2.3")),
                patch("re_pro.analyzers.game.try_decompress_file", side_effect=fake_decompress),
            ):
                GameNativeAnalyzer().analyze(context, report)

            self.assertIn("DirectStorage", report.frameworks)
            self.assertIn("NVIDIA GDeflate", report.frameworks)
            self.assertTrue(any("GDeflate-decompressed asset" in artifact.description for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "GDeflate assets recovered" for finding in report.findings))

    def test_sidecar_game_ddl_structs_are_recovered_as_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.exe"
            target.write_bytes(b"MZ")
            ddl_path = root / "assets" / "player_schema.ddl"
            ddl_path.parent.mkdir(parents=True, exist_ok=True)
            ddl_path.write_text(
                """
                struct PlayerState {
                    uint32 entity_id;
                    float health;
                    vec3 position;
                };
                """,
                encoding="utf-8",
            )
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["D3D12CreateDevice"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_imports=["d3d12.dll"],
            )

            GameNativeAnalyzer().analyze(context, report)

            self.assertIn("Game DDL schemas", report.frameworks)
            self.assertTrue(any(finding.title == "Game DDL structs recovered" for finding in report.findings))
            self.assertTrue(any(source.original_path.startswith("ddl/") for source in report.recovered_sources))
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in context.analysis_index.to_dict()["entities"]}
            self.assertTrue(any(entity_id.startswith("ddl_struct:") and "playerstate" in entity_id for entity_id in entity_ids))

    def test_gdeflate_expanded_ddl_is_parsed_after_decompression(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.exe"
            target.write_bytes(b"MZ")
            candidate = root / "assets" / "runtime_schema.gdeflate"
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_bytes(b"compressed")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["GDeflate", "DirectStorage"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_imports=["dstorage.dll"],
            )

            def fake_decompress(source: Path, destination: Path) -> tuple[bool, str]:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    "struct RuntimeWeapon { uint32 id; float damage; string name; };",
                    encoding="utf-8",
                )
                return True, "decoded"

            with (
                patch("re_pro.analyzers.game.nvcomp_available", return_value=(True, "1.2.3")),
                patch("re_pro.analyzers.game.try_decompress_file", side_effect=fake_decompress),
            ):
                GameNativeAnalyzer().analyze(context, report)

            self.assertIn("NVIDIA GDeflate", report.frameworks)
            self.assertIn("Game DDL schemas", report.frameworks)
            self.assertTrue(any("RuntimeWeapon" in Path(source.restored_path).read_text(encoding="utf-8") for source in report.recovered_sources))


if __name__ == "__main__":
    unittest.main()
