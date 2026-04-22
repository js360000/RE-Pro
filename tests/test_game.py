from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.game import GameNativeAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


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


if __name__ == "__main__":
    unittest.main()
