from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine
from re_pro.models import OutputSettings


class EngineTests(unittest.TestCase):
    def test_plain_text_file_does_not_trigger_binary_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text(
                "This document mentions electron, PyInstaller, Nuitka, and Rust, but it is not an executable.",
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(target)

            self.assertEqual(report.frameworks, [])
            self.assertEqual(report.findings, [])

    def test_engine_can_emit_curated_output_view(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text("plain text\n", encoding="utf-8")
            engine = ReverseEngineeringEngine(
                output_root=root / "out",
                output_settings=OutputSettings(enabled=True, profile="minimal", view_name="clean_view"),
            )

            report = engine.analyze(target)

            output_dir = Path(report.output_dir)
            self.assertTrue((output_dir / "clean_view" / "output_view_manifest.json").exists())
            self.assertTrue(any(artifact.description == "Output view manifest" for artifact in report.artifacts))
            self.assertTrue(any("Curated output view generated" in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
