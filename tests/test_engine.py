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

    def test_output_rules_can_skip_matching_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text("plain text\n", encoding="utf-8")
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "noisy_plugin.py").write_text(
                """
from re_pro.analyzers.base import Analyzer

class NoisyAnalyzer(Analyzer):
    name = "Noisy Native Deep Pass"

    def analyze(self, context, report):
        marker = context.output_dir / "noisy.txt"
        marker.write_text("ran", encoding="utf-8")
        report.add_artifact(str(marker), "log", "Noisy analyzer marker")

ANALYZERS = [NoisyAnalyzer()]
""",
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(
                output_root=root / "out",
                plugin_dirs=[plugin_dir],
                output_settings=OutputSettings(analyzer_exclude=["noisy native"]),
            )

            report = engine.analyze(target)

            output_dir = Path(report.output_dir)
            self.assertFalse((output_dir / "noisy.txt").exists())
            manifest = (output_dir / "analysis_pipeline.json").read_text(encoding="utf-8")
            self.assertIn('"state": "skipped"', manifest)
            self.assertIn("matched analyzer exclude rules", manifest)

    def test_output_rules_budget_skips_later_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text("plain text\n", encoding="utf-8")
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "budget_plugin.py").write_text(
                """
from re_pro.analyzers.base import Analyzer

class BudgetWriter(Analyzer):
    name = "Budget Writer"

    def analyze(self, context, report):
        marker = context.output_dir / "fat.bin"
        marker.write_bytes(b"x" * (2 * 1024 * 1024))
        report.add_artifact(str(marker), "binary", "Budget writer marker")

class AfterBudget(Analyzer):
    name = "After Budget"

    def analyze(self, context, report):
        marker = context.output_dir / "after_budget.txt"
        marker.write_text("ran", encoding="utf-8")
        report.add_artifact(str(marker), "log", "After budget marker")

ANALYZERS = [BudgetWriter(), AfterBudget()]
""",
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(
                output_root=root / "out",
                plugin_dirs=[plugin_dir],
                output_settings=OutputSettings(max_run_artifact_bytes=1024 * 1024),
            )

            report = engine.analyze(target)

            output_dir = Path(report.output_dir)
            self.assertTrue((output_dir / "fat.bin").exists())
            self.assertFalse((output_dir / "after_budget.txt").exists())
            manifest = (output_dir / "analysis_pipeline.json").read_text(encoding="utf-8")
            self.assertIn("After Budget", manifest)
            self.assertIn("artifact byte budget reached", manifest)


if __name__ == "__main__":
    unittest.main()
