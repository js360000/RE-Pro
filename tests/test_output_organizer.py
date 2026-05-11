from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.models import AnalysisReport, OutputSettings
from re_pro.output_organizer import organize_output_view
from tests import _path_setup  # noqa: F401


class OutputOrganizerTests(unittest.TestCase):
    def test_reference_view_groups_selected_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            source = run_dir / "recovered_sources" / "Widget.cpp"
            source.parent.mkdir()
            source.write_text("void Widget::Render() {}\n", encoding="utf-8")
            quality = run_dir / "usability" / "recovery_quality.json"
            quality.parent.mkdir()
            quality.write_text("{}", encoding="utf-8")
            quality_md = run_dir / "usability" / "recovery_quality.md"
            quality_md.write_text("# Quality\n", encoding="utf-8")
            log = run_dir / "ghidra.log"
            log.write_text("tool output\n", encoding="utf-8")
            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(run_dir))
            report.add_recovered_source("src/Widget.cpp", str(source), "")
            report.add_artifact(str(quality), "manifest", "Recovery quality manifest")
            report.add_artifact(str(quality_md), "report", "Recovery quality dashboard")
            report.add_artifact(str(log), "log", "Ghidra verbose log")

            result = organize_output_view(
                report,
                run_dir,
                OutputSettings(
                    enabled=True,
                    profile="custom",
                    include=["recovered_sources", "usability"],
                    view_name="clean_view",
                    folder_map={"recovered_sources": "src/recovered"},
                ),
            )

            self.assertIsNotNone(result)
            manifest_path = Path(result["manifest_path"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["profile"], "custom")
            self.assertEqual(manifest["entry_count"], 3)
            self.assertIn("recovered_sources", manifest["bucket_summaries"])
            self.assertEqual(manifest["bucket_summaries"]["usability"]["entry_count"], 2)
            self.assertTrue((run_dir / "clean_view" / "src" / "recovered" / "index.md").exists())
            self.assertFalse((run_dir / "clean_view" / "14_logs").exists())
            link_files = list((run_dir / "clean_view").rglob("*.repro-link.json"))
            self.assertEqual(len(link_files), 3)

    def test_copy_view_materializes_small_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            report_path = run_dir / "report.md"
            report_path.write_text("# Report\n", encoding="utf-8")
            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(run_dir))
            report.add_artifact(str(report_path), "report", "Human-readable markdown report")

            result = organize_output_view(
                report,
                run_dir,
                OutputSettings(enabled=True, profile="minimal", mode="copy", view_name="copy_view", max_copy_bytes=1024),
            )

            self.assertIsNotNone(result)
            manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["copied_bytes"], report_path.stat().st_size)
            copied_paths = [entry.get("copied_path") for entry in manifest["entries"]]
            self.assertTrue(any(path and Path(path).exists() for path in copied_paths))


if __name__ == "__main__":
    unittest.main()
