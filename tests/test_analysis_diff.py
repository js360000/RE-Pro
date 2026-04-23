from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.analysis_diff import compare_analysis_runs


class AnalysisDiffTests(unittest.TestCase):
    def test_compare_analysis_runs_writes_diff_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_run = root / "base"
            head_run = root / "head"
            diff_dir = root / "diff"
            base_run.mkdir()
            head_run.mkdir()

            (base_run / "report.json").write_text(
                json.dumps(
                    {
                        "target": "base.exe",
                        "frameworks": ["Electron"],
                        "findings": [{"title": "Base finding"}],
                        "artifacts": [{"path": "a.txt", "category": "report", "description": "A"}],
                        "recovered_sources": [{"original_path": "src/a.ts", "restored_path": "out/a.ts"}],
                    }
                ),
                encoding="utf-8",
            )
            (head_run / "report.json").write_text(
                json.dumps(
                    {
                        "target": "head.exe",
                        "frameworks": ["Electron", "Tauri"],
                        "findings": [{"title": "Base finding"}, {"title": "New finding"}],
                        "artifacts": [
                            {"path": "a.txt", "category": "report", "description": "A"},
                            {"path": "b.txt", "category": "report", "description": "B"},
                        ],
                        "recovered_sources": [
                            {"original_path": "src/a.ts", "restored_path": "out/a.ts"},
                            {"original_path": "src/b.ts", "restored_path": "out/b.ts"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (base_run / "analysis_index.json").write_text(
                json.dumps(
                    {
                        "entities": [{"kind": "framework", "key": "electron", "label": "Electron"}],
                        "relations": [],
                    }
                ),
                encoding="utf-8",
            )
            (head_run / "analysis_index.json").write_text(
                json.dumps(
                    {
                        "entities": [
                            {"kind": "framework", "key": "electron", "label": "Electron"},
                            {"kind": "framework", "key": "tauri", "label": "Tauri"},
                        ],
                        "relations": [{"source": "target:head.exe", "predicate": "matches_framework", "target": "framework:tauri"}],
                    }
                ),
                encoding="utf-8",
            )

            diff = compare_analysis_runs(base_run, head_run, diff_dir)

            self.assertIn("Tauri", diff["frameworks"]["added"])
            self.assertIn("src/b.ts", diff["recovered_sources"]["added"])
            self.assertTrue((diff_dir / "analysis_diff.json").exists())
            self.assertTrue((diff_dir / "analysis_diff.md").exists())


if __name__ == "__main__":
    unittest.main()
