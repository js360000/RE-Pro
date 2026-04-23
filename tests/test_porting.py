from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.porting import PortingAdvisorAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


class PortingAdvisorTests(unittest.TestCase):
    def test_porting_preparation_copies_sources_and_writes_notes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            recovered = output_dir / "recovered_sources" / "src" / "main.ts"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text("export const app = true;\n", encoding="utf-8")
            package_json = output_dir / "app.asar_extract" / "package.json"
            package_json.parent.mkdir(parents=True, exist_ok=True)
            package_json.write_text('{"name":"sample-app"}', encoding="utf-8")

            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(output_dir))
            report.target_type = "portable-executable"
            report.add_framework("Electron")
            report.add_artifact(str(package_json), "manifest", "Recovered package.json")
            report.add_recovered_source("src/main.ts", str(recovered), str(output_dir / "bundle.js.map"))
            context = AnalysisContext(target=root / "sample.exe", output_dir=output_dir)

            PortingAdvisorAnalyzer().analyze(context, report)

            manifest_path = output_dir / "porting" / "porting_manifest.json"
            notes_path = output_dir / "porting" / "PORTING_NOTES.md"
            copied_source = output_dir / "porting" / "prepared_sources" / "recovered_sources" / "main.ts"
            recompile_root = output_dir / "porting" / "recompile"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(notes_path.exists())
            self.assertTrue(copied_source.exists())
            self.assertTrue((recompile_root / "projects" / "node_app" / "package.json").exists())
            self.assertTrue((recompile_root / "rebuild_plan.json").exists())
            self.assertTrue((recompile_root / "signing_plan.json").exists())
            self.assertTrue((recompile_root / "patching" / "patch_plan.json").exists())
            self.assertTrue(any("Porting preparation generated" == finding.title for finding in report.findings))


if __name__ == "__main__":
    unittest.main()
