from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.analyzers.porting import PortingAdvisorAnalyzer, generate_architecture_port_from_run
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport, PortingSettings
from tests import _path_setup  # noqa: F401


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

    def test_architecture_port_workspace_is_generated_for_arm64(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            recovered = output_dir / "recovered_sources" / "native" / "widget.cpp"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text(
                "#include <immintrin.h>\nuintptr_t widget = 0;\nvoid f(){ __asm nop }\n",
                encoding="utf-8",
            )

            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(output_dir))
            report.target_type = "portable-executable"
            report.add_framework("Native C/C++")
            report.add_recovered_source("native/widget.cpp", str(recovered), "")
            context = AnalysisContext(
                target=root / "sample.exe",
                output_dir=output_dir,
                porting_settings=PortingSettings(enabled=True, source_arch="x86_64", target_arch="arm64", mode="hybrid"),
            )

            PortingAdvisorAnalyzer().analyze(context, report)

            port_root = output_dir / "porting" / "architecture_ports" / "x86_64_to_arm64"
            manifest_path = port_root / "ARCH_PORT_MANIFEST.json"
            plan_path = port_root / "ARCHITECTURE_PORTING_PLAN.md"
            header_path = port_root / "include" / "repro_arch_port.h"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertTrue(manifest_path.exists())
            self.assertTrue(plan_path.exists())
            self.assertTrue(header_path.exists())
            self.assertEqual(manifest["source_arch"], "x86_64")
            self.assertEqual(manifest["target_arch"], "arm64")
            self.assertEqual(manifest["source_inventory"]["code_files"], 1)
            self.assertGreaterEqual(manifest["blocker_summary"]["by_kind"]["x86_simd_intrinsics"], 1)
            self.assertGreaterEqual(len(manifest["blockers"]), 2)
            self.assertTrue(any("Architecture-targeted source port workspace" == artifact.description for artifact in report.artifacts))

    def test_architecture_port_can_be_generated_from_existing_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "existing_run"
            recovered = run_dir / "recovered_sources" / "native" / "main.cpp"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text("uintptr_t state = 0;\n", encoding="utf-8")

            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(run_dir))
            report.target_type = "portable-executable"
            report.add_framework("Native C/C++")
            report.add_recovered_source("native/main.cpp", str(recovered), "")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            result = generate_architecture_port_from_run(
                run_dir,
                source_arch="x86_64",
                target_arch="arm64",
                mode="heuristic",
            )
            updated_report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))

            self.assertTrue(result["ok"])
            self.assertTrue(result["architecture_ports"])
            self.assertTrue(Path(result["architecture_ports"][0]["workspace_root"]).exists())
            self.assertTrue(any("Architecture port manifest" == artifact["description"] for artifact in updated_report["artifacts"]))

    def test_multiple_architecture_ports_are_preserved_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "existing_run"
            recovered = run_dir / "recovered_sources" / "native" / "main.cpp"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text("uintptr_t state = 0;\n", encoding="utf-8")
            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(run_dir))
            report.target_type = "portable-executable"
            report.fingerprints["machine"] = "x64"
            report.add_framework("Native C/C++")
            report.add_recovered_source("native/main.cpp", str(recovered), "")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            generate_architecture_port_from_run(run_dir, target_arch="arm64", mode="heuristic")
            result = generate_architecture_port_from_run(run_dir, target_arch="riscv64", mode="heuristic")
            ports = result["architecture_ports"]
            keys = {(port["source_arch"], port["target_arch"]) for port in ports}

            self.assertIn(("x86_64", "arm64"), keys)
            self.assertIn(("x86_64", "riscv64"), keys)
            self.assertEqual(len(keys), 2)


if __name__ == "__main__":
    unittest.main()
