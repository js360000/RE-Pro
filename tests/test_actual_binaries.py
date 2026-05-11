from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.analyzers.porting import generate_architecture_port_from_run
from re_pro.engine import ReverseEngineeringEngine
from re_pro.models import PortingSettings
from tests import _path_setup  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[1]
MSVC_RTTI_FIXTURE_EXE = REPO_ROOT / "samples" / "fixtures" / "msvc_rtti_demo" / "build" / "x64" / "msvc_rtti_demo.exe"


@unittest.skipUnless(
    MSVC_RTTI_FIXTURE_EXE.exists(),
    "actual MSVC RTTI fixture binary is not built; run samples/fixtures/build_msvc_fixture.ps1",
)
class ActualBinaryIntegrationTests(unittest.TestCase):
    def test_actual_msvc_binary_recovers_rtti_sources_and_architecture_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = ReverseEngineeringEngine(
                output_root=Path(temp_dir),
                porting_settings=PortingSettings(enabled=True, target_arch="arm64"),
            ).analyze(MSVC_RTTI_FIXTURE_EXE)
            run_dir = Path(report.output_dir)

            self.assertEqual(report.target, str(MSVC_RTTI_FIXTURE_EXE.resolve()))
            self.assertIn("Portable Executable (PE)", report.frameworks)
            self.assertIn("MSVC RTTI", report.frameworks)
            self.assertTrue(any(finding.title == "PDB file recovered" for finding in report.findings))
            self.assertTrue(any(source.original_path == "msvc_rtti::Fixture::AppController.hpp" for source in report.recovered_sources))
            self.assertTrue(any(source.original_path == "msvc_rtti::Fixture::AppController.cpp" for source in report.recovered_sources))

            class_manifest = run_dir / "native" / "msvc_rtti_classes.json"
            self.assertTrue(class_manifest.exists(), f"missing {class_manifest}")
            class_payload = json.loads(class_manifest.read_text(encoding="utf-8"))
            class_names = {str(entry.get("name")) for entry in class_payload.get("classes") or []}
            self.assertIn("Fixture::AppController", class_names)
            self.assertIn("Fixture::ConsoleLogger", class_names)

            arch_manifest_path = run_dir / "porting" / "architecture_ports" / "x86_64_to_arm64" / "ARCH_PORT_MANIFEST.json"
            self.assertTrue(arch_manifest_path.exists(), f"missing {arch_manifest_path}")
            arch_manifest = json.loads(arch_manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(arch_manifest["source_arch"], "x86_64")
            self.assertEqual(arch_manifest["target_arch"], "arm64")
            self.assertGreaterEqual(arch_manifest["source_inventory"]["code_files"], 8)
            recovered_source_dir = run_dir / "porting" / "architecture_ports" / "x86_64_to_arm64" / "source" / "recovered_sources"
            self.assertTrue((recovered_source_dir / "msvc_rtti_Fixture_AppController.hpp").exists())
            self.assertTrue((recovered_source_dir / "msvc_rtti_Fixture_AppController.cpp").exists())

            post_run_result = generate_architecture_port_from_run(
                run_dir,
                source_arch="x86_64",
                target_arch="riscv64",
                mode="heuristic",
            )
            self.assertTrue(post_run_result["ok"])
            port_pairs = {
                (str(entry.get("source_arch")), str(entry.get("target_arch")))
                for entry in post_run_result.get("architecture_ports") or []
            }
            self.assertIn(("x86_64", "arm64"), port_pairs)
            self.assertIn(("x86_64", "riscv64"), port_pairs)

            saved_report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
            saved_artifacts = {str(artifact.get("description")) for artifact in saved_report.get("artifacts") or []}
            self.assertIn("Architecture port manifest", saved_artifacts)
            self.assertIn("Pseudo-C++ classes recovered from MSVC RTTI", saved_artifacts)
