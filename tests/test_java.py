from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.java import JavaPackageAnalyzer
from re_pro.engine import AnalysisContext, ReverseEngineeringEngine
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class JavaAnalyzerTests(unittest.TestCase):
    def test_jar_analysis_extracts_manifest_and_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            jar_path = root / "demo.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMain-Class: com.example.Main\nImplementation-Title: Demo App\nImplementation-Version: 1.2.3\n",
                )
                archive.writestr("META-INF/demo.kotlin_module", b"\x00")
                archive.writestr("BOOT-INF/classes/com/example/Main.class", b"\xca\xfe\xba\xbe")
                archive.writestr(
                    "BOOT-INF/classes/static/app.js.map",
                    json.dumps(
                        {
                            "version": 3,
                            "file": "app.js",
                            "sources": ["src/app.ts"],
                            "sourcesContent": ["export const answer = 42;\n"],
                        }
                    ),
                )

            engine = ReverseEngineeringEngine(output_root=root / "out")
            report = engine.analyze(jar_path)

            self.assertEqual(report.target_type, "java-archive")
            self.assertIn("Java Archive (JAR)", report.frameworks)
            self.assertIn("Java framework: Spring Boot", report.frameworks)
            self.assertIn("Java language: Kotlin", report.frameworks)
            self.assertTrue(any("Java main class: com.example.Main" in note for note in report.notes))
            self.assertGreaterEqual(len(report.recovered_sources), 1)

            index_artifact = next(artifact for artifact in report.artifacts if artifact.description == "Unified analysis index")
            payload = json.loads(Path(index_artifact.path).read_text(encoding="utf-8"))
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in payload["entities"]}
            self.assertIn("format:java-archive:demo.jar", entity_ids)
            self.assertTrue(
                any(entity["kind"] == "java_class" and entity["label"] == "Main" for entity in payload["entities"])
            )

    def test_jar_external_jadx_runs_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            jar_path = root / "demo.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.example.Main\n")
                archive.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")

            report = AnalysisReport(target=str(jar_path), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=jar_path,
                output_dir=root / "out",
                run_external_tools=True,
            )

            def fake_run_command(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                output_dir = context.output_dir / "jadx_java" / "sources" / "com" / "example"
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "Main.java").write_text("class Main {}", encoding="utf-8")
                return 0, "jadx", ""

            with patch("re_pro.analyzers.java.resolve_command", return_value=[str(root / "tools" / "jadx" / "bin" / "jadx.bat")]):
                with patch("re_pro.analyzers.java.run_command_logged", side_effect=fake_run_command):
                    JavaPackageAnalyzer().analyze(context, report)

            self.assertTrue(any(finding.title == "jadx Java archive decompilation succeeded" for finding in report.findings))
            self.assertTrue(any(artifact.description == "jadx decompiled Java archive sources" for artifact in report.artifacts))


if __name__ == "__main__":
    unittest.main()
