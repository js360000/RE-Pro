from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine


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


if __name__ == "__main__":
    unittest.main()
