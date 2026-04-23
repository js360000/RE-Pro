from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine


class PluginLoadingTests(unittest.TestCase):
    def test_engine_loads_local_plugin_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            plugin_path = plugin_dir / "demo_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    from re_pro.analyzers.base import Analyzer


                    class DemoPluginAnalyzer(Analyzer):
                        name = "Demo plugin analyzer"

                        def analyze(self, context, report) -> None:
                            report.add_framework("Plugin Framework")
                            report.add_note("Plugin analyzer executed.")


                    def register_analyzers():
                        return [DemoPluginAnalyzer()]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            target = root / "notes.txt"
            target.write_text("plain text target", encoding="utf-8")
            engine = ReverseEngineeringEngine(output_root=root / "out", plugin_dirs=[plugin_dir])

            report = engine.analyze(target)

            self.assertIn("Plugin Framework", report.frameworks)
            self.assertTrue(any(note == "Plugin analyzer executed." for note in report.notes))
            manifest_artifact = next(
                artifact
                for artifact in report.artifacts
                if artifact.description == "Analysis pipeline manifest"
            )
            manifest = json.loads(Path(manifest_artifact.path).read_text(encoding="utf-8"))
            self.assertTrue(any(item["name"] == "Demo plugin analyzer" for item in manifest["analyzers"]))
            self.assertIn(str(plugin_dir.resolve()), manifest["plugin_dirs"])


if __name__ == "__main__":
    unittest.main()
