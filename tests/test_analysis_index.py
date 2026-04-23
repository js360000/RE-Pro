from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine


class AnalysisIndexTests(unittest.TestCase):
    def test_analysis_index_records_target_framework_and_artifact_relations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            plugin_path = plugin_dir / "index_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    from pathlib import Path
                    from re_pro.analyzers.base import Analyzer


                    class IndexPluginAnalyzer(Analyzer):
                        name = "Index plugin analyzer"

                        def analyze(self, context, report) -> None:
                            marker = context.output_dir / "plugin-marker.txt"
                            marker.write_text("plugin artifact", encoding="utf-8")
                            report.add_framework("Index Test Framework")
                            report.add_artifact(str(marker), "report", "Plugin marker artifact")


                    def register_analyzers():
                        return [IndexPluginAnalyzer()]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            target = root / "target.txt"
            target.write_text("not a binary", encoding="utf-8")
            engine = ReverseEngineeringEngine(output_root=root / "out", plugin_dirs=[plugin_dir])

            report = engine.analyze(target)

            index_artifact = next(
                artifact
                for artifact in report.artifacts
                if artifact.description == "Unified analysis index"
            )
            payload = json.loads(Path(index_artifact.path).read_text(encoding="utf-8"))
            entities = {
                f"{entity['kind']}:{entity['key']}": entity
                for entity in payload["entities"]
            }
            relations = {
                (relation["source"], relation["predicate"], relation["target"])
                for relation in payload["relations"]
            }

            target_id = f"target:{target.resolve()}"
            framework_id = "framework:index test framework"
            marker_path = Path(report.output_dir) / "plugin-marker.txt"
            artifact_id = f"artifact:{marker_path}"

            self.assertIn(target_id, entities)
            self.assertIn(framework_id, entities)
            self.assertIn(artifact_id, entities)
            self.assertIn((target_id, "matches_framework", framework_id), relations)
            self.assertIn((target_id, "produced_artifact", artifact_id), relations)
            self.assertGreaterEqual(payload["summary"]["entity_counts"]["artifact"], 1)

    def test_analysis_index_ingests_and_correlates_structured_tool_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            plugin_path = plugin_dir / "tool_exports_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    import json
                    from re_pro.analyzers.base import Analyzer


                    class ToolExportPluginAnalyzer(Analyzer):
                        name = "Tool export plugin analyzer"

                        def analyze(self, context, report) -> None:
                            ghidra_dir = context.output_dir / "ghidra" / "exports"
                            ghidra_dir.mkdir(parents=True, exist_ok=True)
                            ghidra_functions = ghidra_dir / "functions.json"
                            ghidra_strings = ghidra_dir / "strings.json"
                            ghidra_functions.write_text(json.dumps([
                                {"name": "entry", "entry_point": "01d0001c", "signature": "undefined entry(void)"}
                            ]), encoding="utf-8")
                            ghidra_strings.write_text(json.dumps([
                                {"address": "01d04fd8", "value": "Success", "length": 8, "source": "defined_string"}
                            ]), encoding="utf-8")
                            report.add_artifact(str(ghidra_functions), "json", "Ghidra function export")
                            report.add_artifact(str(ghidra_strings), "json", "Ghidra strings export")

                            rizin_dir = context.output_dir / "rizin"
                            rizin_dir.mkdir(parents=True, exist_ok=True)
                            rizin_functions = rizin_dir / "functions.json"
                            rizin_strings = rizin_dir / "strings.json"
                            rizin_functions.write_text(json.dumps([
                                {"name": "fcn.01d0001c", "offset": 30408732, "signature": "fcn.01d0001c();"}
                            ]), encoding="utf-8")
                            rizin_strings.write_text(json.dumps([
                                {"offset": 30429144, "value": "Success", "length": 8}
                            ]), encoding="utf-8")
                            report.add_artifact(str(rizin_functions), "json", "rizin function list")
                            report.add_artifact(str(rizin_strings), "json", "rizin strings export")


                    def register_analyzers():
                        return [ToolExportPluginAnalyzer()]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            target = root / "binary.bin"
            target.write_bytes(b"MZ")
            engine = ReverseEngineeringEngine(output_root=root / "out", plugin_dirs=[plugin_dir])

            report = engine.analyze(target)

            index_artifact = next(
                artifact
                for artifact in report.artifacts
                if artifact.description == "Unified analysis index"
            )
            payload = json.loads(Path(index_artifact.path).read_text(encoding="utf-8"))
            entities = {
                f"{entity['kind']}:{entity['key']}": entity
                for entity in payload["entities"]
            }
            relations = {
                (relation["source"], relation["predicate"], relation["target"])
                for relation in payload["relations"]
            }

            ghidra_function_id = "function:ghidra:0x1d0001c"
            rizin_function_id = "function:rizin:0x1d0001c"
            ghidra_string_id = "string:ghidra:0x1d04fd8"
            rizin_string_id = "string:rizin:0x1d04fd8"
            ghidra_functions_artifact_id = f"artifact:{Path(report.output_dir) / 'ghidra' / 'exports' / 'functions.json'}"
            ghidra_strings_artifact_id = f"artifact:{Path(report.output_dir) / 'ghidra' / 'exports' / 'strings.json'}"

            self.assertIn(ghidra_function_id, entities)
            self.assertIn(rizin_function_id, entities)
            self.assertIn(ghidra_string_id, entities)
            self.assertIn(rizin_string_id, entities)
            self.assertIn((ghidra_function_id, "correlates_with", rizin_function_id), relations)
            self.assertIn((ghidra_string_id, "correlates_with", rizin_string_id), relations)
            self.assertIn((ghidra_function_id, "originates_from_artifact", ghidra_functions_artifact_id), relations)
            self.assertIn((ghidra_string_id, "originates_from_artifact", ghidra_strings_artifact_id), relations)
            self.assertTrue(any("normalized 2 function candidate(s) and 2 string candidate(s)" in note for note in report.notes))
            self.assertTrue(any("Cross-tool correlation linked 1 function address match(es) and 1 string address match(es)." in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
