from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.models import AnalysisReport
from re_pro.recovery_insights import write_recovery_insights
from tests import _path_setup  # noqa: F401


class RecoveryInsightTests(unittest.TestCase):
    def test_recovery_insights_emit_quality_graph_and_stub_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "run"
            source_dir = output_dir / "recovered_sources"
            source_dir.mkdir(parents=True)
            restored = source_dir / "Widget.cpp"
            restored.write_text(
                "// Pseudo-source synthesized from MSVC RTTI / vftable recovery.\n"
                "void Widget::vf_140001000() { }\n",
                encoding="utf-8",
            )
            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(output_dir), target_type="portable-executable")
            report.add_recovered_source("msvc_rtti::Widget.cpp", str(restored), "")
            analysis_index = {
                "summary": {"entity_counts": {"function": 2, "class": 1, "string": 1}, "relation_count": 2},
                "entities": [
                    {
                        "kind": "function",
                        "key": "ghidra:0x140001000",
                        "label": "sub_140001000",
                        "attributes": {"tool": "ghidra", "address": "0x140001000", "decompile_success": False},
                    },
                    {
                        "kind": "function",
                        "key": "class_context:0x140001020",
                        "label": "Widget::Render",
                        "attributes": {"tool": "class_context", "address": "0x140001020", "class_name": "Widget"},
                    },
                    {"kind": "class", "key": "msvc_rtti:widget", "label": "Widget", "attributes": {}},
                ],
                "relations": [
                    {"source": "class:msvc_rtti:widget", "predicate": "declares_method_candidate", "target": "function:ghidra:0x140001000"},
                    {"source": "class:msvc_rtti:widget", "predicate": "declares_method_candidate", "target": "function:class_context:0x140001020"},
                ],
            }

            artifacts = write_recovery_insights(report, analysis_index, output_dir)

            descriptions = {artifact.description for artifact in artifacts}
            self.assertIn("Recovery quality manifest", descriptions)
            self.assertIn("Evidence graph manifest", descriptions)
            self.assertIn("Evidence graph browser", descriptions)
            self.assertIn("Stub elimination queue", descriptions)
            self.assertIn("Function evidence page manifest", descriptions)
            queue_path = next(artifact.path for artifact in artifacts if artifact.description == "Stub elimination queue")
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(queue["summary"]["target_count"], 2)
            self.assertTrue(any(target["kind"] == "function" for target in queue["targets"]))
            quality_path = next(artifact.path for artifact in artifacts if artifact.description == "Recovery quality manifest")
            quality = json.loads(quality_path.read_text(encoding="utf-8"))
            self.assertEqual(quality["summary"]["function_count"], 2)
            self.assertGreater(quality["summary"]["stub_target_count"], 0)
            self.assertGreater(quality["summary"]["function_evidence_page_count"], 0)
            pages_path = next(artifact.path for artifact in artifacts if artifact.description == "Function evidence page manifest")
            pages = json.loads(pages_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(pages["summary"]["page_count"], 1)
            first_page = Path(pages["pages"][0]["path"])
            self.assertTrue(first_page.exists())
            self.assertIn("# Function Evidence", first_page.read_text(encoding="utf-8"))
            self.assertIn("file:///", pages["pages"][0]["file_url"])
            graph_html_path = next(artifact.path for artifact in artifacts if artifact.description == "Evidence graph browser")
            graph_html = graph_html_path.read_text(encoding="utf-8")
            self.assertIn("RE-Pro Evidence Graph", graph_html)
            self.assertIn("functionPages", graph_html)


if __name__ == "__main__":
    unittest.main()
