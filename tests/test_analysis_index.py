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

    def test_analysis_index_ingests_msvc_rtti_class_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin_dir = root / "plugins"
            plugin_dir.mkdir()
            plugin_path = plugin_dir / "rtti_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    import json
                    from re_pro.analyzers.base import Analyzer


                    class RTTIPluginAnalyzer(Analyzer):
                        name = "RTTI plugin analyzer"

                        def analyze(self, context, report) -> None:
                            native_dir = context.output_dir / "native"
                            native_dir.mkdir(parents=True, exist_ok=True)
                            manifest_path = native_dir / "msvc_rtti_classes.json"
                            manifest_path.write_text(json.dumps({
                                "class_count": 1,
                                "vtable_count": 1,
                                "classes": [
                                    {
                                        "name": "Foo",
                                        "kind": "class",
                                        "mangled_name": ".?AVFoo@@",
                                        "type_descriptor_rva": "0x2000",
                                        "estimated_object_size": 40,
                                        "layout_strategy": "constructor_first_evidence_order",
                                        "layout_sources": ["constructor", "method"],
                                        "base_classes": ["Base"],
                                        "members": [
                                            {
                                                "name": "name_",
                                                "type": "std::string",
                                                "estimated_offset": 8,
                                                "estimated_size": 32,
                                                "layout_index": 0,
                                                "layout_confidence": "high",
                                                "layout_basis": "constructor_first_evidence_order",
                                                "primary_provenance": {
                                                    "source_kind": "constructor",
                                                    "source_function": "Foo",
                                                    "reason": "std_string_member_usage",
                                                    "statement": "std::basic_string<char>::basic_string(&this->name_);",
                                                },
                                                "layout_provenance": [
                                                    {
                                                        "source_kind": "constructor",
                                                        "source_function": "Foo",
                                                        "reason": "std_string_member_usage",
                                                        "statement": "std::basic_string<char>::basic_string(&this->name_);",
                                                    }
                                                ],
                                            }
                                        ],
                                        "vtables": [
                                            {
                                                "rva": "0x2128",
                                                "address": "0x140002128",
                                                "method_count": 1
                                            }
                                        ],
                                        "methods": [
                                            {
                                                "name": "vf_140001000",
                                                "display_name": "__scalar_deleting_destructor",
                                                "qualified_name": "Foo::__scalar_deleting_destructor",
                                                "method_kind": "scalar_deleting_destructor",
                                                "semantic_alias": "~Foo",
                                                "return_type": "void",
                                                "params": [{"type": "uint", "name": "flags"}],
                                                "slot": 0,
                                                "address": "0x140001000",
                                                "rva": "0x1000",
                                                "vtable_rva": "0x2128"
                                            }
                                        ]
                                    }
                                ]
                            }, indent=2), encoding="utf-8")
                            report.add_artifact(str(manifest_path), "json", "Ghidra enriched class manifest")

                            ghidra_dir = context.output_dir / "ghidra" / "exports"
                            ghidra_dir.mkdir(parents=True, exist_ok=True)
                            ghidra_functions = ghidra_dir / "functions.json"
                            ghidra_targeted = ghidra_dir / "targeted_decompilation.json"
                            ghidra_callgraph = ghidra_dir / "class_callgraph_manifest.json"
                            ghidra_functions.write_text(json.dumps([
                                {"name": "sub_140001000", "entry_point": "140001000", "signature": "undefined8 sub_140001000(void)"}
                            ]), encoding="utf-8")
                            ghidra_targeted.write_text(json.dumps([
                                {
                                    "requested_address": "0x140001000",
                                    "entry_point": "0x140001000",
                                    "name": "sub_140001000",
                                    "signature": "undefined8 sub_140001000(void)",
                                    "return_type": "undefined8",
                                    "parameters": [
                                        {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                                        {"ordinal": 1, "name": "flags", "data_type": "uint", "storage": "RDX"}
                                    ],
                                    "caller_count": 1,
                                    "callers": [
                                        {"caller_name": "main", "caller_entry_point": "0x140000100", "from_address": "0x140000188", "ref_type": "UNCONDITIONAL_CALL"}
                                    ],
                                    "callee_count": 1,
                                    "callees": [
                                        {"name": "puts", "entry_point": "0x140002000", "from_address": "0x140001020", "ref_type": "UNCONDITIONAL_CALL"}
                                    ],
                                    "decompile_success": True,
                                    "decompiled_c": "undefined8 sub_140001000(void) { return 1; }"
                                }
                            ]), encoding="utf-8")
                            ghidra_callgraph.write_text(json.dumps({
                                "artifact_type": "ghidra_class_callgraph_manifest",
                                "class_count": 1,
                                "function_count": 1,
                                "classes": [
                                    {
                                        "name": "Foo",
                                        "estimated_object_size": 40,
                                        "methods": [
                                            {
                                                "class_name": "Foo",
                                                "name": "__scalar_deleting_destructor",
                                                "qualified_name": "Foo::__scalar_deleting_destructor",
                                                "address": "0x140001000",
                                                "slot": 0,
                                                "vtable_rva": "0x2128",
                                                "method_kind": "scalar_deleting_destructor",
                                                "semantic_alias": "~Foo",
                                                "decompiler": {"tool": "ghidra", "success": True, "name": "sub_140001000"},
                                                "callers": [
                                                    {"caller_name": "main", "caller_entry_point": "0x140000100", "from_address": "0x140000188"}
                                                ],
                                                "callees": [
                                                    {"name": "puts", "entry_point": "0x140002000", "from_address": "0x140001020"}
                                                ],
                                                "call_edges": [
                                                    {"target": "puts", "target_address": "0x140002000"}
                                                ],
                                                "llm_priority": 95,
                                                "evidence": ["msvc_rtti_vtable", "ghidra_decompiled_body", "ghidra_call_edges"]
                                            }
                                        ]
                                    }
                                ]
                            }, indent=2), encoding="utf-8")
                            report.add_artifact(str(ghidra_functions), "json", "Ghidra function export")
                            report.add_artifact(str(ghidra_targeted), "json", "Ghidra targeted pseudo-code export")
                            report.add_artifact(str(ghidra_callgraph), "json", "Ghidra class callgraph manifest")


                    def register_analyzers():
                        return [RTTIPluginAnalyzer()]
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

            class_id = "class:msvc_rtti:foo"
            base_id = "class:msvc_rtti:base"
            method_id = "function:msvc_rtti:0x140001000"
            ghidra_method_id = "function:ghidra:0x140001000"
            context_method_id = "function:class_context:0x140001000"
            context_callee_id = "function:class_context:0x140002000"
            context_class_id = "class:class_context:foo"
            vtable_id = "vtable:msvc_rtti:0x2128"
            field_id = "field:msvc_rtti:foo::name_"

            self.assertIn(class_id, entities)
            self.assertIn(base_id, entities)
            self.assertIn(method_id, entities)
            self.assertIn(vtable_id, entities)
            self.assertIn(field_id, entities)
            self.assertIn(context_class_id, entities)
            self.assertIn(context_method_id, entities)
            self.assertIn(context_callee_id, entities)
            self.assertIn((class_id, "inherits_from", base_id), relations)
            self.assertIn((class_id, "owns_vtable", vtable_id), relations)
            self.assertIn((class_id, "declares_method_candidate", method_id), relations)
            self.assertIn((class_id, "declares_field_candidate", field_id), relations)
            self.assertIn((context_class_id, "declares_contextualized_method", context_method_id), relations)
            self.assertIn((context_method_id, "calls", context_callee_id), relations)
            self.assertIn((method_id, "correlates_with", ghidra_method_id), relations)
            self.assertIn((method_id, "correlates_with", context_method_id), relations)
            self.assertEqual(entities[method_id]["label"], "Foo::__scalar_deleting_destructor")
            self.assertEqual(entities[method_id]["attributes"].get("semantic_alias"), "~Foo")
            self.assertEqual(entities[class_id]["attributes"].get("estimated_object_size"), 40)
            self.assertEqual(entities[class_id]["attributes"].get("layout_strategy"), "constructor_first_evidence_order")
            self.assertEqual(entities[field_id]["attributes"].get("estimated_offset"), 8)
            self.assertEqual(entities[field_id]["attributes"].get("layout_confidence"), "high")
            self.assertEqual(
                entities[field_id]["attributes"].get("primary_provenance", {}).get("source_function"),
                "Foo",
            )
            self.assertEqual(
                entities[ghidra_method_id]["attributes"].get("decompiled_c"),
                "undefined8 sub_140001000(void) { return 1; }",
            )
            self.assertEqual(entities[ghidra_method_id]["attributes"].get("caller_count"), 1)
            self.assertEqual(entities[ghidra_method_id]["attributes"].get("callee_count"), 1)
            self.assertEqual(entities[ghidra_method_id]["attributes"].get("return_type"), "undefined8")
            self.assertEqual(entities[context_method_id]["attributes"].get("llm_priority"), 95)


if __name__ == "__main__":
    unittest.main()
