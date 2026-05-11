from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from re_pro.index_workflows import build_entity_workflow
from tests import _path_setup  # noqa: F401


class IndexWorkflowTests(unittest.TestCase):
    def test_function_workflow_exposes_artifact_and_porting_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            ghidra_functions = run_dir / "ghidra" / "exports" / "functions.json"
            ghidra_functions.parent.mkdir(parents=True, exist_ok=True)
            ghidra_functions.write_text("[]", encoding="utf-8")
            recovered = run_dir / "recovered_sources" / "src" / "main.ts"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text("export const app = true;\n", encoding="utf-8")
            porting_notes = run_dir / "porting" / "PORTING_NOTES.md"
            porting_notes.parent.mkdir(parents=True, exist_ok=True)
            porting_notes.write_text("# Porting\n", encoding="utf-8")
            recompile_manifest = run_dir / "porting" / "recompile" / "workspace_manifest.json"
            recompile_manifest.parent.mkdir(parents=True, exist_ok=True)
            recompile_manifest.write_text("{}", encoding="utf-8")
            recompile_dir = recompile_manifest.parent

            report = {
                "target": str(root / "sample.exe"),
                "frameworks": ["Electron", "Index Test Framework"],
                "artifacts": [
                    {"path": str(ghidra_functions), "category": "json", "description": "Ghidra function export"},
                    {"path": str(porting_notes), "category": "report", "description": "Porting guidance"},
                    {"path": str(recompile_dir), "category": "directory", "description": "Recompile workspace"},
                    {"path": str(recompile_manifest), "category": "manifest", "description": "Recompile workspace manifest"},
                ],
                "recovered_sources": [
                    {
                        "original_path": "src/main.ts",
                        "restored_path": str(recovered),
                        "source_map": str(run_dir / "bundle.js.map"),
                    }
                ],
            }
            analysis_index = {
                "entities": [
                    {"kind": "function", "key": "ghidra:0x401000", "label": "entry", "attributes": {"tool": "ghidra"}},
                    {
                        "kind": "artifact",
                        "key": str(ghidra_functions),
                        "label": "functions.json",
                        "attributes": {"path": str(ghidra_functions), "category": "json"},
                    },
                    {
                        "kind": "recovered_source",
                        "key": str(recovered),
                        "label": "src/main.ts",
                        "attributes": {"restored_path": str(recovered), "original_path": "src/main.ts"},
                    },
                    {"kind": "framework", "key": "electron", "label": "Electron", "attributes": {}},
                ],
                "relations": [
                    {
                        "source": "function:ghidra:0x401000",
                        "predicate": "originates_from_artifact",
                        "target": f"artifact:{ghidra_functions}",
                        "attributes": {"tool": "ghidra"},
                    },
                    {
                        "source": "function:ghidra:0x401000",
                        "predicate": "matches_framework",
                        "target": "framework:electron",
                        "attributes": {},
                    },
                    {
                        "source": "function:ghidra:0x401000",
                        "predicate": "references_recovered_source",
                        "target": f"recovered_source:{recovered}",
                        "attributes": {},
                    },
                ],
            }

            workflow = build_entity_workflow(report, analysis_index, "function:ghidra:0x401000")

            self.assertEqual(workflow["entity"]["label"], "entry")
            self.assertEqual(workflow["artifact_candidates"][0]["path"], str(ghidra_functions))
            self.assertEqual(workflow["recovered_sources"][0]["restored_path"], str(recovered))
            self.assertEqual(workflow["action_targets"]["porting_notes_path"], str(porting_notes))
            self.assertEqual(workflow["action_targets"]["recompile_workspace_path"], str(recompile_dir))
            self.assertIn("inspect the originating export artifact", workflow["workflow_summary"])


if __name__ == "__main__":
    unittest.main()
