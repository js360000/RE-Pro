from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.json_schemas import (
    SchemaError,
    load_analysis_index,
    load_browser_manifest,
    load_edits,
    load_json_object,
    load_report,
)
from tests import _path_setup as _path_setup  # noqa: F401


def _write(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class JsonSchemasTests(unittest.TestCase):
    def test_load_json_object_rejects_non_object_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "list.json", [1, 2, 3])
            with self.assertRaises(SchemaError) as ctx:
                load_json_object(path)
            self.assertIn("expected a JSON object", str(ctx.exception))

    def test_load_json_object_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(SchemaError) as ctx:
                load_json_object(path)
            self.assertIn("invalid JSON", str(ctx.exception))

    def test_load_report_requires_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "report.json", {"frameworks": []})
            with self.assertRaises(SchemaError) as ctx:
                load_report(path)
            self.assertIn("missing required key", str(ctx.exception))
            self.assertIn("target", str(ctx.exception))

    def test_load_report_rejects_wrong_field_type(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(
                Path(temp_dir) / "report.json",
                {"target": "x", "frameworks": "not-a-list"},
            )
            with self.assertRaises(SchemaError) as ctx:
                load_report(path)
            self.assertIn("frameworks", str(ctx.exception))
            self.assertIn("list", str(ctx.exception))

    def test_load_report_accepts_minimal_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "report.json", {"target": "x"})
            payload = load_report(path)
            self.assertEqual(payload["target"], "x")

    def test_load_browser_manifest_requires_workspace_root_and_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "browser_manifest.json", {"nodes": []})
            with self.assertRaises(SchemaError):
                load_browser_manifest(path)

    def test_load_browser_manifest_accepts_valid_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(
                Path(temp_dir) / "browser_manifest.json",
                {"workspace_root": "/tmp/x", "nodes": []},
            )
            payload = load_browser_manifest(path)
            self.assertEqual(payload["workspace_root"], "/tmp/x")

    def test_load_edits_accepts_empty_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "edits.json", {})
            payload = load_edits(path)
            self.assertEqual(payload, {})

    def test_load_edits_rejects_non_list_edits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "edits.json", {"edits": "nope"})
            with self.assertRaises(SchemaError):
                load_edits(path)

    def test_load_analysis_index_requires_entities_and_relations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(Path(temp_dir) / "analysis_index.json", {"entities": []})
            with self.assertRaises(SchemaError):
                load_analysis_index(path)

    def test_load_analysis_index_accepts_minimal_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write(
                Path(temp_dir) / "analysis_index.json",
                {"entities": [], "relations": []},
            )
            payload = load_analysis_index(path)
            self.assertEqual(payload["entities"], [])


if __name__ == "__main__":
    unittest.main()
