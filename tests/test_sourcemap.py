from __future__ import annotations

import json
import base64
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.sourcemap import restore_inline_source_maps_from_file
from re_pro.sourcemap import restore_sources_from_map


class SourceMapTests(unittest.TestCase):
    def test_restore_sources_from_map_writes_original_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            map_path = root / "bundle.js.map"
            output_root = root / "out"
            map_path.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "bundle.js",
                        "sources": ["webpack://src/index.ts", "webpack://src/util/math.ts"],
                        "sourcesContent": ["console.log('hi');", "export const add = () => 1;"],
                    }
                ),
                encoding="utf-8",
            )

            recovered, notes = restore_sources_from_map(map_path, output_root)

            self.assertEqual(notes, [])
            self.assertEqual(len(recovered), 2)
            restored_paths = [Path(item.restored_path) for item in recovered]
            self.assertTrue(all(path.exists() for path in restored_paths))
            self.assertTrue(any(path.as_posix().endswith("bundle.js/src/index.ts") for path in restored_paths))

    def test_restore_sources_from_map_reads_neighbor_sources_without_sources_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "index.ts").write_text("export const fromDisk = true;\n", encoding="utf-8")
            map_path = root / "bundle.js.map"
            output_root = root / "out"
            map_path.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "bundle.js",
                        "sources": ["webpack://src/index.ts"],
                    }
                ),
                encoding="utf-8",
            )

            recovered, notes = restore_sources_from_map(map_path, output_root)

            self.assertEqual(notes, [])
            self.assertEqual(len(recovered), 1)
            restored = Path(recovered[0].restored_path)
            self.assertEqual(restored.read_text(encoding="utf-8"), "export const fromDisk = true;\n")

    def test_restore_inline_source_maps_from_file_writes_original_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_path = root / "style.css"
            output_root = root / "out"
            payload = {
                "version": 3,
                "file": "style.css",
                "sources": ["src/style.scss"],
                "sourcesContent": ["$color: red;\nbody { color: $color; }\n"],
            }
            encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
            source_path.write_text(f"body{{color:red}}\n/*# sourceMappingURL=data:application/json;base64,{encoded} */", encoding="utf-8")

            recovered, notes = restore_inline_source_maps_from_file(source_path, output_root)

            self.assertEqual(notes, [])
            self.assertEqual(len(recovered), 1)
            restored = Path(recovered[0].restored_path)
            self.assertEqual(restored.read_text(encoding="utf-8"), "$color: red;\nbody { color: $color; }\n")


if __name__ == "__main__":
    unittest.main()
