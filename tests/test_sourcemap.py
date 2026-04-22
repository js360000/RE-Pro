from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

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


if __name__ == "__main__":
    unittest.main()
