from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from re_pro.symbolic_source import extract_source_file_hints, extract_symbol_names, synthesize_symbolic_source_tree
from tests import _path_setup  # noqa: F401


class SymbolicSourceTests(unittest.TestCase):
    def test_extract_helpers_and_synthesize_from_source_hints(self) -> None:
        text = "public: void __cdecl Foo::Bar(void)\nC:\\src\\Foo.cpp\n"
        self.assertIn("C:/src/Foo.cpp", [value.replace("\\", "/") for value in extract_source_file_hints(text)])
        self.assertIn("Foo::Bar", extract_symbol_names(text))

        with tempfile.TemporaryDirectory() as temp_dir:
            generated = synthesize_symbolic_source_tree(
                Path(temp_dir),
                origin_label="test symbols",
                source_paths=["C:/src/Foo.cpp"],
                function_names=["Foo::Bar"],
            )
            self.assertEqual(len(generated), 1)
            content = Path(generated[0][1]).read_text(encoding="utf-8")
            self.assertIn("Foo::Bar", content)

    def test_synthesize_class_and_globals_when_only_symbols_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            generated = synthesize_symbolic_source_tree(
                Path(temp_dir),
                origin_label="ELF symbols",
                function_names=["Foo::Bar", "main"],
            )
            labels = {item[0] for item in generated}
            self.assertIn("symbols/Foo.hpp", labels)
            self.assertIn("symbols/Foo.cpp", labels)
            self.assertIn("symbols/globals.cpp", labels)


if __name__ == "__main__":
    unittest.main()
