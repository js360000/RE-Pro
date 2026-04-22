from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine


class EngineTests(unittest.TestCase):
    def test_plain_text_file_does_not_trigger_binary_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text(
                "This document mentions electron, PyInstaller, Nuitka, and Rust, but it is not an executable.",
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(target)

            self.assertEqual(report.frameworks, [])
            self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
