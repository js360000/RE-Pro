from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.native import NativeLanguageAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class PackerDetectionTests(unittest.TestCase):
    def test_mpress_detection_adds_framework(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "packed.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["This binary was compressed by MPRESS"],
                pe_sections=[{"name": "MPRESS1"}, {"name": "MPRESS2"}],
                pe_metadata={"sections": ["MPRESS1", "MPRESS2"]},
                probable_binary=True,
            )

            with patch("re_pro.analyzers.native.resolve_command", return_value=None):
                NativeLanguageAnalyzer().analyze(context, report)

            self.assertIn("Packed executable: MPRESS", report.frameworks)
            self.assertTrue(any("MPRESS" in finding.title for finding in report.findings))


if __name__ == "__main__":
    unittest.main()
