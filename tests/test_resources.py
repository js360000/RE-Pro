from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.resources import PEResourceAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


class ResourceAnalyzerTests(unittest.TestCase):
    def test_resource_analyzer_records_manifest_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                pe_metadata={"sections": [".rsrc"]},
            )
            fake_manifest = output_dir / "pe_resources.json"
            fake_manifest.parent.mkdir(parents=True, exist_ok=True)
            fake_manifest.write_text("[]", encoding="utf-8")
            fake_entries = [
                type(
                    "Entry",
                    (),
                    {
                        "type_name": "MANIFEST",
                        "name": "1",
                        "language": 1033,
                        "path": str(output_dir / "pe_resources" / "MANIFEST" / "1_lang1033.xml"),
                    },
                )()
            ]

            with patch("re_pro.analyzers.resources.extract_pe_resources", return_value=(fake_entries, fake_manifest)):
                PEResourceAnalyzer().analyze(context, report)

            self.assertTrue(any(finding.title == "PE resources extracted" for finding in report.findings))
            self.assertTrue(any(artifact.category == "resource" for artifact in report.artifacts))


if __name__ == "__main__":
    unittest.main()
