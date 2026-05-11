from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.installer import InstallerAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class InstallerTests(unittest.TestCase):
    def test_msi_installer_detection_and_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.msi"
            target.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=False,
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                extracted = output_dir / "installer_extract"
                extracted.mkdir(parents=True, exist_ok=True)
                (extracted / "app.exe").write_bytes(b"MZ")
                return 0, "ok", ""

            with patch("re_pro.analyzers.installer.resolve_command", return_value=["7z", "x", "-y", f"-o{output_dir / 'installer_extract'}", str(target)]):
                with patch("re_pro.analyzers.installer.run_command", side_effect=fake_run_command):
                    InstallerAnalyzer().analyze(context, report)

            self.assertIn("Installer: MSI", report.frameworks)
            self.assertTrue(any("MSI installer detected" == finding.title for finding in report.findings))
            self.assertTrue(any(artifact.category == "payload" for artifact in report.artifacts))

    def test_cab_installer_detection_and_expand_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "payload.cab"
            target.write_bytes(b"MSCF" + b"\x00" * 32)
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=False,
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                extracted = output_dir / "installer_extract"
                extracted.mkdir(parents=True, exist_ok=True)
                (extracted / "app.exe").write_bytes(b"MZ")
                return 0, "ok", ""

            with patch("re_pro.analyzers.installer.resolve_command", side_effect=[["expand", str(target), "-F:*", str(output_dir / "installer_extract")], None]):
                with patch("re_pro.analyzers.installer.run_command", side_effect=fake_run_command):
                    InstallerAnalyzer().analyze(context, report)

            self.assertIn("Installer: CAB", report.frameworks)
            self.assertTrue(any("CAB installer detected" == finding.title for finding in report.findings))
            self.assertTrue(any(artifact.category == "payload" for artifact in report.artifacts))


if __name__ == "__main__":
    unittest.main()
