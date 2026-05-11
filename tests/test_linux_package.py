from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.linux_package import LinuxPackageAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class LinuxPackageAnalyzerTests(unittest.TestCase):
    def test_appimage_analysis_carves_squashfs_and_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "demo.AppImage"
            target.write_bytes(
                b"\x7fELF" + b"\x00" * 4 + b"AI\x02" + b"\x00" * 64 + b"hsqs" + b"payload"
            )
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                binary_head=target.read_bytes(),
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                extract_dir = output_dir / "linux_package_extract"
                extract_dir.mkdir(parents=True, exist_ok=True)
                (extract_dir / "AppRun").write_text("#!/bin/sh\n", encoding="utf-8")
                map_path = extract_dir / "resources" / "app.js.map"
                map_path.parent.mkdir(parents=True, exist_ok=True)
                map_path.write_text(
                    json.dumps(
                        {
                            "version": 3,
                            "file": "app.js",
                            "sources": ["src/app.ts"],
                            "sourcesContent": ["export const app = true;\n"],
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, "ok", ""

            with (
                patch("re_pro.analyzers.linux_package.resolve_command", return_value=["7z", "x", "-y", "-oX", "demo"]),
                patch("re_pro.analyzers.linux_package.run_command", side_effect=fake_run_command),
            ):
                LinuxPackageAnalyzer().analyze(context, report)

            self.assertEqual(report.target_type, "linux-appimage")
            self.assertIn("Linux AppImage", report.frameworks)
            self.assertTrue(any("AppImage extraction produced" in note for note in report.notes))
            self.assertGreaterEqual(len(report.recovered_sources), 1)
            self.assertTrue(any("Embedded SquashFS image carved from AppImage" == artifact.description for artifact in report.artifacts))

    def test_squashfs_image_is_detected_by_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "rootfs.bin"
            target.write_bytes(b"hsqs" + b"\x00" * 128)
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                binary_head=target.read_bytes(),
            )

            with patch.object(LinuxPackageAnalyzer, "_extract_rootfs", return_value=output_dir / "linux_package_extract"):
                (output_dir / "linux_package_extract").mkdir(parents=True, exist_ok=True)
                LinuxPackageAnalyzer().analyze(context, report)

            self.assertEqual(report.target_type, "squashfs-image")
            self.assertIn("SquashFS image", report.frameworks)


if __name__ == "__main__":
    unittest.main()
