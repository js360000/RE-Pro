from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.installer import InstallerAnalyzer
from re_pro.analyzers.tauri import TauriAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class FrameworkAnalyzerTests(unittest.TestCase):
    def test_tauri_analyzer_detects_tauri_bundle_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(
                b"MZ"
                + b"/index.html"
                + b"/assets/index-ABC123.js"
                + b"/assets/index-XYZ789.css"
                + b"sidecars/opencode-cli"
                + b"https://github.com/anomalyco/opencode/releases/latest/download/latest.json"
                + b"C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-123\\crate\\src\\lib.rs"
            )
            report = AnalysisReport(target=str(target), output_dir="out")
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=[
                    "tauri://localhost",
                    "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-123\\crate\\src\\lib.rs",
                ],
                pe_metadata={"sections": [".text", ".taubndl"]},
                pe_sections=[{"name": ".taubndl", "raw_offset": 0, "raw_size": 2}],
                probable_binary=True,
            )

            with patch(
                "re_pro.analyzers.tauri.extract_tauri_assets",
                return_value={
                    "entries": [],
                    "manifest_path": root / "out" / "tauri" / "extracted_assets_manifest.json",
                    "assets_dir": root / "out" / "tauri" / "assets",
                    "extracted_count": 0,
                    "restored_sources": [],
                    "notes": [],
                },
            ):
                TauriAnalyzer().analyze(context, report)

            self.assertIn("Tauri", report.frameworks)
            self.assertIn("Rust native binary", report.frameworks)
            self.assertIn("Frontend bundle: Vite", report.frameworks)
            self.assertTrue(any("Tauri application detected" == finding.title for finding in report.findings))
            manifest = context.output_dir / "tauri" / "embedded_asset_manifest.json"
            self.assertTrue(manifest.exists())

    def test_tauri_analyzer_detects_nextjs_assets_without_taubndl_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(
                b"MZ"
                + b"__TAURI__"
                + b"/index.html"
                + b"/_next/static/chunks/app-test.js"
                + b"/_next/static/chunks/app-test.js.map"
                + b"turbopack"
            )
            report = AnalysisReport(target=str(target), output_dir="out")
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=[],
                pe_metadata={"sections": [".text", ".rdata"]},
                pe_sections=[],
                probable_binary=True,
            )

            with patch(
                "re_pro.analyzers.tauri.extract_tauri_assets",
                return_value={
                    "entries": [],
                    "manifest_path": root / "out" / "tauri" / "extracted_assets_manifest.json",
                    "assets_dir": root / "out" / "tauri" / "assets",
                    "extracted_count": 0,
                    "restored_sources": [],
                    "notes": [],
                },
            ):
                TauriAnalyzer().analyze(context, report)

            self.assertIn("Tauri", report.frameworks)
            self.assertIn("Web framework: Next.js", report.frameworks)
            self.assertTrue(any("source map path" in note for note in report.notes))

    def test_tauri_analyzer_ignores_non_pe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.apk"
            target.write_bytes(b"PK\x03\x04__TAURI__/index.html/_next/static/app.js.map")
            report = AnalysisReport(target=str(target), output_dir="out")
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["__TAURI__", "/_next/static/app.js.map"],
                pe_metadata=None,
                pe_sections=[],
                probable_binary=True,
            )

            TauriAnalyzer().analyze(context, report)

            self.assertNotIn("Tauri", report.frameworks)
            self.assertFalse((context.output_dir / "tauri").exists())

    def test_installer_analyzer_extracts_with_7z_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "installer.exe"
            target.write_bytes(b"MZ\x00NSIS\x00")
            output_dir = root / "out"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                ascii_strings=["Nullsoft Install System", "NSIS"],
                probable_binary=True,
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                extracted = output_dir / "installer_extract"
                extracted.mkdir(parents=True, exist_ok=True)
                (extracted / "OpenCode.exe").write_bytes(b"MZ")
                (extracted / "nsis_tauri_utils.dll").write_bytes(b"MZ")
                return 0, "ok", ""

            with patch("re_pro.analyzers.installer.resolve_command", return_value=["7z", "x", "-y", f"-o{output_dir / 'installer_extract'}", str(target)]):
                with patch("re_pro.analyzers.installer.run_command", side_effect=fake_run_command):
                    InstallerAnalyzer().analyze(context, report)

            self.assertIn("Installer: NSIS", report.frameworks)
            self.assertTrue(any("payload" == artifact.category for artifact in report.artifacts))
            self.assertTrue(any("Tauri-related files" in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
