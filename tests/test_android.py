from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.engine import ReverseEngineeringEngine
from re_pro.analyzers.android import AndroidAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


class AndroidAnalyzerTests(unittest.TestCase):
    def test_apk_analysis_restores_sources_from_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr(
                    "AndroidManifest.xml",
                    """<?xml version="1.0" encoding="utf-8"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
                      <application android:label="Example App" android:name="com.example.MainApplication" />
                    </manifest>
                    """,
                )
                archive.writestr("classes.dex", b"dex\n035\x00")
                archive.writestr("assets/www/app.js", "console.log('hi');")
                archive.writestr(
                    "assets/www/app.js.map",
                    json.dumps(
                        {
                            "version": 3,
                            "file": "app.js",
                            "sources": ["webpack:///src/main.ts"],
                            "sourcesContent": ["console.log('src');"],
                        }
                    ),
                )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(apk_path)

            self.assertIn("Android APK", report.frameworks)
            self.assertIn("Android framework: WebView bundle", report.frameworks)
            self.assertTrue(any("Android package name: com.example.app" in note for note in report.notes))
            self.assertEqual(len(report.recovered_sources), 1)

    def test_apks_analysis_extracts_base_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_apk = root / "base.apk"
            with zipfile.ZipFile(base_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", "<manifest package='com.example.bundle' />")
                archive.writestr(
                    "assets/index.js.map",
                    json.dumps(
                        {
                            "version": 3,
                            "file": "index.js",
                            "sources": ["src/index.ts"],
                            "sourcesContent": ["export const ok = true;"],
                        }
                    ),
                )
            apks_path = root / "bundle.apks"
            with zipfile.ZipFile(apks_path, "w") as archive:
                archive.write(base_apk, "base.apk")
                archive.writestr("split_config.arm64_v8a.apk", b"PK\x03\x04")
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(apks_path)

            self.assertIn("Android package set (.apks/.xapk)", report.frameworks)
            self.assertIn("Android APK", report.frameworks)
            self.assertEqual(len(report.recovered_sources), 1)

    def test_android_external_tools_run_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.apk"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
                archive.writestr("classes.dex", b"dex\n035\x00")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                run_external_tools=True,
            )

            def fake_run_command(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                if "apktool" in " ".join(command) or (len(command) >= 3 and command[0] == "java" and command[2].endswith(".jar")):
                    decoded = context.output_dir / "apktool_decode"
                    decoded.mkdir(parents=True, exist_ok=True)
                    (decoded / "AndroidManifest.xml").write_text("<manifest package='com.example.tool' />", encoding="utf-8")
                    return 0, "decoded", ""
                if "jadx" in " ".join(command).lower():
                    out = context.output_dir / "jadx" / "sources"
                    out.mkdir(parents=True, exist_ok=True)
                    (out / "MainActivity.java").write_text("class MainActivity {}", encoding="utf-8")
                    return 0, "jadx", ""
                return 1, "", "unexpected"

            with patch("re_pro.analyzers.android.resolve_command", side_effect=[[str(root / "tools" / "jadx" / "bin" / "jadx.bat")], None]):
                with patch("re_pro.analyzers.android.resolve_tool_path", return_value=str(root / "tools" / "apktool" / "apktool_3.0.2.jar")):
                    with patch("re_pro.analyzers.android.run_command_logged", side_effect=fake_run_command):
                        AndroidAnalyzer().analyze(context, report)

            self.assertTrue(any("apktool decode succeeded" == finding.title for finding in report.findings))
            self.assertTrue(any("jadx decompilation succeeded" == finding.title for finding in report.findings))


if __name__ == "__main__":
    unittest.main()
