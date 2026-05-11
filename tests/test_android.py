from __future__ import annotations

import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.android import AndroidAnalyzer
from re_pro.dex import parse_dex_metadata
from re_pro.engine import AnalysisContext, ReverseEngineeringEngine
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class AndroidAnalyzerTests(unittest.TestCase):
    def test_standalone_resources_arsc_analysis_recovers_package_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            arsc_path = root / "resources.arsc"
            arsc_path.write_bytes(_build_test_arsc("com.example.resources"))

            engine = ReverseEngineeringEngine(output_root=root / "out")
            report = engine.analyze(arsc_path)

            self.assertEqual(report.target_type, "android-resource-table")
            self.assertIn("Android resource table (.arsc)", report.frameworks)
            self.assertTrue(any("Android resource packages: com.example.resources" in note for note in report.notes))

    def test_parse_standalone_dex_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dex_path = Path(temp_dir) / "classes.dex"
            dex_path.write_bytes(_build_test_dex())
            metadata = parse_dex_metadata(dex_path)
            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["version"], "035")
            self.assertIn("Lcom/example/Main;", metadata["class_descriptors"])

    def test_raw_dex_analysis_records_classes_and_runs_jadx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dex_path = root / "classes.dex"
            dex_path.write_bytes(_build_test_dex())
            report = AnalysisReport(target=str(dex_path), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=dex_path,
                output_dir=root / "out",
                probable_binary=True,
                run_external_tools=True,
                binary_head=dex_path.read_bytes()[:1024],
            )

            def fake_run_command(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                if "jadx" in " ".join(command).lower():
                    out = context.output_dir / "jadx" / "sources"
                    out.mkdir(parents=True, exist_ok=True)
                    (out / "Main.java").write_text("class Main {}", encoding="utf-8")
                    return 0, "jadx", ""
                return 1, "", "unexpected"

            with patch("re_pro.analyzers.android.resolve_command", return_value=[str(root / "tools" / "jadx" / "bin" / "jadx.bat")]):
                with patch("re_pro.analyzers.android.run_command_logged", side_effect=fake_run_command):
                    AndroidAnalyzer().analyze(context, report)

            self.assertEqual(report.target_type, "android-dex")
            self.assertIn("Android DEX bytecode", report.frameworks)
            self.assertTrue(any("DEX package namespaces:" in note for note in report.notes))
            self.assertTrue(any("jadx decompilation succeeded" == finding.title for finding in report.findings))

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

    def test_aab_analysis_extracts_base_module_and_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            aab_path = root / "bundle.aab"
            with zipfile.ZipFile(aab_path, "w") as archive:
                archive.writestr(
                    "base/manifest/AndroidManifest.xml",
                    """<?xml version="1.0" encoding="utf-8"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.bundle">
                      <application android:label="Bundle App" android:name="com.example.BundleApplication" />
                    </manifest>
                    """,
                )
                archive.writestr("base/dex/classes.dex", b"dex\n035\x00")
                archive.writestr("base/resources.pb", b"\x0a\x01\x00")
                archive.writestr("base/assets/www/app.js", "console.log('bundle');")
                archive.writestr(
                    "base/assets/www/app.js.map",
                    json.dumps(
                        {
                            "version": 3,
                            "file": "app.js",
                            "sources": ["webpack:///src/bundle.ts"],
                            "sourcesContent": ["console.log('bundle source');"],
                        }
                    ),
                )
                archive.writestr("feature_chat/manifest/AndroidManifest.xml", "<manifest package='com.example.bundle.chat' />")
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(aab_path)

            self.assertEqual(report.target_type, "android-app-bundle")
            self.assertIn("Android App Bundle (.aab)", report.frameworks)
            self.assertIn("Android framework: WebView bundle", report.frameworks)
            self.assertTrue(any("Android package name: com.example.bundle" in note for note in report.notes))
            self.assertTrue(any("Recovered 2 Android App Bundle module(s): base, feature_chat" in note for note in report.notes))
            self.assertTrue(any("base module DEX files present: classes.dex" in note for note in report.notes))
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


def _build_test_dex() -> bytes:
    strings = [b"Lcom/example/Main;", b"com.example"]
    string_data = bytearray()
    string_offsets: list[int] = []
    base_string_data_off = 112 + len(strings) * 4 + 4 + len(strings) * 4 + 32
    cursor = base_string_data_off
    for value in strings:
        string_offsets.append(cursor)
        encoded = bytes([len(value)]) + value + b"\x00"
        string_data.extend(encoded)
        cursor += len(encoded)

    string_ids_off = 112
    type_ids_off = string_ids_off + len(strings) * 4
    class_defs_off = type_ids_off + len(strings) * 4
    file_size = base_string_data_off + len(string_data)

    header = bytearray(file_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, 112)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(strings))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<I", header, 76, 0)
    struct.pack_into("<I", header, 80, 0)
    struct.pack_into("<I", header, 84, 0)
    struct.pack_into("<I", header, 88, 0)
    struct.pack_into("<I", header, 92, 0)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)

    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", header, string_ids_off + (index * 4), offset)
    struct.pack_into("<I", header, type_ids_off, 0)
    struct.pack_into("<I", header, type_ids_off + 4, 1)
    struct.pack_into("<I", header, class_defs_off, 0)
    header[base_string_data_off : base_string_data_off + len(string_data)] = string_data
    return bytes(header)


def _build_test_arsc(package_name: str) -> bytes:
    package_chunk_size = 0x120
    total_size = 12 + package_chunk_size
    data = bytearray(total_size)
    struct.pack_into("<HHI", data, 0, 0x0002, 12, total_size)
    struct.pack_into("<I", data, 8, 1)

    chunk_offset = 12
    struct.pack_into("<HHI", data, chunk_offset, 0x0200, 0x0120, package_chunk_size)
    struct.pack_into("<I", data, chunk_offset + 8, 0x7F)
    encoded_name = package_name.encode("utf-16le")
    data[chunk_offset + 12 : chunk_offset + 12 + len(encoded_name)] = encoded_name
    return bytes(data)
