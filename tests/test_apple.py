from __future__ import annotations

import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.apple import AppleAnalyzer
from re_pro.engine import AnalysisContext, ReverseEngineeringEngine
from re_pro.models import AnalysisReport
from re_pro.utils import parse_macho_metadata
from tests import _path_setup  # noqa: F401


class AppleAnalyzerTests(unittest.TestCase):
    def test_parse_macho_metadata_for_minimal_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x01000007, 3, 2, 10, 512, 0x2000)
            path.write_bytes(bytes(header))

            metadata = parse_macho_metadata(path)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["format"], "mach-o")
            self.assertEqual(metadata["cpu_type"], "x86_64")
            self.assertEqual(metadata["file_type"], "executable")

    def test_app_bundle_analysis_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_dir = root / "Sample.app"
            macos_dir = app_dir / "Contents" / "MacOS"
            resources_dir = app_dir / "Contents" / "Resources" / "app"
            macos_dir.mkdir(parents=True)
            resources_dir.mkdir(parents=True)

            info_path = app_dir / "Contents" / "Info.plist"
            info_path.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.example.sample",
                        "CFBundleName": "Sample",
                        "CFBundleExecutable": "Sample",
                        "CFBundleShortVersionString": "1.2.3",
                    }
                )
            )
            executable_path = macos_dir / "Sample"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            executable_path.write_bytes(bytes(header) + b"__TAURI__")

            (resources_dir / "package.json").write_text('{"name":"sample-app","version":"1.2.3"}', encoding="utf-8")
            (resources_dir / "index.html").write_text("<html></html>", encoding="utf-8")
            (resources_dir / "app.js.map").write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "app.js",
                        "sources": ["webpack:///src/app.tsx"],
                        "sourcesContent": ["export const App = () => null;"],
                    }
                ),
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(app_dir)

            self.assertIn("Apple app bundle (.app)", report.frameworks)
            self.assertIn("Mach-O", report.frameworks)
            self.assertEqual(report.target_type, "macos-app-bundle")
            self.assertEqual(len(report.recovered_sources), 1)
            self.assertTrue(any("bundle_id=com.example.sample" in note for note in report.notes))

    def test_ipa_analysis_extracts_ios_app_bundle_and_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ipa_path = root / "Sample.ipa"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            with zipfile.ZipFile(ipa_path, "w") as archive:
                archive.writestr(
                    "Payload/Sample.app/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleIdentifier": "com.example.iossample",
                            "CFBundleName": "Sample iOS",
                            "CFBundleExecutable": "Sample",
                            "CFBundleShortVersionString": "2.0.0",
                            "MinimumOSVersion": "16.0",
                        }
                    ),
                )
                archive.writestr("Payload/Sample.app/Sample", bytes(header) + b"React Native")
                archive.writestr("Payload/Sample.app/www/app.js.map", json.dumps(
                    {
                        "version": 3,
                        "file": "app.js",
                        "sources": ["webpack:///src/mobile.ts"],
                        "sourcesContent": ["export const mobile = true;"],
                    }
                ))
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(ipa_path)

            self.assertIn("iOS application archive (.ipa)", report.frameworks)
            self.assertIn("iOS app bundle (.app)", report.frameworks)
            self.assertEqual(report.target_type, "ios-app-bundle")
            self.assertEqual(len(report.recovered_sources), 1)
            self.assertTrue(any("bundle_id=com.example.iossample" in note for note in report.notes))

    def test_ipa_analysis_records_provisioning_entitlements_and_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ipa_path = root / "Sample.ipa"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            mobileprovision = (
                b"prefix"
                + plistlib.dumps(
                    {
                        "Name": "Demo Profile",
                        "UUID": "1234-5678",
                        "TeamName": "Example Team",
                        "TeamIdentifier": ["TEAM123"],
                        "ProvisionedDevices": ["device-1", "device-2"],
                        "Entitlements": {
                            "application-identifier": "TEAM123.com.example.iossample",
                            "aps-environment": "development",
                            "get-task-allow": True,
                            "com.apple.developer.team-identifier": "TEAM123",
                        },
                    }
                )
                + b"suffix"
            )
            with zipfile.ZipFile(ipa_path, "w") as archive:
                archive.writestr(
                    "Payload/Sample.app/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleIdentifier": "com.example.iossample",
                            "CFBundleName": "Sample iOS",
                            "CFBundleExecutable": "Sample",
                        }
                    ),
                )
                archive.writestr("Payload/Sample.app/Sample", bytes(header))
                archive.writestr("Payload/Sample.app/embedded.mobileprovision", mobileprovision)
                archive.writestr(
                    "Payload/Sample.app/Sample.xcent",
                    plistlib.dumps(
                        {
                            "application-identifier": "TEAM123.com.example.iossample",
                            "aps-environment": "development",
                            "get-task-allow": True,
                        }
                    ),
                )
                archive.writestr("Payload/Sample.app/Frameworks/UnityFramework.framework/UnityFramework", b"\x00")
                archive.writestr("Payload/Sample.app/Frameworks/Hermes.framework/Hermes", b"\x00")
                archive.writestr("Payload/Sample.app/Frameworks/libswiftCore.dylib", b"\x00")
                archive.writestr(
                    "Payload/Sample.app/PlugIns/Share.appex/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleIdentifier": "com.example.iossample.share",
                            "NSExtension": {
                                "NSExtensionPointIdentifier": "com.apple.share-services",
                            },
                        }
                    ),
                )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            report = engine.analyze(ipa_path)

            self.assertIn("iOS framework: Unity", report.frameworks)
            self.assertIn("iOS framework: React Native", report.frameworks)
            self.assertIn("iOS language/runtime: Swift", report.frameworks)
            self.assertIn("iOS app extensions", report.frameworks)
            self.assertTrue(any("Provisioning profile:" in note for note in report.notes))
            self.assertTrue(any("Provisioned entitlements:" in note for note in report.notes))
            self.assertTrue(any("Recovered 1 iOS extension bundle(s)." in note for note in report.notes))

    def test_app_bundle_restores_sources_from_extracted_asar(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_dir = root / "Sample.app"
            macos_dir = app_dir / "Contents" / "MacOS"
            resources_dir = app_dir / "Contents" / "Resources"
            extracted_asar_dir = root / "asar_extract"
            macos_dir.mkdir(parents=True)
            resources_dir.mkdir(parents=True)
            extracted_asar_dir.mkdir(parents=True)

            info_path = app_dir / "Contents" / "Info.plist"
            info_path.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.example.sample",
                        "CFBundleName": "Sample",
                        "CFBundleExecutable": "Sample",
                    }
                )
            )
            executable_path = macos_dir / "Sample"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            executable_path.write_bytes(bytes(header))
            (resources_dir / "app.asar").write_bytes(b"asar")
            (extracted_asar_dir / "package.json").write_text('{"name":"sample-asar","version":"9.9.9"}', encoding="utf-8")
            (extracted_asar_dir / "main.js.map").write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "main.js",
                        "sources": ["webpack:///packages/app/main.ts"],
                        "sourcesContent": ["export const main = true;"],
                    }
                ),
                encoding="utf-8",
            )
            engine = ReverseEngineeringEngine(output_root=root / "out")

            with patch("re_pro.analyzers.apple.AppleAnalyzer._extract_asar", return_value=extracted_asar_dir):
                report = engine.analyze(app_dir)

            self.assertIn("Electron", report.frameworks)
            self.assertEqual(len(report.recovered_sources), 1)

    def test_macos_external_tools_run_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample"
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            target.write_bytes(bytes(header))
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                run_external_tools=True,
            )

            command_map = {
                "llvm-objdump": [str(root / "llvm" / "bin" / "llvm-objdump.exe")],
                "llvm-nm": [str(root / "llvm" / "bin" / "llvm-nm.exe")],
                "rizin": [str(root / "rizin" / "bin" / "rizin.exe")],
                "rz-bin": [str(root / "rizin" / "bin" / "rz-bin.exe")],
                "r2": [str(root / "radare2" / "bin" / "radare2.exe")],
                "radare2": [str(root / "radare2" / "bin" / "radare2.exe")],
                "rabin2": [str(root / "radare2" / "bin" / "rabin2.exe")],
            }

            def fake_resolve_command(candidates):
                for candidate in candidates:
                    if candidate[0] in command_map:
                        return command_map[candidate[0]]
                return None

            def fake_run_command(command, *, cwd=None, timeout=300):
                return 0, "exported", ""

            with patch("re_pro.analyzers.apple.resolve_command", side_effect=fake_resolve_command):
                with patch("re_pro.analyzers.apple.run_command", side_effect=fake_run_command):
                    AppleAnalyzer().analyze(context, report)

            artifact_paths = [artifact.path for artifact in report.artifacts]
            self.assertTrue(any(path.endswith("headers.txt") for path in artifact_paths))
            self.assertTrue(any(path.endswith("symbols.txt") for path in artifact_paths))
            self.assertTrue(any(path.endswith("rizin_functions.json") for path in artifact_paths))

    def test_dmg_partial_extraction_with_symlink_errors_still_analyzes_app_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dmg_path = root / "Sample.dmg"
            dmg_path.write_bytes(b"UDIF")
            output_dir = root / "out"
            extracted_app = output_dir / "apple_extract" / "Mounted" / "Sample.app"
            contents_dir = extracted_app / "Contents"
            resources_dir = contents_dir / "Resources" / "app"
            macos_dir = contents_dir / "MacOS"
            resources_dir.mkdir(parents=True, exist_ok=True)
            macos_dir.mkdir(parents=True, exist_ok=True)
            (contents_dir / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.example.sample",
                        "CFBundleName": "Sample",
                        "CFBundleExecutable": "Sample",
                    }
                )
            )
            header = bytearray(32)
            header[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<iiIIII", header, 4, 0x0100000C, 0, 2, 8, 256, 0x2000)
            (macos_dir / "Sample").write_bytes(bytes(header))
            (resources_dir / "index.html").write_text("<html></html>", encoding="utf-8")
            report = AnalysisReport(target=str(dmg_path), output_dir=str(output_dir))
            context = AnalysisContext(
                target=dmg_path,
                output_dir=output_dir,
            )

            with patch("re_pro.analyzers.apple.resolve_command", return_value=["7z", "x", "-y", f"-o{output_dir / 'apple_extract'}", str(dmg_path)]):
                with patch("re_pro.analyzers.apple.run_command", return_value=(2, "partial", "Cannot create symbolic link")):
                    AppleAnalyzer().analyze(context, report)

            self.assertIn("Apple disk image (.dmg)", report.frameworks)
            self.assertIn("Apple app bundle (.app)", report.frameworks)
            self.assertTrue(any("symlink errors" in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
