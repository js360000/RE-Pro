from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.dotnet import DotNetAnalyzer
from re_pro.dotnet_bundle import extract_dotnet_single_file_bundle, parse_dotnet_single_file_bundle
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from re_pro.utils import parse_pe_cli_metadata


class DotNetAnalyzerTests(unittest.TestCase):
    def test_parse_pe_cli_metadata_reads_basic_clr_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "managed.exe"
            data = bytearray(0x800)
            data[0:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 123456789, 0, 0, 0xF0, 0x22)
            struct.pack_into("<H", data, 0x98, 0x20B)
            struct.pack_into("<II", data, 0x108 + (8 * 14), 0x1000, 0x48)
            data[0x188:0x190] = b".text\x00\x00\x00"
            struct.pack_into("<IIII", data, 0x190, 0x600, 0x1000, 0x600, 0x200)

            struct.pack_into(
                "<IHHIIIIIIII",
                data,
                0x200,
                0x48,
                2,
                5,
                0x1100,
                0x80,
                0x00000009,
                0x06000001,
                0,
                0,
                0x1180,
                0x20,
            )
            data[0x300:0x304] = b"BSJB"
            struct.pack_into("<HHII", data, 0x304, 1, 1, 0, 13)
            data[0x310:0x31D] = b"v4.0.30319\x00\x00\x00"
            struct.pack_into("<HH", data, 0x320, 0, 2)
            struct.pack_into("<II", data, 0x324, 0x40, 0x20)
            data[0x32C:0x330] = b"#~\x00\x00"
            struct.pack_into("<II", data, 0x330, 0x60, 0x20)
            data[0x338:0x340] = b"#Strings"
            data[0x340] = 0
            path.write_bytes(bytes(data))

            metadata = parse_pe_cli_metadata(path)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["runtime_version"], "2.5")
            self.assertEqual(metadata["metadata_version"], "v4.0.30319")
            self.assertIn("ILONLY", metadata["flags"])
            self.assertIn("STRONGNAMESIGNED", metadata["flags"])
            self.assertEqual(metadata["metadata_streams"], ["#~", "#Strings"])

    def test_parse_and_extract_single_file_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "bundle.exe"
            managed_payload = self._build_minimal_managed_pe()
            bundle.write_bytes(self._build_single_file_bundle(managed_payload, "ScreenToGif.dll"))

            parsed = parse_dotnet_single_file_bundle(bundle)
            extracted = extract_dotnet_single_file_bundle(bundle, root / "bundle_extract")

            self.assertIsNotNone(parsed)
            assert parsed is not None
            self.assertEqual(parsed["major_version"], 6)
            self.assertEqual(parsed["file_count"], 1)
            self.assertEqual(parsed["entries"][0]["relative_path"], "ScreenToGif.dll")
            self.assertIsNotNone(extracted)
            assert extracted is not None
            extracted_dll = Path(extracted["extracted_entries"][0]["destination"])
            self.assertEqual(extracted_dll.read_bytes(), managed_payload)
            self.assertIsNotNone(parse_pe_cli_metadata(extracted_dll))

    def test_dotnet_analyzer_detects_managed_ui_and_exports_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "app.exe"
            target.write_bytes(b"MZ")
            runtimeconfig = root / "app.runtimeconfig.json"
            runtimeconfig.write_text("{}", encoding="utf-8")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=[
                    "System.Windows.Forms",
                    "Application.Run",
                    "System.Private.CoreLib",
                ],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_cli_metadata={
                    "runtime_version": "2.5",
                    "metadata_version": "v4.0.30319",
                    "flags": ["ILONLY"],
                    "metadata_streams": ["#~", "#Strings", "#Blob"],
                },
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                output_dir = root / "out" / "dotnet_decompile"
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "App.csproj").write_text("<Project />", encoding="utf-8")
                return 0, "decompiled", ""

            with (
                patch("re_pro.analyzers.dotnet.resolve_command", side_effect=lambda candidates: ["dotnet"] if candidates[0][0] == "dotnet" else None),
                patch("re_pro.analyzers.dotnet.resolve_tool_path", return_value=str(root / "tools" / "ilspycmd" / "ilspycmd.exe")),
                patch("re_pro.analyzers.dotnet.extract_managed_resources", return_value=None),
                patch("re_pro.analyzers.dotnet.run_command", side_effect=fake_run_command),
            ):
                DotNetAnalyzer().analyze(context, report)

            self.assertIn(".NET", report.frameworks)
            self.assertIn(".NET Core / .NET 5+", report.frameworks)
            self.assertIn("WinForms", report.frameworks)
            self.assertTrue(any(artifact.description == ".NET CLR metadata manifest" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == ".NET runtime configuration" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == ".NET decompilation completed" for finding in report.findings))

    def test_dotnet_analyzer_extracts_managed_payload_from_single_file_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "ScreenToGif.exe"
            target.write_bytes(self._build_single_file_bundle(self._build_minimal_managed_pe(), "ScreenToGif.dll"))
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=[
                    "System.Private.CoreLib",
                    "PresentationFramework",
                    "ScreenToGif.dll",
                ],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                version_info={"OriginalFilename": "ScreenToGif.dll"},
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                output_dir = root / "out" / "dotnet_decompile"
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "ScreenToGif.csproj").write_text("<Project />", encoding="utf-8")
                return 0, "decompiled", ""

            with (
                patch("re_pro.analyzers.dotnet.extract_managed_resources", return_value=None),
                patch("re_pro.analyzers.dotnet.run_command", side_effect=fake_run_command),
            ):
                DotNetAnalyzer().analyze(context, report)

            self.assertIn(".NET single-file bundle", report.frameworks)
            self.assertTrue(any(artifact.description == ".NET single-file bundle manifest" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == "Companion managed assembly selected for .NET decompilation" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == ".NET decompilation completed" for finding in report.findings))

    def test_parse_pe_cli_metadata_detects_readytorun_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "r2r.exe"
            data = bytearray(0x1000)
            data[0:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 123456789, 0, 0, 0xF0, 0x22)
            struct.pack_into("<H", data, 0x98, 0x20B)
            struct.pack_into("<II", data, 0x108 + (8 * 14), 0x1000, 0x70)
            data[0x188:0x190] = b".text\x00\x00\x00"
            struct.pack_into("<IIII", data, 0x190, 0x800, 0x1000, 0x800, 0x200)
            struct.pack_into(
                "<IHHIIIIIIIIIIIIIIII",
                data,
                0x200,
                0x48,
                2,
                5,
                0x1100,
                0x80,
                0x0000000D,
                0x06000001,
                0,
                0,
                0x1180,
                0x20,
                0,
                0,
                0,
                0,
                0,
                0,
                0x1200,
                0x20,
            )
            data[0x300:0x304] = b"BSJB"
            struct.pack_into("<HHII", data, 0x304, 1, 1, 0, 13)
            data[0x310:0x31D] = b"v4.0.30319\x00\x00\x00"
            struct.pack_into("<HH", data, 0x320, 0, 2)
            struct.pack_into("<II", data, 0x324, 0x40, 0x20)
            data[0x32C:0x330] = b"#~\x00\x00"
            struct.pack_into("<II", data, 0x330, 0x60, 0x20)
            data[0x338:0x340] = b"#Strings"
            data[0x340] = 0
            struct.pack_into("<IHHII", data, 0x400, 0x00525452, 3, 1, 0x2, 7)
            path.write_bytes(bytes(data))

            metadata = parse_pe_cli_metadata(path)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["managed_native_header_rva"], 0x1200)
            readytorun = metadata["managed_native_header"]
            self.assertIsInstance(readytorun, dict)
            assert isinstance(readytorun, dict)
            self.assertTrue(readytorun["is_readytorun"])
            self.assertEqual(readytorun["major_version"], 3)
            self.assertEqual(readytorun["section_count"], 7)

    def test_dotnet_analyzer_records_managed_resources_and_baml_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "app.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["PresentationFramework", "System.Private.CoreLib"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_cli_metadata={
                    "runtime_version": "2.5",
                    "metadata_version": "v4.0.30319",
                    "flags": ["ILONLY", "IL_LIBRARY"],
                    "metadata_streams": ["#~", "#Strings", "#Blob"],
                    "managed_native_header": {
                        "is_readytorun": True,
                        "major_version": 3,
                        "minor_version": 1,
                        "section_count": 4,
                    },
                },
            )

            def fake_run_command(command, *, cwd=None, timeout=300):
                output_dir = root / "out" / "dotnet_decompile"
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "App.csproj").write_text("<Project />", encoding="utf-8")
                baml_dir = output_dir / "views"
                baml_dir.mkdir(parents=True, exist_ok=True)
                (baml_dir / "mainwindow.baml").write_bytes(b"MSBAML")
                return 0, "decompiled", ""

            resource_manifest = {
                "manifest_resources": [
                    {
                        "name": "App.g.resources",
                        "relative_path": "manifest_resources/App.g.resources",
                        "resource_entries": [
                            {
                                "name": "views/mainwindow.baml",
                                "relative_path": "resources/App.g/views/mainwindow.baml",
                                "probable_baml": True,
                                "probable_xaml_path": "resources/App.g/views/mainwindow.xaml",
                            }
                        ],
                    }
                ]
            }

            def fake_extract_managed_resources(target_path, output_dir, logger=None):
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "resource_manifest.json").write_text("{}", encoding="utf-8")
                resources_dir = output_dir / "resources"
                resources_dir.mkdir(parents=True, exist_ok=True)
                baml_dir = resources_dir / "App.g" / "views"
                baml_dir.mkdir(parents=True, exist_ok=True)
                (baml_dir / "mainwindow.baml").write_bytes(b"MSBAML")
                raw_dir = output_dir / "manifest_resources"
                raw_dir.mkdir(parents=True, exist_ok=True)
                return resource_manifest

            def fake_decompile_baml_to_xaml(assembly_path, jobs, output_dir, logger=None):
                output_dir.mkdir(parents=True, exist_ok=True)
                results = []
                for job in jobs:
                    relative = Path(str(job["output_relative_path"]))
                    destination = output_dir / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text("<Window />", encoding="utf-8")
                    results.append(
                        {
                            "source_path": str(job["source_path"]),
                            "output_relative_path": relative.as_posix(),
                            "output_path": str(destination),
                            "success": True,
                        }
                    )
                manifest = {
                    "total_jobs": len(jobs),
                    "success_count": len(results),
                    "results": results,
                }
                (output_dir / "xaml_manifest.json").write_text("{}", encoding="utf-8")
                return manifest

            with (
                patch("re_pro.analyzers.dotnet.resolve_command", side_effect=lambda candidates: ["dotnet"] if candidates[0][0] == "dotnet" else None),
                patch("re_pro.analyzers.dotnet.resolve_tool_path", return_value=str(root / "tools" / "ilspycmd" / "ilspycmd.exe")),
                patch("re_pro.analyzers.dotnet.extract_managed_resources", side_effect=fake_extract_managed_resources),
                patch("re_pro.analyzers.dotnet.decompile_baml_to_xaml", side_effect=fake_decompile_baml_to_xaml),
                patch("re_pro.analyzers.dotnet.run_command", side_effect=fake_run_command),
            ):
                DotNetAnalyzer().analyze(context, report)

            self.assertIn(".NET ReadyToRun", report.frameworks)
            self.assertTrue(any(artifact.description == ".NET managed resource manifest" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == "WPF BAML-to-XAML path hints" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == "ILSpy BAML output manifest" for artifact in report.artifacts))
            self.assertTrue(any(".NET reconstructed XAML manifest (managed resource)" == artifact.description for artifact in report.artifacts))
            self.assertTrue(any(".NET reconstructed XAML manifest (ILSpy BAML)" == artifact.description for artifact in report.artifacts))
            self.assertTrue(any("Readable WPF XAML reconstructed from managed resource BAML" == artifact.description for artifact in report.artifacts))
            self.assertTrue(any("Readable WPF XAML reconstructed from ILSpy BAML" == artifact.description for artifact in report.artifacts))
            self.assertTrue(any("probable XAML source paths were inferred" in note for note in report.notes))
            self.assertTrue(any("Reconstructed 1 readable WPF XAML file(s) from managed resource BAML" in note for note in report.notes))
            self.assertTrue(any("Reconstructed 1 readable WPF XAML file(s) from ILSpy BAML" in note for note in report.notes))

    @staticmethod
    def _build_minimal_managed_pe() -> bytes:
        data = bytearray(0x800)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 123456789, 0, 0, 0xF0, 0x22)
        struct.pack_into("<H", data, 0x98, 0x20B)
        struct.pack_into("<II", data, 0x108 + (8 * 14), 0x1000, 0x48)
        data[0x188:0x190] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, 0x190, 0x600, 0x1000, 0x600, 0x200)
        struct.pack_into(
            "<IHHIIIIIIII",
            data,
            0x200,
            0x48,
            2,
            5,
            0x1100,
            0x80,
            0x00000009,
            0x06000001,
            0,
            0,
            0x1180,
            0x20,
        )
        data[0x300:0x304] = b"BSJB"
        struct.pack_into("<HHII", data, 0x304, 1, 1, 0, 13)
        data[0x310:0x31D] = b"v4.0.30319\x00\x00\x00"
        struct.pack_into("<HH", data, 0x320, 0, 2)
        struct.pack_into("<II", data, 0x324, 0x40, 0x20)
        data[0x32C:0x330] = b"#~\x00\x00"
        struct.pack_into("<II", data, 0x330, 0x60, 0x20)
        data[0x338:0x340] = b"#Strings"
        data[0x340] = 0
        return bytes(data)

    @staticmethod
    def _build_single_file_bundle(payload: bytes, relative_path: str) -> bytes:
        signature = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
        host = bytearray(b"MZ" + (b"\x00" * 96))
        signature_offset = 16
        host[signature_offset - 8 : signature_offset] = b"\x00" * 8
        host[signature_offset : signature_offset + len(signature)] = signature
        payload_offset = len(host)
        header = bytearray()
        header += struct.pack("<II", 6, 0)
        header += struct.pack("<i", 1)
        header += DotNetAnalyzerTests._encode_binary_writer_string("BUNDLEID1234")
        header += struct.pack("<qqqqQ", 0, 0, 0, 0, 0)
        header += struct.pack("<qqqB", payload_offset, len(payload), 0, 1)
        header += DotNetAnalyzerTests._encode_binary_writer_string(relative_path)
        header_offset = payload_offset + len(payload)
        host[signature_offset - 8 : signature_offset] = struct.pack("<q", header_offset)
        return bytes(host) + payload + bytes(header)

    @staticmethod
    def _encode_binary_writer_string(value: str) -> bytes:
        encoded = value.encode("utf-8")
        length = len(encoded)
        prefix = bytearray()
        while length >= 0x80:
            prefix.append((length & 0x7F) | 0x80)
            length >>= 7
        prefix.append(length)
        return bytes(prefix) + encoded


if __name__ == "__main__":
    unittest.main()
