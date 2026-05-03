from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.electron import ElectronAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport, FrontendSettings


class ElectronAnalyzerTests(unittest.TestCase):
    def test_app_asar_source_maps_restore_original_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "Sample.exe"
            target.write_bytes(b"MZ" + b"\0" * 128)
            resources = root / "resources"
            resources.mkdir()
            _write_minimal_asar(
                resources / "app.asar",
                {
                    "package.json": b'{"name":"sample"}',
                    "bundle.js": b"console.log(1);\n//# sourceMappingURL=bundle.js.map\n",
                    "bundle.js.map": json.dumps(
                        {
                            "version": 3,
                            "file": "bundle.js",
                            "sources": ["src/app.ts"],
                            "sourcesContent": ["export const answer = 1;\n"],
                        }
                    ).encode("utf-8"),
                },
            )
            output_dir = root / "out"
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                frontend_settings=FrontendSettings(beautify_bundles=False),
            )
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))

            with patch("re_pro.asar_tools._asar_extract_command_templates", return_value=[]):
                ElectronAnalyzer().analyze(context, report)

            self.assertTrue(any(source.original_path == "src/app.ts" for source in report.recovered_sources))
            self.assertTrue(any("inside extracted app.asar" in note for note in report.notes))
            restored = Path(report.recovered_sources[0].restored_path)
            self.assertEqual(restored.read_text(encoding="utf-8"), "export const answer = 1;\n")

    def test_beautify_frontend_uses_cleaned_bundle_names_when_no_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "Sample.exe"
            target.write_bytes(b"MZ" + b"\0" * 128)
            app_dir = root / "resources" / "app" / "assets"
            app_dir.mkdir(parents=True)
            (app_dir / "index-a1b2c3d4.js").write_text("function main(){console.log('ok');}", encoding="utf-8")
            output_dir = root / "out"
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                frontend_settings=FrontendSettings(beautify_bundles=True),
            )
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))

            ElectronAnalyzer().analyze(context, report)

            restored_paths = [Path(source.restored_path) for source in report.recovered_sources]
            self.assertTrue(any(path.name == "index.js" for path in restored_paths))
            self.assertTrue(any("Beautified Electron bundled frontend sources" == artifact.description for artifact in report.artifacts))
            restored = next(path for path in restored_paths if path.name == "index.js")
            text = restored.read_text(encoding="utf-8")
            self.assertIn("Original bundled asset: assets/index-a1b2c3d4.js", text)
            self.assertIn("function main()", text)


def _write_minimal_asar(path: Path, files: dict[str, bytes]) -> None:
    header_files = {}
    offset = 0
    payload = bytearray()
    for name, data in files.items():
        header_files[name] = {"offset": str(offset), "size": len(data)}
        payload.extend(data)
        offset += len(data)
    header_pickle = _pickle_string(json.dumps({"files": header_files}, separators=(",", ":")))
    path.write_bytes(_pickle_uint32(len(header_pickle)) + header_pickle + bytes(payload))


def _pickle_uint32(value: int) -> bytes:
    return struct.pack("<II", 4, value)


def _pickle_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    payload = struct.pack("<i", len(encoded)) + encoded
    payload += b"\x00" * ((4 - (len(payload) % 4)) % 4)
    return struct.pack("<I", len(payload)) + payload


if __name__ == "__main__":
    unittest.main()
