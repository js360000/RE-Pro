from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from re_pro.analyzers.live_process import LiveProcessAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.live_process import capture_live_process
from re_pro.live_process import list_live_processes
from re_pro.models import AnalysisReport
from re_pro.models import LiveProcessSettings


class LiveProcessTests(unittest.TestCase):
    def test_capture_live_process_dumps_and_carves_runtime_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            region_data = _pe_blob() + b"\x00" * 32 + b"function recoveredRuntime() { return true; }\n"
            settings = LiveProcessSettings(enabled=True, pid=4242, max_region_bytes=1024 * 1024, max_total_bytes=1024 * 1024)

            with (
                patch("re_pro.live_process._query_process_list", return_value=[_process()]),
                patch("re_pro.live_process._query_modules_for_pid", return_value=[{"name": "pcsx2-qt.exe", "path": r"C:\pcsx2\pcsx2-qt.exe"}]),
                patch(
                    "re_pro.live_process._enumerate_memory_regions",
                    return_value=[
                        {
                            "base_address": 0x140000000,
                            "base_address_hex": "0x140000000",
                            "region_size": len(region_data),
                            "committed": True,
                            "readable": True,
                            "executable": True,
                            "mapped_image": False,
                            "protect": 0x20,
                            "type": 0x20000,
                        }
                    ],
                ),
                patch("re_pro.live_process._read_memory_region", return_value=region_data),
            ):
                result = capture_live_process(output_dir=root, settings=settings)

            self.assertTrue(result["ok"])
            self.assertEqual(result["summary"]["dumped_region_count"], 1)
            self.assertGreaterEqual(result["summary"]["carved_payload_count"], 2)
            kinds = {payload["kind"] for payload in result["carved_payloads"]}
            self.assertIn("portable_executable", kinds)
            self.assertIn("source_text_fragment", kinds)
            self.assertTrue(Path(result["artifacts"]["strings"]).exists())

    def test_live_process_analyzer_adds_artifacts_findings_and_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                live_process_settings=LiveProcessSettings(enabled=True, pid=4242),
            )
            manifest_path = root / "out" / "live_process" / "live_process_manifest.json"
            carved = root / "out" / "live_process" / "carved_payloads" / "runtime.wasm"
            carved.parent.mkdir(parents=True)
            carved.write_bytes(b"\x00asm")
            manifest = {
                "manifest_path": str(manifest_path),
                "process": _process(),
                "modules": [{"name": "pcsx2-qt.exe", "path": r"C:\pcsx2\pcsx2-qt.exe"}],
                "dumped_regions": [{"base_address_hex": "0x1000", "path": str(root / "region.bin")}],
                "carved_payloads": [{"kind": "wasm", "path": str(carved)}],
                "artifacts": {
                    "process": str(root / "process.json"),
                    "modules": str(root / "modules.json"),
                    "regions": str(root / "regions.json"),
                    "strings": str(root / "strings.txt"),
                },
                "summary": {"module_count": 1, "dumped_region_count": 1, "carved_payload_count": 1, "dumped_bytes": 4},
            }

            with patch("re_pro.analyzers.live_process.capture_live_process", return_value=manifest):
                LiveProcessAnalyzer().analyze(context, report)

            self.assertTrue(any(artifact.description == "Live process attach manifest" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "Live process memory snapshot captured" for finding in report.findings))
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in context.analysis_index.to_dict()["entities"]}
            self.assertIn("runtime_process:4242", entity_ids)
            self.assertTrue(any(entity_id.startswith("runtime_payload:") for entity_id in entity_ids))

    def test_live_process_analyzer_recovers_runtime_ddl_structs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.exe"
            target.write_bytes(b"MZ")
            region = root / "region_ddl.bin"
            region.write_text(
                "struct RuntimeActor { uint32 actor_id; vec3 world_position; float health; };",
                encoding="utf-8",
            )
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                live_process_settings=LiveProcessSettings(enabled=True, pid=4242),
            )
            manifest_path = root / "out" / "live_process" / "live_process_manifest.json"
            manifest = {
                "manifest_path": str(manifest_path),
                "process": _process(),
                "modules": [],
                "dumped_regions": [{"base_address_hex": "0x1000", "path": str(region)}],
                "carved_payloads": [],
                "artifacts": {
                    "process": str(root / "process.json"),
                    "modules": str(root / "modules.json"),
                    "regions": str(root / "regions.json"),
                    "strings": str(root / "strings.txt"),
                },
                "summary": {"module_count": 0, "dumped_region_count": 1, "carved_payload_count": 0, "dumped_bytes": region.stat().st_size},
            }

            with patch("re_pro.analyzers.live_process.capture_live_process", return_value=manifest):
                LiveProcessAnalyzer().analyze(context, report)

            self.assertIn("Runtime DDL schemas", report.frameworks)
            self.assertTrue(any(finding.title == "Runtime DDL structs recovered" for finding in report.findings))
            self.assertTrue(any(source.original_path.startswith("live_process/ddl/") for source in report.recovered_sources))
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in context.analysis_index.to_dict()["entities"]}
            self.assertTrue(any(entity_id.startswith("ddl_struct:") and "runtimeactor" in entity_id for entity_id in entity_ids))

    def test_list_live_processes_filters_query(self) -> None:
        with patch(
            "re_pro.live_process._query_process_list",
            return_value=[
                _process(),
                {"pid": 99, "name": "notepad.exe", "executable_path": r"C:\Windows\notepad.exe", "command_line": ""},
            ],
        ):
            result = list_live_processes("pcsx2")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["pid"], 4242)


def _process() -> dict[str, object]:
    return {
        "pid": 4242,
        "parent_pid": 100,
        "name": "pcsx2-qt.exe",
        "executable_path": r"C:\pcsx2\pcsx2-qt.exe",
        "command_line": r"C:\pcsx2\pcsx2-qt.exe game.iso",
    }


def _pe_blob() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
