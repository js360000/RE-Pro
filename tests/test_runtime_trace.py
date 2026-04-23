from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.runtime_trace import RuntimeTraceAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport, RuntimeTraceSettings


class RuntimeTraceAnalyzerTests(unittest.TestCase):
    def test_runtime_trace_adds_observation_artifacts_and_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                runtime_trace_settings=RuntimeTraceSettings(enabled=True, duration_seconds=1, use_frida=False),
            )

            observation = {
                "target": str(target),
                "pid": 4242,
                "exit_code": 0,
                "timed_out": False,
                "children": [{"ProcessId": 4243, "Name": "helper.exe", "CommandLine": "helper.exe"}],
                "connections": [{"protocol": "tcp", "remote_address": "127.0.0.1:443", "local_address": "127.0.0.1:50000", "pid": "4242"}],
                "modules": [{"image_name": "sample.exe", "pid": "4242", "modules": ["KERNEL32.dll", "USER32.dll"]}],
                "child_snapshots": [],
                "stdout_path": "",
                "stderr_path": "",
            }

            with patch.object(RuntimeTraceAnalyzer, "_observe_process", return_value=observation):
                RuntimeTraceAnalyzer().analyze(context, report)

            self.assertTrue(any(artifact.description == "Runtime observation manifest" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "Runtime observation captured" for finding in report.findings))
            index_payload = context.analysis_index.to_dict()
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in index_payload["entities"]}
            self.assertIn("runtime_process:4242", entity_ids)
            self.assertTrue(any(entity_id.startswith("runtime_endpoint:tcp:") for entity_id in entity_ids))

    def test_runtime_trace_indexes_frida_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                runtime_trace_settings=RuntimeTraceSettings(enabled=True, duration_seconds=1, use_frida=True),
            )

            observation = {
                "target": str(target),
                "pid": 4242,
                "exit_code": 0,
                "timed_out": False,
                "children": [],
                "connections": [],
                "modules": [],
                "child_snapshots": [],
                "stdout_path": "",
                "stderr_path": "",
            }
            frida_result = {
                "target": str(target),
                "pid": 4242,
                "events": [
                    {"kind": "file", "api": "CreateFileW", "path": r"C:\Temp\config.json"},
                    {"kind": "registry", "api": "RegOpenKeyExW", "subKey": r"Software\Vendor\App"},
                    {"kind": "network", "api": "connect"},
                ],
                "errors": [],
            }

            with (
                patch.object(RuntimeTraceAnalyzer, "_observe_process", return_value=observation),
                patch.object(RuntimeTraceAnalyzer, "_run_frida_trace", return_value=frida_result),
            ):
                RuntimeTraceAnalyzer().analyze(context, report)

            self.assertTrue(any(artifact.description == "Frida runtime hook events" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "Frida runtime hooks captured" for finding in report.findings))
            index_payload = context.analysis_index.to_dict()
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in index_payload["entities"]}
            self.assertIn(r"runtime_file:c:\temp\config.json", entity_ids)
            self.assertIn(r"runtime_registry:software\vendor\app", entity_ids)


if __name__ == "__main__":
    unittest.main()
