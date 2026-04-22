from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.llm import LLMAssistAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.llm_assist import run_llm_assist_job
from re_pro.models import AnalysisReport, LlmAssistSettings


class _FakeResponses:
    def __init__(self) -> None:
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return SimpleNamespace(
                id="resp_1",
                output=[
                    SimpleNamespace(
                        type="function_call",
                        call_id="call_1",
                        name="write_reconstruction_file",
                        arguments=json.dumps(
                            {
                                "relative_path": "src/app_approx.ts",
                                "content": "// Approximate reconstruction\nexport const app = true;\n",
                                "rationale": "Recovered from strings and metadata",
                                "confidence": 0.72,
                                "evidence_refs": ["context"],
                            }
                        ),
                    )
                ],
                output_text="",
            )
        return SimpleNamespace(
            id="resp_2",
            output=[
                SimpleNamespace(
                    type="message",
                    content=[SimpleNamespace(type="output_text", text="Reconstruction complete.")],
                )
            ],
            output_text="Reconstruction complete.",
        )


class _FakeClient:
    def __init__(self) -> None:
        self.responses = _FakeResponses()


class LlmAssistTests(unittest.TestCase):
    def test_run_llm_assist_job_writes_reconstructed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            context_file = root / "context.txt"
            context_file.write_text("sample reverse engineering context", encoding="utf-8")
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "llm_dir": str(root / "llm"),
                        "reconstructed_root": str(root / "llm" / "reconstructed_src"),
                        "settings": {
                            "model": "gpt-5.4",
                            "reasoning_effort": "high",
                            "verbosity": "medium",
                            "max_output_tokens": 4000,
                            "user_task": "Reconstruct the core app entrypoint",
                            "allow_dependency_installs": True,
                            "run_recompile_checks": True,
                        },
                        "report": {"target": "sample.exe", "frameworks": ["Native Windows application"]},
                        "context_items": [
                            {
                                "name": "context",
                                "path": str(context_file),
                                "summary": "test",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_llm_assist_job(request_path, client_factory=_FakeClient)

            self.assertEqual(result["status"], "completed")
            reconstructed = root / "llm" / "reconstructed_src" / "src" / "app_approx.ts"
            self.assertTrue(reconstructed.exists())
            self.assertIn("Approximate reconstruction", reconstructed.read_text(encoding="utf-8"))

    def test_llm_analyzer_auto_mode_runs_when_sources_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            report.target_type = "portable-executable"
            report.add_framework("Native Windows application")
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                llm_settings=LlmAssistSettings(
                    enabled=False,
                    auto=True,
                    model="gpt-5.4",
                    reasoning_effort="high",
                    verbosity="medium",
                    background=False,
                    max_output_tokens=4000,
                    user_task="Focus on the launcher logic",
                    allow_dependency_installs=True,
                    run_recompile_checks=True,
                ),
            )

            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                with patch("re_pro.analyzers.llm.run_llm_assist_job", return_value={"written_files": []}):
                    LLMAssistAnalyzer().analyze(context, report)

            self.assertTrue(any("LLM reconstruction completed" == finding.title for finding in report.findings))
            self.assertTrue((output_dir / "llm_assist" / "request.json").exists())


if __name__ == "__main__":
    unittest.main()
