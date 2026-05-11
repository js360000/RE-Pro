from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from re_pro.analyzers.llm import LLMAssistAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.llm_assist import _dispatch_tool_call, run_llm_assist_job
from re_pro.llm_auth import llm_auth_available, llm_auth_status, load_codex_oauth_token
from re_pro.models import AnalysisReport, LlmAssistSettings
from tests import _path_setup  # noqa: F401


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
    def test_codex_oauth_auth_json_is_detected_without_exposing_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = Path(temp_dir) / "auth.json"
            auth_path.write_text(
                json.dumps(
                    {
                        "auth_mode": "chatgpt",
                        "tokens": {
                            "access_token": "secret-access-token",
                            "refresh_token": "secret-refresh-token",
                        },
                    }
                ),
                encoding="utf-8",
            )
            settings = LlmAssistSettings(auth_provider="codex-oauth", codex_auth_path=str(auth_path))

            token = load_codex_oauth_token(auth_path)
            status = llm_auth_status(settings)

            self.assertIsNotNone(token)
            self.assertEqual(token.access_token, "secret-access-token")
            self.assertTrue(llm_auth_available(settings))
            self.assertTrue(status["has_codex_oauth_token"])
            self.assertEqual(status["selected"], "codex-oauth")
            self.assertNotIn("secret-access-token", json.dumps(status))

    def test_llm_analyzer_context_includes_naming_hints(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            report.add_recovered_source("src/Foo.cpp", str(output_dir / "native" / "Foo.cpp"), "pdb_symbols")
            context = AnalysisContext(target=target, output_dir=output_dir)
            context.analysis_index.add_entity("class", "msvc_rtti:foo", "Foo")
            context.analysis_index.add_entity("function", "ghidra:0x140001000", "Foo::Bar", attributes={"namespace": "Foo"})

            items = LLMAssistAnalyzer()._build_context_items(context, report, output_dir / "llm")
            naming_item = next(item for item in items if item["name"] == "naming_hints.json")
            payload = json.loads(Path(naming_item["path"]).read_text(encoding="utf-8"))

            self.assertIn("src/Foo.cpp", payload["preferred_source_paths"])
            self.assertIn("Foo", payload["class_names"])
            self.assertIn("Foo::Bar", payload["function_names"])

    def test_llm_context_prioritizes_decompiler_artifacts_and_directory_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            llm_dir = output_dir / "llm"
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            status_path = output_dir / "ghidra" / "status.json"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(json.dumps({"state": "completed"}), encoding="utf-8")
            targeted = output_dir / "ghidra" / "exports" / "targeted_decompilation.json"
            targeted.parent.mkdir(parents=True)
            targeted.write_text(json.dumps({"methods": [{"name": "Fixture::AppController::Run"}]}), encoding="utf-8")
            callgraph = output_dir / "ghidra" / "exports" / "class_callgraph_manifest.json"
            callgraph.write_text(json.dumps({"classes": [{"name": "Fixture::AppController"}]}), encoding="utf-8")
            pseudo_dir = output_dir / "ghidra" / "exports" / "class_pseudo_cpp"
            pseudo_dir.mkdir()
            (pseudo_dir / "Fixture__AppController.cpp").write_text("void Fixture::AppController::Run() {}\n", encoding="utf-8")
            report.add_artifact(str(status_path), "metadata", "Ghidra status")
            report.add_artifact(str(pseudo_dir), "directory", "Ghidra class-scoped pseudo-C++ directory")
            report.add_artifact(str(callgraph), "metadata", "Ghidra class callgraph manifest")
            report.add_artifact(str(targeted), "metadata", "Ghidra targeted pseudo-code export")
            context = AnalysisContext(target=target, output_dir=output_dir)

            items = LLMAssistAnalyzer()._build_context_items(context, report, llm_dir)
            names = [str(item["name"]) for item in items]

            self.assertTrue(any("class_callgraph_manifest.json" in name for name in names))
            self.assertTrue(any("targeted_decompilation.json" in name for name in names))
            self.assertTrue(any("Fixture__AppController.cpp" in name for name in names))
            callgraph_index = next(index for index, name in enumerate(names) if "class_callgraph_manifest.json" in name)
            targeted_index = next(index for index, name in enumerate(names) if "targeted_decompilation.json" in name)
            status_index = next(index for index, name in enumerate(names) if "status.json" in name)
            self.assertLess(callgraph_index, status_index)
            self.assertLess(targeted_index, status_index)

    def test_foreground_llm_waits_for_pending_tool_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            status_path = output_dir / "ghidra" / "status.json"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(json.dumps({"state": "running"}), encoding="utf-8")
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            log_messages: list[str] = []
            context = AnalysisContext(target=target, output_dir=output_dir, logger=log_messages.append)

            def finish_status() -> None:
                time.sleep(0.15)
                status_path.write_text(json.dumps({"state": "completed"}), encoding="utf-8")

            worker = threading.Thread(target=finish_status)
            worker.start()
            try:
                with patch.dict(os.environ, {"RE_PRO_LLM_CONTEXT_WAIT_SECONDS": "2"}):
                    LLMAssistAnalyzer()._wait_for_async_tool_context(context)
            finally:
                worker.join()

            self.assertTrue(any("waiting for async RE context" in message for message in log_messages))

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
                            },
                            {
                                "name": "naming_hints.json",
                                "path": str(root / "naming_hints.json"),
                                "summary": "naming hints",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "naming_hints.json").write_text(json.dumps({}), encoding="utf-8")

            log_messages: list[str] = []
            result = run_llm_assist_job(request_path, client_factory=_FakeClient, logger=log_messages.append)

            self.assertEqual(result["status"], "completed")
            reconstructed = root / "llm" / "reconstructed_src" / "src" / "app_approx.ts"
            self.assertTrue(reconstructed.exists())
            self.assertIn("Approximate reconstruction", reconstructed.read_text(encoding="utf-8"))
            self.assertTrue(any(message == "LLM reconstruction output:" for message in log_messages))
            self.assertTrue(any("Reconstruction complete." in message for message in log_messages))
            llm_log = root / "llm" / "llm.log"
            self.assertIn("LLM reconstruction output:", llm_log.read_text(encoding="utf-8"))

    def test_run_llm_assist_job_uses_codex_cli_for_codex_oauth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_script = fake_bin / "fake_codex.py"
            fake_script.write_text(
                "\n".join(
                    [
                        "import json, sys",
                        "from pathlib import Path",
                        "args = sys.argv[1:]",
                        "sys.stdin.read()",
                        "last = Path(args[args.index('-o') + 1])",
                        "last.write_text(json.dumps({",
                        "  'summary_markdown': '## Codex CLI complete',",
                        "  'written_files': [],",
                        "  'reconstructed_files': [{'relative_path': 'src/codex_cli.cpp', 'content': '// codex cli backend\\\\n', 'confidence': 0.8, 'rationale': 'fixture'}],",
                        "  'validation_notes': ['fixture validation']",
                        "}), encoding='utf-8')",
                        "print('fake codex cli ran')",
                    ]
                ),
                encoding="utf-8",
            )
            fake_cmd = fake_bin / "codex.cmd"
            fake_cmd.write_text("@echo off\r\npy \"%~dp0fake_codex.py\" %*\r\n", encoding="utf-8")
            auth_path = root / "auth.json"
            auth_path.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {"access_token": "codex-token"}}), encoding="utf-8")
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "llm_dir": str(root / "llm"),
                        "reconstructed_root": str(root / "llm" / "reconstructed_src"),
                        "settings": {
                            "model": "gpt-5.5",
                            "auth_provider": "codex-oauth",
                            "codex_auth_path": str(auth_path),
                            "reasoning_effort": "medium",
                            "verbosity": "medium",
                            "max_output_tokens": 4000,
                        },
                        "report": {"target": "sample.exe", "frameworks": ["Native Windows application"]},
                        "context_items": [],
                    }
                ),
                encoding="utf-8",
            )

            env = {
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                "OPENAI_API_KEY": "",
            }
            with patch.dict(os.environ, env):
                result = run_llm_assist_job(request_path)

            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["backend"], "codex-cli")
            self.assertTrue((root / "llm" / "reconstructed_src" / "src" / "codex_cli.cpp").exists())
            self.assertIn("Codex CLI complete", (root / "llm" / "assistant_summary.md").read_text(encoding="utf-8"))
            self.assertIn("backend", json.loads((root / "llm" / "status.json").read_text(encoding="utf-8")))

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
            self.assertTrue(any(artifact.description == "LLM reconstruction log" for artifact in report.artifacts))

    def test_llm_analyzer_accepts_codex_oauth_auth_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            target = root / "sample.exe"
            auth_path = root / "auth.json"
            target.write_bytes(b"MZ")
            auth_path.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {"access_token": "codex-token"}}), encoding="utf-8")
            report = AnalysisReport(target=str(target), output_dir=str(output_dir), target_type="portable-executable")
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                llm_settings=LlmAssistSettings(
                    enabled=True,
                    model="gpt-5.5",
                    auth_provider="codex-oauth",
                    codex_auth_path=str(auth_path),
                    reasoning_effort="xhigh",
                    background=False,
                ),
            )

            with patch.dict(os.environ, {}, clear=True):
                with patch("re_pro.analyzers.llm.run_llm_assist_job", return_value={"written_files": []}):
                    LLMAssistAnalyzer().analyze(context, report)

            request = json.loads((output_dir / "llm_assist" / "request.json").read_text(encoding="utf-8"))
            self.assertEqual(request["settings"]["model"], "gpt-5.5")
            self.assertEqual(request["settings"]["auth_provider"], "codex-oauth")
            self.assertEqual(request["settings"]["codex_auth_path"], str(auth_path))
            self.assertEqual(request["settings"]["reasoning_effort"], "xhigh")

    def test_llm_analyzer_records_foreground_failures_without_aborting(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(output_dir), target_type="portable-executable")
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                llm_settings=LlmAssistSettings(
                    enabled=True,
                    model="gpt-5.5",
                    background=False,
                ),
            )

            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                with patch("re_pro.analyzers.llm.run_llm_assist_job", side_effect=RuntimeError("missing scope")):
                    LLMAssistAnalyzer().analyze(context, report)

            failure = next(finding for finding in report.findings if finding.title == "LLM reconstruction failed")
            self.assertEqual(failure.severity, "warning")
            self.assertIn("missing scope", failure.details or "")
            self.assertTrue(any(artifact.description == "LLM reconstruction status" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == "LLM reconstruction log" for artifact in report.artifacts))

    def test_index_tools_expose_entities_and_relations(self) -> None:
        analysis_index = {
            "entities": [
                {"kind": "function", "key": "ghidra:0x401000", "label": "entry", "attributes": {"tool": "ghidra"}},
                {"kind": "string", "key": "ghidra:0x402000", "label": "Success", "attributes": {"tool": "ghidra"}},
            ],
            "relations": [
                {"source": "function:ghidra:0x401000", "predicate": "references", "target": "string:ghidra:0x402000", "attributes": {}},
            ],
        }

        search_result = _dispatch_tool_call(
            "search_index",
            {"query": "success"},
            context_items=[],
            analysis_index=analysis_index,
            reconstructed_root=Path.cwd(),
            writes=[],
            validations=[],
            recompile_root=Path.cwd(),
            settings={},
        )
        entity_result = _dispatch_tool_call(
            "get_index_entity",
            {"entity_id": "function:ghidra:0x401000"},
            context_items=[],
            analysis_index=analysis_index,
            reconstructed_root=Path.cwd(),
            writes=[],
            validations=[],
            recompile_root=Path.cwd(),
            settings={},
        )

        self.assertEqual(search_result["matches"][0]["label"], "Success")
        self.assertEqual(entity_result["entity"]["label"], "entry")
        self.assertEqual(entity_result["relations"][0]["predicate"], "references")

    def test_write_reconstruction_file_rejects_generic_path_when_naming_hints_exist(self) -> None:
        result = _dispatch_tool_call(
            "write_reconstruction_file",
            {
                "relative_path": "src/app_approx.ts",
                "content": "export const x = 1;\n",
                "confidence": 0.8,
                "evidence_refs": ["context"],
            },
            context_items=[{"name": "context", "path": __file__, "summary": "test"}],
            analysis_index={},
            reconstructed_root=Path.cwd(),
            writes=[],
            validations=[],
            recompile_root=Path.cwd(),
            settings={},
            naming_hints={"preferred_source_paths": ["src/Foo.cpp"], "class_names": ["Foo"], "function_names": ["Foo::Bar"]},
        )

        self.assertIn("naming_hints", result["error"])


if __name__ == "__main__":
    unittest.main()
