from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.cli import main
from re_pro.models import AnalysisReport
from re_pro.profiles import build_analysis_profile
from re_pro.profiles import save_profile


class CliProfileTests(unittest.TestCase):
    def test_analyze_accepts_codex_oauth_llm_options(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            auth_path = root / "auth.json"
            target.write_bytes(b"MZ")
            auth_path.write_text("{}", encoding="utf-8")
            report = AnalysisReport(
                target=str(target),
                target_type="portable-executable",
                output_dir=str(root / "analysis_output" / "sample_20260423_180000"),
            )
            captured = {}

            class FakeEngine:
                def __init__(self, *args, **kwargs) -> None:
                    captured.update(kwargs)

                def analyze(self, target_path):
                    self.target = target_path
                    return report

            with patch("re_pro.cli.ReverseEngineeringEngine", FakeEngine):
                with patch(
                    "sys.argv",
                    [
                        "re-pro",
                        "analyze",
                        str(target),
                        "--llm",
                        "--llm-model",
                        "gpt-5.5",
                        "--llm-auth",
                        "codex-oauth",
                        "--codex-auth-json",
                        str(auth_path),
                        "--llm-reasoning",
                        "xhigh",
                        "--llm-foreground",
                    ],
                ):
                    exit_code = main()

            self.assertEqual(exit_code, 0)
            llm_settings = captured["llm_settings"]
            self.assertEqual(llm_settings.model, "gpt-5.5")
            self.assertEqual(llm_settings.auth_provider, "codex-oauth")
            self.assertEqual(llm_settings.codex_auth_path, str(auth_path))
            self.assertEqual(llm_settings.reasoning_effort, "xhigh")
            self.assertFalse(llm_settings.background)

    def test_analyze_can_run_from_saved_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profile_path = save_profile(
                build_analysis_profile(
                    name="Saved Run",
                    target=str(root / "sample.exe"),
                    output_root=str(root / "analysis_output"),
                ),
                profiles_root=root / "profiles",
            )

            report = AnalysisReport(
                target=str(root / "sample.exe"),
                target_type="portable-executable",
                output_dir=str(root / "analysis_output" / "sample_20260423_180000"),
            )

            class FakeEngine:
                def __init__(self, *args, **kwargs) -> None:
                    self.kwargs = kwargs

                def analyze(self, target):
                    self.target = target
                    return report

            stdout = io.StringIO()
            with patch("re_pro.cli.ReverseEngineeringEngine", FakeEngine):
                with patch("sys.argv", ["re-pro", "analyze", "--profile", str(profile_path), "--profiles-root", str(root / "profiles")]):
                    with patch("sys.stdout", stdout):
                        exit_code = main()

            self.assertEqual(exit_code, 0)
            self.assertIn("Analysis complete:", stdout.getvalue())
            saved_profiles = list((root / "profiles" / "analysis").glob("*.json"))
            self.assertGreaterEqual(len(saved_profiles), 2)

    def test_inspect_run_prints_quality_and_function_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "sample_20260423_180000"
            usability = run_dir / "usability"
            usability.mkdir(parents=True)
            (run_dir / "report.json").write_text(json.dumps({"target": "sample.exe"}), encoding="utf-8")
            (usability / "recovery_quality.json").write_text(
                json.dumps(
                    {
                        "summary": {
                            "function_count": 3,
                            "class_count": 1,
                            "source_count": 2,
                            "high_confidence_source_ratio": 0.5,
                            "stub_target_count": 1,
                            "function_evidence_page_count": 1,
                        }
                    }
                ),
                encoding="utf-8",
            )
            (usability / "recovery_quality.md").write_text("# Recovery Quality\n", encoding="utf-8")
            (usability / "evidence_graph.json").write_text(
                json.dumps({"top_hubs": [{"degree": 4, "kind": "class", "label": "Widget", "entity_id": "class:Widget"}]}),
                encoding="utf-8",
            )
            (usability / "evidence_graph.html").write_text("<html></html>", encoding="utf-8")
            (usability / "stub_elimination_queue.json").write_text(
                json.dumps({"targets": [{"priority": 90, "kind": "function", "label": "Widget::Render", "reason": "generic function name"}]}),
                encoding="utf-8",
            )
            (usability / "function_evidence_pages.json").write_text(
                json.dumps({"pages": [{"confidence": "medium", "label": "Widget::Render", "address": "0x140001000", "path": "Widget_Render.md"}]}),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with patch("sys.argv", ["re-pro", "inspect-run", str(run_dir), "--query", "Widget"]):
                with patch("sys.stdout", stdout):
                    exit_code = main()

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Recovery Quality:", output)
            self.assertIn("Widget::Render", output)
            self.assertIn("evidence_graph_html", output)

    def test_inspect_run_can_emit_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "sample_20260423_180000"
            usability = run_dir / "usability"
            usability.mkdir(parents=True)
            (run_dir / "report.json").write_text(json.dumps({"target": "sample.exe"}), encoding="utf-8")
            (usability / "recovery_quality.json").write_text(json.dumps({"summary": {"function_count": 1}}), encoding="utf-8")
            (usability / "stub_elimination_queue.json").write_text(json.dumps({"targets": []}), encoding="utf-8")
            (usability / "evidence_graph.json").write_text(json.dumps({"top_hubs": []}), encoding="utf-8")
            (usability / "function_evidence_pages.json").write_text(json.dumps({"pages": []}), encoding="utf-8")

            stdout = io.StringIO()
            with patch("sys.argv", ["re-pro", "inspect-run", str(run_dir), "--json"]):
                with patch("sys.stdout", stdout):
                    exit_code = main()

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["target"], "sample.exe")
            self.assertEqual(payload["quality"]["function_count"], 1)


if __name__ == "__main__":
    unittest.main()
