from __future__ import annotations

import io
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
                    ],
                ):
                    exit_code = main()

            self.assertEqual(exit_code, 0)
            llm_settings = captured["llm_settings"]
            self.assertEqual(llm_settings.model, "gpt-5.5")
            self.assertEqual(llm_settings.auth_provider, "codex-oauth")
            self.assertEqual(llm_settings.codex_auth_path, str(auth_path))
            self.assertEqual(llm_settings.reasoning_effort, "xhigh")

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


if __name__ == "__main__":
    unittest.main()
