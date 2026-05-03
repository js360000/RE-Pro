from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.models import LlmAssistSettings
from re_pro.models import OutputSettings
from re_pro.models import RuntimeTraceSettings
from re_pro.profiles import analysis_settings_from_profile
from re_pro.profiles import build_analysis_profile
from re_pro.profiles import build_package_action_profile
from re_pro.profiles import list_profiles
from re_pro.profiles import load_profile
from re_pro.profiles import package_settings_from_profile
from re_pro.profiles import save_profile


class ProfileStoreTests(unittest.TestCase):
    def test_analysis_profiles_round_trip_and_search(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profile_path = save_profile(
                build_analysis_profile(
                    name="Z Code Deep Run",
                    target=str(root / "z-code.exe"),
                    output_root=str(root / "analysis_output"),
                    plugin_dirs=[str(root / "plugins")],
                    run_external_tools=True,
                    run_ghidra=True,
                    llm_settings=LlmAssistSettings(
                        enabled=True,
                        model="gpt-5.5",
                        auth_provider="codex-oauth",
                        codex_auth_path=str(root / "auth.json"),
                        reasoning_effort="xhigh",
                        user_task="map main update flow",
                    ),
                    runtime_trace_settings=RuntimeTraceSettings(enabled=True, duration_seconds=12, use_frida=True),
                    output_settings=OutputSettings(
                        enabled=True,
                        profile="source-first",
                        mode="copy",
                        include=["usability"],
                        exclude=["logs"],
                        folder_map={"recovered_sources": "src/recovered"},
                        analyzer_include=["native"],
                        analyzer_exclude=["ghidra"],
                        max_run_artifact_bytes=128 * 1024 * 1024,
                        max_run_artifact_count=64,
                    ),
                    report={
                        "target": str(root / "z-code.exe"),
                        "output_dir": str(root / "analysis_output" / "z-code_20260423_170000"),
                        "frameworks": ["Tauri", "Next.js (Turbopack)"],
                        "findings": [{"title": "x", "summary": "y"}],
                        "artifacts": [{"path": str(root / "artifact.txt"), "category": "report", "description": "Artifact"}],
                        "recovered_sources": [{"original_path": "src/app.tsx", "restored_path": str(root / "src" / "app.tsx")}],
                    },
                ),
                profiles_root=root / "profiles",
            )

            self.assertTrue(profile_path.exists())
            profile = load_profile(profile_path, profiles_root=root / "profiles")
            settings = analysis_settings_from_profile(profile)
            self.assertEqual(settings["target"], str(root / "z-code.exe"))
            self.assertTrue(settings["run_external_tools"])
            self.assertTrue(settings["run_ghidra"])
            self.assertTrue(settings["llm_settings"].enabled)
            self.assertEqual(settings["llm_settings"].model, "gpt-5.5")
            self.assertEqual(settings["llm_settings"].auth_provider, "codex-oauth")
            self.assertEqual(settings["llm_settings"].reasoning_effort, "xhigh")
            self.assertEqual(settings["runtime_trace_settings"].duration_seconds, 12)
            self.assertTrue(settings["output_settings"].enabled)
            self.assertEqual(settings["output_settings"].profile, "source-first")
            self.assertEqual(settings["output_settings"].mode, "copy")
            self.assertEqual(settings["output_settings"].folder_map["recovered_sources"], "src/recovered")
            self.assertEqual(settings["output_settings"].analyzer_include, ["native"])
            self.assertEqual(settings["output_settings"].analyzer_exclude, ["ghidra"])
            self.assertEqual(settings["output_settings"].max_run_artifact_bytes, 128 * 1024 * 1024)
            self.assertEqual(settings["output_settings"].max_run_artifact_count, 64)

            entries = list_profiles(profiles_root=root / "profiles", query="turbopack")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["profile_type"], "analysis")

    def test_package_profiles_round_trip_without_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profile_path = save_profile(
                build_package_action_profile(
                    name="APK Rebuild",
                    workspace_root=str(root / "workspace"),
                    ecosystem="android-gradle",
                    action="sign-apk",
                    artifact_path=str(root / "app.apk"),
                    output_path=str(root / "app.signed.apk"),
                    keystore_path=str(root / "debug.keystore"),
                    key_alias="androiddebugkey",
                    target_root=str(root / "overlay"),
                    compression="lzma",
                    compression_level=7,
                    block_size=0x8000,
                    result={"ok": True, "signed_artifact": str(root / "app.signed.apk"), "store_pass": "secret"},
                ),
                profiles_root=root / "profiles",
            )

            profile = load_profile(profile_path, profiles_root=root / "profiles")
            settings = package_settings_from_profile(profile)
            self.assertEqual(settings["ecosystem"], "android-gradle")
            self.assertEqual(settings["action"], "sign-apk")
            self.assertEqual(settings["output_path"], str(root / "app.signed.apk"))
            self.assertEqual(settings["compression"], "lzma")
            self.assertEqual(settings["compression_level"], 7)
            self.assertEqual(settings["block_size"], 0x8000)
            self.assertEqual(profile["last_result"]["signed_artifact"], str(root / "app.signed.apk"))
            self.assertNotIn("store_pass", profile["last_result"])


if __name__ == "__main__":
    unittest.main()
