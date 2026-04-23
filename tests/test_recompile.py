from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analysis_diff import create_patch_bundle_from_runs
from re_pro.recompile import apply_patch_bundle, create_recompile_workspace, run_packaging_action


class RecompileWorkflowTests(unittest.TestCase):
    def test_android_signing_action_prefers_zipalign_then_apksigner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "workspace"
            workspace.mkdir()
            apk_path = root / "sample.apk"
            ks_path = root / "debug.keystore"
            apk_path.write_bytes(b"apk")
            ks_path.write_bytes(b"keystore")

            calls: list[list[str]] = []

            def fake_resolve(candidates):
                executable = candidates[0][0]
                if executable == "zipalign":
                    return [str(root / "sdk" / "zipalign.exe")]
                if executable == "apksigner":
                    return [str(root / "sdk" / "apksigner.bat")]
                return None

            def fake_run(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                calls.append(command)
                return 0, "ok", ""

            with patch("re_pro.recompile.resolve_command", side_effect=fake_resolve):
                with patch("re_pro.recompile.run_command_logged", side_effect=fake_run):
                    result = run_packaging_action(
                        workspace_root=workspace,
                        ecosystem="android-gradle",
                        action="sign-apk",
                        artifact_path=str(apk_path),
                        keystore_path=str(ks_path),
                        key_alias="androiddebugkey",
                        store_pass="android",
                        key_pass="android",
                    )

            self.assertTrue(result["ok"])
            self.assertEqual(len(calls), 2)
            self.assertIn("zipalign", calls[0][0].lower())
            self.assertIn("apksigner", calls[1][0].lower())
            self.assertTrue(str(result["signed_artifact"]).endswith(".signed.apk"))

    def test_electron_packaging_action_runs_package_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.exe", "target_type": "portable-executable", "artifacts": [], "recovered_sources": []},
                ["Electron"],
            )
            workspace_root = Path(metadata["workspace_root"])
            calls: list[list[str]] = []

            def fake_resolve(candidates):
                if candidates[0][0] == "npm":
                    return [str(root / "node" / "npm.cmd")]
                return None

            def fake_run(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                calls.append(command)
                return 0, "packaged", ""

            with patch("re_pro.recompile.resolve_command", side_effect=fake_resolve):
                with patch("re_pro.recompile.run_command_logged", side_effect=fake_run):
                    result = run_packaging_action(
                        workspace_root=workspace_root,
                        ecosystem="electron",
                        action="repack",
                    )

            self.assertTrue(result["ok"])
            self.assertEqual(calls[0][-2:], ["run", "package"])

    def test_patch_bundle_can_be_created_from_diff_and_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_run = root / "base"
            head_run = root / "head"
            base_run.mkdir()
            head_run.mkdir()

            restored = head_run / "recovered_sources" / "src" / "feature.ts"
            restored.parent.mkdir(parents=True, exist_ok=True)
            restored.write_text("export const feature = true;\n", encoding="utf-8")
            manifest = head_run / "manifest.json"
            manifest.write_text('{"name":"head"}', encoding="utf-8")

            (base_run / "report.json").write_text(
                json.dumps({"target": "base.exe", "frameworks": [], "findings": [], "artifacts": [], "recovered_sources": []}),
                encoding="utf-8",
            )
            (base_run / "analysis_index.json").write_text(json.dumps({"entities": [], "relations": []}), encoding="utf-8")
            (head_run / "report.json").write_text(
                json.dumps(
                    {
                        "target": "head.exe",
                        "frameworks": ["Electron"],
                        "findings": [],
                        "artifacts": [{"path": str(manifest), "category": "manifest", "description": "Manifest"}],
                        "recovered_sources": [{"original_path": "src/feature.ts", "restored_path": str(restored)}],
                    }
                ),
                encoding="utf-8",
            )
            (head_run / "analysis_index.json").write_text(json.dumps({"entities": [], "relations": []}), encoding="utf-8")

            bundle = create_patch_bundle_from_runs(base_run, head_run, root / "bundle")
            target_root = root / "target"
            result = apply_patch_bundle(bundle_root=Path(bundle["bundle_root"]), target_root=target_root)

            self.assertTrue(bundle["ok"])
            self.assertTrue(result["ok"])
            self.assertTrue((target_root / "src" / "feature.ts").exists())
            self.assertTrue((target_root / "artifacts" / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
