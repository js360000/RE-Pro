from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from re_pro.analysis_diff import create_patch_bundle_from_runs
from re_pro.psarc import extract_psarc, pack_psarc_from_mapping, parse_psarc
from re_pro.recompile import (
    apply_patch_bundle,
    create_recompile_workspace,
    rebuild_zip_archive_with_overlay,
    run_packaging_action,
)
from tests import _path_setup  # noqa: F401


class RecompileWorkflowTests(unittest.TestCase):
    def test_android_rebuild_apk_from_tree_creates_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.apk", "target_type": "android-package", "artifacts": [], "recovered_sources": []},
                ["Android APK"],
            )
            workspace_root = Path(metadata["workspace_root"])
            source_root = workspace_root / "projects" / "android_studio" / "app" / "src" / "main"
            (source_root / "AndroidManifest.xml").write_text("<manifest package='repro.recovered' />", encoding="utf-8")
            assets_dir = source_root / "assets"
            assets_dir.mkdir(parents=True, exist_ok=True)
            (assets_dir / "app.js").write_text("console.log('hi');", encoding="utf-8")

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="android-gradle",
                action="rebuild-apk",
            )

            self.assertTrue(result["ok"])
            rebuilt = Path(result["rebuilt_artifact"])
            self.assertTrue(rebuilt.exists())

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

    def test_android_rebuild_aab_from_tree_creates_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.aab", "target_type": "android-app-bundle", "artifacts": [], "recovered_sources": []},
                ["Android APK"],
            )
            workspace_root = Path(metadata["workspace_root"])
            source_root = workspace_root / "projects" / "android_studio" / "app" / "src" / "main"
            (source_root / "AndroidManifest.xml").write_text("<manifest package='repro.bundle' />", encoding="utf-8")
            assets_dir = source_root / "assets"
            assets_dir.mkdir(parents=True, exist_ok=True)
            (assets_dir / "bundle.js").write_text("console.log('bundle');", encoding="utf-8")

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="android-gradle",
                action="rebuild-aab",
            )

            self.assertTrue(result["ok"])
            self.assertTrue(str(result["rebuilt_artifact"]).endswith(".aab"))

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

    def test_electron_asar_repack_uses_asar_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.exe", "target_type": "portable-executable", "artifacts": [], "recovered_sources": []},
                ["Electron"],
            )
            workspace_root = Path(metadata["workspace_root"])
            app_root = workspace_root / "projects" / "electron_app" / "resources" / "app"
            (app_root / "main.js").write_text("console.log('main');", encoding="utf-8")
            calls: list[list[str]] = []

            def fake_resolve(candidates):
                executable = candidates[0][0]
                if executable == "asar":
                    return [str(root / "node_modules" / ".bin" / "asar.cmd")]
                return None

            def fake_run(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                calls.append(command)
                return 0, "packed", ""

            with patch("re_pro.recompile.resolve_command", side_effect=fake_resolve):
                with patch("re_pro.recompile.run_command_logged", side_effect=fake_run):
                    result = run_packaging_action(
                        workspace_root=workspace_root,
                        ecosystem="electron",
                        action="repack-asar",
                    )

            self.assertTrue(result["ok"])
            self.assertIn("asar", calls[0][0].lower())
            self.assertTrue(str(result["rebuilt_artifact"]).endswith("app.asar"))

    def test_electron_asset_staging_copies_tree_into_app_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.exe", "target_type": "portable-executable", "artifacts": [], "recovered_sources": []},
                ["Electron"],
            )
            workspace_root = Path(metadata["workspace_root"])
            incoming_root = workspace_root / "projects" / "electron_app" / "dist" / "incoming" / "src"
            incoming_root.mkdir(parents=True, exist_ok=True)
            (incoming_root / "renderer.js").write_text("console.log('renderer');", encoding="utf-8")

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="electron",
                action="stage-assets",
            )

            self.assertTrue(result["ok"])
            self.assertTrue((workspace_root / "projects" / "electron_app" / "resources" / "app" / "src" / "renderer.js").exists())

    def test_tauri_sidecar_staging_copies_files_into_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.exe", "target_type": "portable-executable", "artifacts": [], "recovered_sources": []},
                ["Tauri"],
            )
            workspace_root = Path(metadata["workspace_root"])
            source_sidecars = root / "sidecars"
            source_sidecars.mkdir()
            (source_sidecars / "helper.exe").write_bytes(b"helper")

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="tauri",
                action="stage-sidecars",
                target_root=str(source_sidecars),
            )

            self.assertTrue(result["ok"])
            self.assertTrue((workspace_root / "projects" / "tauri_app" / "src-tauri" / "sidecars" / "helper.exe").exists())

    def test_tauri_asset_staging_copies_tree_into_dist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata = create_recompile_workspace(
                root,
                {"target": "app.exe", "target_type": "portable-executable", "artifacts": [], "recovered_sources": []},
                ["Tauri"],
            )
            workspace_root = Path(metadata["workspace_root"])
            incoming_root = workspace_root / "projects" / "tauri_app" / "dist" / "incoming" / "assets"
            incoming_root.mkdir(parents=True, exist_ok=True)
            (incoming_root / "index.js").write_text("console.log('tauri');", encoding="utf-8")

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="tauri",
                action="stage-assets",
            )

            self.assertTrue(result["ok"])
            self.assertTrue((workspace_root / "projects" / "tauri_app" / "dist" / "assets" / "index.js").exists())

    def test_archive_package_action_creates_new_psarc_from_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace_root = root / "workspace"
            source_root = root / "assets"
            (source_root / "scripts").mkdir(parents=True)
            (source_root / "scripts" / "boot.lua").write_text("return true\n", encoding="utf-8")
            (source_root / "readme.txt").write_text("asset pack\n", encoding="utf-8")
            output_path = root / "dist" / "assets.psarc"

            result = run_packaging_action(
                workspace_root=workspace_root,
                ecosystem="archive",
                action="create-psarc",
                target_root=str(source_root),
                output_path=str(output_path),
                compression="lzma",
                compression_level=9,
                block_size=64,
            )

            self.assertTrue(result["ok"])
            self.assertTrue(output_path.exists())
            archive = parse_psarc(output_path, inspect_blocks=True)
            self.assertEqual(archive.compression, "lzma")
            self.assertEqual(archive.manifest_paths, ["readme.txt", "scripts/boot.lua"])
            extract_dir = root / "extract"
            extract_psarc(output_path, extract_dir)
            self.assertEqual((extract_dir / "scripts" / "boot.lua").read_text(encoding="utf-8"), "return true\n")

    def test_archive_package_action_rebuilds_psarc_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "base.psarc"
            pack_psarc_from_mapping({"data/config.txt": b"old\n"}, archive_path, compression="zlib", block_size=64)
            overlay = root / "overlay"
            (overlay / "data").mkdir(parents=True)
            (overlay / "data" / "config.txt").write_text("new\n", encoding="utf-8")
            output_path = root / "rebuilt.psarc"

            result = run_packaging_action(
                workspace_root=root / "workspace",
                ecosystem="archive",
                action="overlay-rebuild",
                artifact_path=str(archive_path),
                target_root=str(overlay),
                output_path=str(output_path),
            )

            self.assertTrue(result["ok"])
            extract_dir = root / "extract"
            extract_psarc(output_path, extract_dir)
            self.assertEqual((extract_dir / "data" / "config.txt").read_text(encoding="utf-8"), "new\n")

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

    def test_archive_overlay_rebuild_replaces_and_adds_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_archive = root / "base.apk"
            overlay_root = root / "overlay"
            overlay_root.mkdir()
            with zipfile.ZipFile(base_archive, "w") as archive:
                archive.writestr("AndroidManifest.xml", "<manifest package='base' />")
                archive.writestr("assets/app.js", "console.log('base');")
            (overlay_root / "AndroidManifest.xml").write_text("<manifest package='patched' />", encoding="utf-8")
            assets_dir = overlay_root / "assets"
            assets_dir.mkdir()
            (assets_dir / "new.js").write_text("console.log('new');", encoding="utf-8")

            result = rebuild_zip_archive_with_overlay(base_archive, overlay_root)

            self.assertTrue(result["ok"])
            rebuilt = Path(result["rebuilt_artifact"])
            self.assertTrue(rebuilt.exists())
            with zipfile.ZipFile(rebuilt, "r") as archive:
                self.assertEqual(archive.read("AndroidManifest.xml").decode("utf-8"), "<manifest package='patched' />")
                self.assertEqual(archive.read("assets/new.js").decode("utf-8"), "console.log('new');")


if __name__ == "__main__":
    unittest.main()
