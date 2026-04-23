from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .tooling import resolve_command, run_command_logged
from .utils import ensure_dir


SUPPORTED_TOOLCHAINS = {
    "python": [["py", "-3"], ["python"]],
    "node": [["node"]],
    "npm": [["npm", "cmd", "/c"], ["npm"]],
    "pnpm": [["pnpm"]],
    "yarn": [["yarn"]],
    "cargo": [["cargo"]],
    "cmake": [["cmake"]],
}


def detect_toolchains() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, candidates in SUPPORTED_TOOLCHAINS.items():
        command = resolve_command(candidates)
        result[name] = {
            "available": command is not None,
            "command": command or [],
        }
    return result


def create_recompile_workspace(base_dir: Path, report_dict: dict[str, Any], frameworks: list[str]) -> dict[str, Any]:
    workspace_root = ensure_dir(base_dir / "recompile")
    source_root = ensure_dir(workspace_root / "src")
    logs_root = ensure_dir(workspace_root / "logs")
    projects_root = ensure_dir(workspace_root / "projects")
    patch_root = ensure_dir(workspace_root / "patching")
    project_templates = generate_project_templates(projects_root, report_dict, frameworks)
    rebuild_plan = build_rebuild_plan(workspace_root, report_dict, frameworks)
    signing_plan = build_signing_plan(workspace_root, report_dict, frameworks)
    patch_plan = build_patch_plan(patch_root, report_dict)
    metadata = {
        "workspace_root": str(workspace_root),
        "source_root": str(source_root),
        "logs_root": str(logs_root),
        "projects_root": str(projects_root),
        "patch_root": str(patch_root),
        "frameworks": frameworks,
        "toolchains": detect_toolchains(),
        "ecosystems": infer_ecosystems(report_dict, frameworks),
        "project_templates": project_templates,
        "rebuild_plan_path": str(rebuild_plan),
        "signing_plan_path": str(signing_plan),
        "patch_plan_path": str(patch_plan),
    }
    manifest_path = workspace_root / "workspace_manifest.json"
    manifest_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def infer_ecosystems(report_dict: dict[str, Any], frameworks: list[str]) -> list[str]:
    lower = {framework.lower() for framework in frameworks}
    ecosystems: list[str] = []
    if any(marker in framework for framework in lower for marker in ("electron", "react native", "vite", "webpack", "next.js", "node")):
        ecosystems.append("node")
    if any(marker in framework for framework in lower for marker in ("python", "pyinstaller", "nuitka")):
        ecosystems.append("python")
    if any(marker in framework for framework in lower for marker in ("rust", "tauri")):
        ecosystems.append("cargo")
    if any(marker in framework for framework in lower for marker in ("qt", "c/c++", "native windows application", "mach-o")):
        ecosystems.append("cmake")
    if report_dict.get("target_type") == "android-package":
        ecosystems.extend(["node", "cargo"])
    if report_dict.get("target_type") in {"android-package", "android-app-bundle", "android-library-archive", "android-dex", "android-resource-table"}:
        ecosystems.append("android-gradle")
    if report_dict.get("target_type") in {"ios-ipa", "ios-app-bundle", "macos-app-bundle", "mach-o"}:
        ecosystems.append("xcode")
    return sorted(set(ecosystems))


def generate_project_templates(projects_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    ecosystems = infer_ecosystems(report_dict, frameworks)
    if "android-gradle" in ecosystems:
        templates.append(_create_android_studio_template(projects_root / "android_studio", report_dict, frameworks))
    if "xcode" in ecosystems:
        templates.append(_create_xcode_template(projects_root / "xcode", report_dict, frameworks))
    if "node" in ecosystems:
        templates.append(_create_node_template(projects_root / "node_app", report_dict, frameworks))
    if "cmake" in ecosystems:
        templates.append(_create_cmake_template(projects_root / "cmake_app", report_dict, frameworks))
    return templates


def build_rebuild_plan(workspace_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> Path:
    ecosystems = infer_ecosystems(report_dict, frameworks)
    steps: list[dict[str, Any]] = []
    for ecosystem in ecosystems:
        if ecosystem == "node":
            steps.extend(
                [
                    {"ecosystem": "node", "action": "install", "command_hint": "npm install or pnpm install"},
                    {"ecosystem": "node", "action": "build", "command_hint": "npm run build"},
                ]
            )
        elif ecosystem == "python":
            steps.append({"ecosystem": "python", "action": "compile", "command_hint": "python -m compileall"})
        elif ecosystem == "cargo":
            steps.append({"ecosystem": "cargo", "action": "check", "command_hint": "cargo check"})
        elif ecosystem == "cmake":
            steps.extend(
                [
                    {"ecosystem": "cmake", "action": "configure", "command_hint": "cmake -S . -B build"},
                    {"ecosystem": "cmake", "action": "build", "command_hint": "cmake --build build"},
                ]
            )
        elif ecosystem == "android-gradle":
            steps.append({"ecosystem": "android-gradle", "action": "assembleDebug", "command_hint": "./gradlew assembleDebug"})
        elif ecosystem == "xcode":
            steps.append({"ecosystem": "xcode", "action": "build", "command_hint": "xcodebuild -scheme RecoveredApp build"})
    payload = {
        "target": report_dict.get("target"),
        "target_type": report_dict.get("target_type"),
        "frameworks": frameworks,
        "steps": steps,
    }
    path = workspace_root / "rebuild_plan.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def build_signing_plan(workspace_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> Path:
    lower = {framework.lower() for framework in frameworks}
    targets: list[dict[str, Any]] = []
    if report_dict.get("target_type") in {"android-package", "android-app-bundle", "android-library-archive"} or any("android" in framework for framework in lower):
        targets.append(
            {
                "platform": "android",
                "artifacts": ["apk", "aab"],
                "requirements": ["keystore", "key alias", "apksigner or jarsigner"],
                "notes": "Use a debug keystore first, then replace with release signing once the reconstructed package is stable.",
            }
        )
    if report_dict.get("target_type") in {"ios-ipa", "ios-app-bundle", "macos-app-bundle", "mach-o"} or any("ios" in framework or "macos" in framework for framework in lower):
        targets.append(
            {
                "platform": "apple",
                "artifacts": ["app", "ipa"],
                "requirements": ["team identifier", "signing certificate", "provisioning profile where applicable", "codesign/xcodebuild"],
                "notes": "Replace recovered bundle identifiers, entitlements, and provisioning data before attempting release signing.",
            }
        )
    payload = {
        "target": report_dict.get("target"),
        "frameworks": frameworks,
        "targets": targets,
    }
    path = workspace_root / "signing_plan.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def build_patch_plan(patch_root: Path, report_dict: dict[str, Any]) -> Path:
    ensure_dir(patch_root)
    payload = {
        "target": report_dict.get("target"),
        "artifact_candidates": [
            {
                "path": artifact.get("path"),
                "category": artifact.get("category"),
                "description": artifact.get("description"),
            }
            for artifact in (report_dict.get("artifacts") or [])
            if artifact.get("category") in {"binary", "resource", "archive", "manifest", "payload"}
        ][:200],
        "recovered_sources": [
            {
                "original_path": source.get("original_path"),
                "restored_path": source.get("restored_path"),
            }
            for source in (report_dict.get("recovered_sources") or [])
        ][:200],
        "strategies": [
            "Prefer source-level modifications in recovered or reconstructed project templates before patching packed binaries directly.",
            "Use manifest/resource replacements first for icons, labels, endpoints, and updater metadata.",
            "Treat binary patching as a last resort after resource and project-level rebuild paths have been exhausted.",
        ],
    }
    path = patch_root / "patch_plan.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def install_dependency(
    *,
    workspace_root: Path,
    ecosystem: str,
    package: str,
    logger=None,
    timeout: int = 1800,
) -> dict[str, Any]:
    ecosystem = ecosystem.lower()
    if ecosystem == "python":
        venv_dir = ensure_dir(workspace_root / ".venv")
        if not (venv_dir / "Scripts" / "python.exe").exists():
            python = resolve_command([["py", "-3"], ["python"]])
            if python is None:
                return {"ok": False, "error": "Python runtime not available"}
            run_command_logged(
                python + ["-m", "venv", str(venv_dir)],
                cwd=workspace_root,
                timeout=timeout,
                logger=logger,
                label="venv",
            )
        installer = [str(venv_dir / "Scripts" / "python.exe"), "-m", "pip", "install", package]
        code, stdout, stderr = run_command_logged(installer, cwd=workspace_root, timeout=timeout, logger=logger, label="pip")
        return _command_result(code, stdout, stderr, installer)

    if ecosystem in {"node", "npm"}:
        npm = resolve_command([["npm"]])
        if npm is None:
            return {"ok": False, "error": "npm not available"}
        package_json = workspace_root / "package.json"
        if not package_json.exists():
            package_json.write_text(json.dumps({"name": "re-pro-recompile", "private": True, "version": "0.0.0"}, indent=2), encoding="utf-8")
        command = npm + ["install", package]
        code, stdout, stderr = run_command_logged(command, cwd=workspace_root, timeout=timeout, logger=logger, label="npm")
        return _command_result(code, stdout, stderr, command)

    if ecosystem == "pnpm":
        pnpm = resolve_command([["pnpm"]])
        if pnpm is None:
            return {"ok": False, "error": "pnpm not available"}
        package_json = workspace_root / "package.json"
        if not package_json.exists():
            package_json.write_text(json.dumps({"name": "re-pro-recompile", "private": True, "version": "0.0.0"}, indent=2), encoding="utf-8")
        command = pnpm + ["add", package]
        code, stdout, stderr = run_command_logged(command, cwd=workspace_root, timeout=timeout, logger=logger, label="pnpm")
        return _command_result(code, stdout, stderr, command)

    if ecosystem == "yarn":
        yarn = resolve_command([["yarn"]])
        if yarn is None:
            return {"ok": False, "error": "yarn not available"}
        package_json = workspace_root / "package.json"
        if not package_json.exists():
            package_json.write_text(json.dumps({"name": "re-pro-recompile", "private": True, "version": "0.0.0"}, indent=2), encoding="utf-8")
        command = yarn + ["add", package]
        code, stdout, stderr = run_command_logged(command, cwd=workspace_root, timeout=timeout, logger=logger, label="yarn")
        return _command_result(code, stdout, stderr, command)

    if ecosystem == "cargo":
        cargo = resolve_command([["cargo"]])
        if cargo is None:
            return {"ok": False, "error": "cargo not available"}
        cargo_toml = workspace_root / "Cargo.toml"
        if not cargo_toml.exists():
            cargo_toml.write_text(
                "[package]\nname = \"re_pro_recompile\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
                encoding="utf-8",
            )
        command = cargo + ["add", package]
        code, stdout, stderr = run_command_logged(command, cwd=workspace_root, timeout=timeout, logger=logger, label="cargo-add")
        return _command_result(code, stdout, stderr, command)

    return {"ok": False, "error": f"Unsupported ecosystem {ecosystem}"}


def run_recompile_command(
    *,
    workspace_root: Path,
    ecosystem: str,
    action: str,
    logger=None,
    timeout: int = 1800,
) -> dict[str, Any]:
    ecosystem = ecosystem.lower()
    action = action.lower()
    if ecosystem in {"node", "npm", "pnpm", "yarn"}:
        command = _node_action_command(workspace_root, ecosystem, action)
    elif ecosystem == "python":
        command = _python_action_command(workspace_root, action)
    elif ecosystem == "cargo":
        command = _cargo_action_command(action)
    elif ecosystem == "cmake":
        command = _cmake_action_command(workspace_root, action)
    elif ecosystem == "android-gradle":
        command = _android_gradle_action_command(workspace_root, action)
    elif ecosystem == "xcode":
        command = _xcode_action_command(workspace_root, action)
    else:
        return {"ok": False, "error": f"Unsupported ecosystem {ecosystem}"}
    if command is None:
        return {"ok": False, "error": f"Unsupported action {action} for ecosystem {ecosystem}"}
    code, stdout, stderr = run_command_logged(command, cwd=workspace_root, timeout=timeout, logger=logger, label=f"{ecosystem}-{action}")
    return _command_result(code, stdout, stderr, command)


def validate_reconstruction_file(path: Path, *, workspace_root: Path, logger=None, timeout: int = 120) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".py":
        command = resolve_command([["py", "-3"], ["python"]])
        if command is None:
            return {"ok": False, "error": "Python runtime not available for validation"}
        result = run_command_logged(command + ["-m", "py_compile", str(path)], cwd=workspace_root, timeout=timeout, logger=logger, label="py-compile")
        return _command_result(*result, command=command + ["-m", "py_compile", str(path)])
    if suffix == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8"))
            return {"ok": True, "command": ["json.loads"], "stdout": "", "stderr": ""}
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": str(exc)}
    if suffix == ".js":
        node = resolve_command([["node"]])
        if node is None:
            return {"ok": False, "error": "Node.js not available for JS syntax validation"}
        result = run_command_logged(node + ["--check", str(path)], cwd=workspace_root, timeout=timeout, logger=logger, label="node-check")
        return _command_result(*result, command=node + ["--check", str(path)])
    return {"ok": True, "command": ["noop"], "stdout": "", "stderr": "", "note": f"No validator for {suffix}"}


def _node_action_command(workspace_root: Path, ecosystem: str, action: str) -> list[str] | None:
    if ecosystem == "npm":
        base = resolve_command([["npm"]])
    elif ecosystem == "pnpm":
        base = resolve_command([["pnpm"]])
    elif ecosystem == "yarn":
        base = resolve_command([["yarn"]])
    else:
        base = resolve_command([["npm"]])
    if base is None:
        return None
    package_json = workspace_root / "package.json"
    if not package_json.exists():
        return None
    package_data = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
    scripts = package_data.get("scripts") or {}
    if action in scripts:
        return base + ["run", action] if ecosystem != "yarn" else base + [action]
    if action == "install":
        return base + ["install"]
    if action == "build" and "build" in scripts:
        return base + ["run", "build"] if ecosystem != "yarn" else base + ["build"]
    if action == "test" and "test" in scripts:
        return base + ["run", "test"] if ecosystem != "yarn" else base + ["test"]
    return None


def _python_action_command(workspace_root: Path, action: str) -> list[str] | None:
    python = resolve_command([["py", "-3"], ["python"]])
    if python is None:
        return None
    if action == "compile":
        py_files = [str(path) for path in workspace_root.rglob("*.py")][:200]
        if not py_files:
            return None
        return python + ["-m", "compileall", "-q", str(workspace_root)]
    if action == "test":
        return python + ["-m", "unittest", "discover", "-v"]
    return None


def _cargo_action_command(action: str) -> list[str] | None:
    cargo = resolve_command([["cargo"]])
    if cargo is None:
        return None
    if action in {"build", "check", "test"}:
        return cargo + [action]
    return None


def _cmake_action_command(workspace_root: Path, action: str) -> list[str] | None:
    cmake = resolve_command([["cmake"]])
    if cmake is None:
        return None
    build_dir = ensure_dir(workspace_root / "build")
    if action == "configure":
        return cmake + ["-S", str(workspace_root), "-B", str(build_dir)]
    if action == "build":
        return cmake + ["--build", str(build_dir)]
    return None


def _android_gradle_action_command(workspace_root: Path, action: str) -> list[str] | None:
    gradlew = workspace_root / "projects" / "android_studio" / "gradlew.bat"
    if not gradlew.exists():
        return None
    if action in {"assembledebug", "assembleDebug"}:
        return [str(gradlew), "assembleDebug"]
    if action in {"build", "assemble"}:
        return [str(gradlew), "build"]
    return None


def _xcode_action_command(workspace_root: Path, action: str) -> list[str] | None:
    xcodebuild = resolve_command([["xcodebuild"]])
    if xcodebuild is None:
        return None
    project_root = workspace_root / "projects" / "xcode"
    if action == "build":
        return xcodebuild + ["-project", str(project_root / "RecoveredApp.xcodeproj"), "-scheme", "RecoveredApp", "build"]
    return None


def _create_android_studio_template(template_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> dict[str, Any]:
    app_root = ensure_dir(template_root / "app" / "src" / "main")
    ensure_dir(app_root / "java" / "repro" / "recovered")
    ensure_dir(app_root / "res" / "values")
    (template_root / "settings.gradle.kts").write_text('rootProject.name = "RecoveredApp"\ninclude(":app")\n', encoding="utf-8")
    (template_root / "build.gradle.kts").write_text(
        "plugins {\n    id(\"com.android.application\") version \"8.5.0\" apply false\n    kotlin(\"android\") version \"2.0.21\" apply false\n}\n",
        encoding="utf-8",
    )
    (template_root / "gradle.properties").write_text("android.useAndroidX=true\norg.gradle.jvmargs=-Xmx2048m\n", encoding="utf-8")
    (template_root / "gradlew.bat").write_text("@echo off\r\necho Add a Gradle wrapper or open in Android Studio to regenerate wrapper files.\r\nexit /b 1\r\n", encoding="utf-8")
    (template_root / "app" / "build.gradle.kts").write_text(
        (
            "plugins {\n"
            "    id(\"com.android.application\")\n"
            "    kotlin(\"android\")\n"
            "}\n\n"
            "android {\n"
            "    namespace = \"repro.recovered\"\n"
            "    compileSdk = 34\n"
            "    defaultConfig {\n"
            "        applicationId = \"repro.recovered\"\n"
            "        minSdk = 24\n"
            "        targetSdk = 34\n"
            "        versionCode = 1\n"
            "        versionName = \"0.1.0\"\n"
            "    }\n"
            "}\n\n"
            "dependencies {\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    (app_root / "AndroidManifest.xml").write_text(
        (
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<manifest package=\"repro.recovered\" xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
            "  <application android:label=\"RecoveredApp\" android:allowBackup=\"true\">\n"
            "    <activity android:name=\".MainActivity\" android:exported=\"true\">\n"
            "      <intent-filter>\n"
            "        <action android:name=\"android.intent.action.MAIN\" />\n"
            "        <category android:name=\"android.intent.category.LAUNCHER\" />\n"
            "      </intent-filter>\n"
            "    </activity>\n"
            "  </application>\n"
            "</manifest>\n"
        ),
        encoding="utf-8",
    )
    (app_root / "java" / "repro" / "recovered" / "MainActivity.kt").write_text(
        "package repro.recovered\n\nimport android.app.Activity\n\nclass MainActivity : Activity()\n",
        encoding="utf-8",
    )
    (app_root / "res" / "values" / "strings.xml").write_text(
        "<resources>\n    <string name=\"app_name\">RecoveredApp</string>\n</resources>\n",
        encoding="utf-8",
    )
    readme = template_root / "README.md"
    readme.write_text(
        "# Android Studio Template\n\nUse this as a reconstructed project shell. Replace manifest identifiers, dependencies, resources, and recovered sources incrementally.\n",
        encoding="utf-8",
    )
    return {
        "name": "android_studio",
        "platform": "android",
        "path": str(template_root),
        "readme": str(readme),
    }


def _create_xcode_template(template_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> dict[str, Any]:
    app_root = ensure_dir(template_root / "RecoveredApp")
    xcodeproj = ensure_dir(template_root / "RecoveredApp.xcodeproj")
    bundle_identifier = "repro.recovered"
    (app_root / "Info.plist").write_text(
        (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict>\n"
            "  <key>CFBundleExecutable</key><string>RecoveredApp</string>\n"
            "  <key>CFBundleIdentifier</key><string>repro.recovered</string>\n"
            "  <key>CFBundleName</key><string>RecoveredApp</string>\n"
            "  <key>CFBundleVersion</key><string>1</string>\n"
            "  <key>CFBundleShortVersionString</key><string>0.1.0</string>\n"
            "</dict></plist>\n"
        ),
        encoding="utf-8",
    )
    (app_root / "AppDelegate.swift").write_text(
        "import Foundation\n\n@main\nstruct RecoveredApp {\n    static func main() {\n        print(\"RecoveredApp bootstrap placeholder\")\n    }\n}\n",
        encoding="utf-8",
    )
    (xcodeproj / "project.pbxproj").write_text(
        "// Placeholder Xcode project file. Open this template in Xcode and regenerate the project structure.\n",
        encoding="utf-8",
    )
    readme = template_root / "README.md"
    readme.write_text(
        "# Xcode Template\n\nUse this as a signing and bundle-structure starting point. Replace placeholder bundle identifiers, entitlements, and recovered source entrypoints before attempting codesign.\n",
        encoding="utf-8",
    )
    manifest = template_root / "project_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "bundle_identifier": bundle_identifier,
                "frameworks": frameworks,
                "target_type": report_dict.get("target_type"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "name": "xcode",
        "platform": "apple",
        "path": str(template_root),
        "readme": str(readme),
    }


def _create_node_template(template_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> dict[str, Any]:
    ensure_dir(template_root / "src")
    package_json = template_root / "package.json"
    package_json.write_text(
        json.dumps(
            {
                "name": "recovered-app",
                "private": True,
                "version": "0.1.0",
                "scripts": {"build": "echo Replace with recovered build command", "start": "node src/index.js"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (template_root / "src" / "index.js").write_text("console.log('Recovered app entrypoint placeholder');\n", encoding="utf-8")
    readme = template_root / "README.md"
    readme.write_text("# Node Template\n\nCopy recovered web/app sources into `src/` and replace the placeholder build scripts.\n", encoding="utf-8")
    return {"name": "node_app", "platform": "node", "path": str(template_root), "readme": str(readme)}


def _create_cmake_template(template_root: Path, report_dict: dict[str, Any], frameworks: list[str]) -> dict[str, Any]:
    ensure_dir(template_root / "src")
    (template_root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(RecoveredApp LANGUAGES C CXX)\nadd_executable(RecoveredApp src/main.cpp)\n",
        encoding="utf-8",
    )
    (template_root / "src" / "main.cpp").write_text("#include <iostream>\nint main() { std::cout << \"RecoveredApp placeholder\"; }\n", encoding="utf-8")
    readme = template_root / "README.md"
    readme.write_text("# CMake Template\n\nReplace `src/main.cpp` with recovered native sources and expand target dependencies incrementally.\n", encoding="utf-8")
    return {"name": "cmake_app", "platform": "native", "path": str(template_root), "readme": str(readme)}


def _command_result(code: int, stdout: str, stderr: str, command: list[str]) -> dict[str, Any]:
    return {
        "ok": code == 0,
        "exit_code": code,
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
        "command": command,
    }
