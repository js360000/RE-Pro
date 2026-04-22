from __future__ import annotations

import json
import os
import subprocess
import sys
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
    metadata = {
        "workspace_root": str(workspace_root),
        "source_root": str(source_root),
        "logs_root": str(logs_root),
        "frameworks": frameworks,
        "toolchains": detect_toolchains(),
        "ecosystems": infer_ecosystems(report_dict, frameworks),
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
    return sorted(set(ecosystems))


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


def _command_result(code: int, stdout: str, stderr: str, command: list[str]) -> dict[str, Any]:
    return {
        "ok": code == 0,
        "exit_code": code,
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
        "command": command,
    }
