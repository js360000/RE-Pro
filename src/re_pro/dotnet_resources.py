from __future__ import annotations

import json
from pathlib import Path

from .tooling import resolve_command, run_command_logged
from .utils import ensure_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_SOURCE_ROOT = REPO_ROOT / "src" / "re_pro_dotnet_helper"
HELPER_PROJECT = HELPER_SOURCE_ROOT / "RePro.DotNetHelper.csproj"
HELPER_BUILD_ROOT = REPO_ROOT / "tools" / "dotnet_helper"
HELPER_DLL = HELPER_BUILD_ROOT / "RePro.DotNetHelper.dll"


def _helper_source_inputs() -> list[Path]:
    return [
        path
        for path in HELPER_SOURCE_ROOT.rglob("*")
        if path.is_file() and not {"bin", "obj"}.intersection(path.parts)
    ]


def ensure_dotnet_resource_helper(logger=None) -> Path | None:
    dotnet_command = resolve_command([["dotnet"], ["dotnet.exe"]])
    if dotnet_command is None or not HELPER_PROJECT.exists():
        return None

    if HELPER_DLL.exists():
        newest_input = max(
            (path.stat().st_mtime for path in _helper_source_inputs()),
            default=0.0,
        )
        if HELPER_DLL.stat().st_mtime >= newest_input:
            return HELPER_DLL

    ensure_dir(HELPER_BUILD_ROOT)
    command = dotnet_command + [
        "build",
        str(HELPER_PROJECT),
        "-c",
        "Release",
        "-o",
        str(HELPER_BUILD_ROOT),
        "/nologo",
    ]
    code, _, _ = run_command_logged(
        command,
        cwd=REPO_ROOT,
        timeout=900,
        logger=logger,
        label="dotnet-helper-build",
    )
    if code != 0 or not HELPER_DLL.exists():
        return None
    return HELPER_DLL


def extract_managed_resources(assembly_path: Path, output_dir: Path, logger=None) -> dict[str, object] | None:
    helper_path = ensure_dotnet_resource_helper(logger=logger)
    dotnet_command = resolve_command([["dotnet"], ["dotnet.exe"]])
    if helper_path is None or dotnet_command is None:
        return None

    ensure_dir(output_dir)
    command = dotnet_command + [
        str(helper_path),
        "extract-resources",
        str(assembly_path),
        str(output_dir),
    ]
    code, _, _ = run_command_logged(
        command,
        cwd=assembly_path.parent,
        timeout=900,
        logger=logger,
        label="dotnet-resource-extract",
    )
    manifest_path = output_dir / "resource_manifest.json"
    if code != 0 or not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None


def decompile_baml_to_xaml(
    assembly_path: Path,
    jobs: list[dict[str, object]],
    output_dir: Path,
    logger=None,
) -> dict[str, object] | None:
    helper_path = ensure_dotnet_resource_helper(logger=logger)
    dotnet_command = resolve_command([["dotnet"], ["dotnet.exe"]])
    if helper_path is None or dotnet_command is None or not jobs:
        return None

    ensure_dir(output_dir)
    jobs_path = output_dir / "baml_jobs.json"
    jobs_path.write_text(
        json.dumps({"jobs": jobs}, indent=2),
        encoding="utf-8",
    )
    command = dotnet_command + [
        str(helper_path),
        "decompile-baml",
        str(assembly_path),
        str(jobs_path),
        str(output_dir),
    ]
    code, _, _ = run_command_logged(
        command,
        cwd=assembly_path.parent,
        timeout=1800,
        logger=logger,
        label="dotnet-baml-decompile",
    )
    manifest_path = output_dir / "xaml_manifest.json"
    if code != 0 or not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
