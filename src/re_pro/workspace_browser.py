from __future__ import annotations

import base64
import json
import re
import shutil
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .json_schemas import (
    SchemaError,
    load_json_object,
    validate_browser_manifest,
    validate_edits,
    validate_report,
)
from .psarc import PSARC_METADATA_NAME, PsarcFormatError, extract_psarc, is_psarc, rebuild_psarc_with_overlay
from .psp import (
    PARAM_SFO_JSON_NAME,
    PSP_SECTION_METADATA_NAMES,
    PspFormatError,
    build_param_sfo_from_json,
    extract_pbp,
    is_param_sfo,
    is_pbp,
    parse_param_sfo_file,
    rebuild_pbp_with_overlay,
)
from .psp_tools import encrypt_data_psp, materialize_pbp_tool_outputs, pack_data_psar
from .recompile import create_recompile_workspace, rebuild_zip_archive_with_overlay, validate_reconstruction_file
from .tooling import resolve_command, run_command_logged
from .utils import ensure_dir, is_probable_binary, safe_slug, sanitize_relative_source_path

BROWSER_WORKSPACE_DIR = "browse_workspace"
BROWSER_MANIFEST_NAME = "browser_manifest.json"
BROWSER_EDITS_NAME = "edits.json"
BROWSER_MANIFEST_VERSION = 2
MAX_COPY_BYTES = 256 * 1024 * 1024
MAX_TEXT_READ_BYTES = 4 * 1024 * 1024
MAX_BINARY_READ_BYTES = 256 * 1024
MAX_DIRECTORY_FILES = 5000
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024

TEXT_SUFFIXES = {
    ".asm",
    ".bat",
    ".c",
    ".cfg",
    ".cmake",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".log",
    ".lua",
    ".m",
    ".mm",
    ".md",
    ".plist",
    ".ps1",
    ".py",
    ".rb",
    ".rc",
    ".rs",
    ".s",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
IMAGE_SUFFIXES = {".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".webp"}
ZIP_SUFFIXES = {".apk", ".aab", ".ipa", ".jar", ".zip", ".xpi", ".nupkg", ".vsix"}
TAR_SUFFIXES = {".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz"}


def build_browser_workspace(run_output_dir: str | Path) -> dict[str, Any]:
    """Materialize an editable, source-first browse view for one RE-Pro run."""

    run_dir = Path(run_output_dir).resolve()
    report_path = run_dir / "report.json"
    if not report_path.exists():
        raise FileNotFoundError(report_path)
    report = _read_json(report_path)
    workspace_root = ensure_dir(run_dir / BROWSER_WORKSPACE_DIR)
    nodes: list[dict[str, Any]] = []
    seen_relatives: set[str] = set()
    warnings: list[str] = []

    _write_browser_readme(workspace_root)
    _copy_file_node(
        report_path,
        workspace_root=workspace_root,
        relative_path="metadata/report.json",
        nodes=nodes,
        seen_relatives=seen_relatives,
        origin="run_report",
        priority=90,
        editable=True,
        overwrite=True,
    )
    index_path = run_dir / "analysis_index.json"
    if index_path.exists():
        _copy_file_node(
            index_path,
            workspace_root=workspace_root,
            relative_path="metadata/analysis_index.json",
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin="analysis_index",
            priority=85,
            editable=True,
            overwrite=True,
        )

    for source in report.get("recovered_sources") or []:
        if not isinstance(source, dict):
            continue
        restored_path = Path(str(source.get("restored_path", "")).strip())
        if not restored_path.exists() or not restored_path.is_file():
            continue
        original_path = str(source.get("original_path", "")).strip() or restored_path.name
        relative_path = _safe_join("source/recovered", original_path)
        _copy_file_node(
            restored_path,
            workspace_root=workspace_root,
            relative_path=relative_path,
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin="recovered_source",
            priority=100,
            editable=True,
            label=original_path,
        )

    for source_root, destination, priority in _candidate_source_dirs(run_dir):
        if source_root.exists() and source_root.is_dir():
            _copy_directory_tree(
                source_root,
                workspace_root=workspace_root,
                destination_prefix=destination,
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin=f"source_tree:{source_root.relative_to(run_dir).as_posix()}",
                priority=priority,
                editable=True,
                warnings=warnings,
            )

    target = Path(str(report.get("target", "")).strip())
    if target.exists():
        if target.is_file():
            target_node = _copy_file_node(
                target,
                workspace_root=workspace_root,
                relative_path=_safe_join("binary/target", target.name),
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin="target_binary",
                priority=20,
                editable=target.stat().st_size <= MAX_COPY_BYTES,
                force_view_mode="hex",
            )
            if target_node and _is_supported_archive(target):
                _extract_archive_node(
                    target,
                    workspace_root=workspace_root,
                    destination_prefix=_safe_join("archives/target", target.stem),
                    nodes=nodes,
                    seen_relatives=seen_relatives,
                    origin="target_archive",
                    priority=60,
                    warnings=warnings,
                )
            elif is_param_sfo(target):
                _add_param_sfo_json_node(
                    target,
                    workspace_root=workspace_root,
                    relative_path=_safe_join("structured/target", f"{target.stem}.PARAM.SFO.json"),
                    nodes=nodes,
                    seen_relatives=seen_relatives,
                    origin="target_param_sfo",
                    priority=62,
                    warnings=warnings,
                )
        elif target.is_dir():
            _copy_directory_tree(
                target,
                workspace_root=workspace_root,
                destination_prefix="target_tree",
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin="target_directory",
                priority=50,
                editable=True,
                warnings=warnings,
            )

    for artifact in report.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        artifact_path = Path(str(artifact.get("path", "")).strip())
        if not artifact_path.exists():
            continue
        category = safe_slug(str(artifact.get("category", "artifact")))
        description = safe_slug(str(artifact.get("description", "")) or artifact_path.stem)
        prefix = _safe_join("artifacts", category, description)
        if artifact_path.is_dir():
            _copy_directory_tree(
                artifact_path,
                workspace_root=workspace_root,
                destination_prefix=prefix,
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin=f"artifact:{artifact.get('description', '')}",
                priority=_artifact_priority(artifact),
                editable=True,
                warnings=warnings,
            )
            continue
        _copy_file_node(
            artifact_path,
            workspace_root=workspace_root,
            relative_path=_safe_join(prefix, artifact_path.name),
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin=f"artifact:{artifact.get('description', '')}",
            priority=_artifact_priority(artifact),
            editable=artifact_path.stat().st_size <= MAX_COPY_BYTES,
        )
        if _is_supported_archive(artifact_path):
            _extract_archive_node(
                artifact_path,
                workspace_root=workspace_root,
                destination_prefix=_safe_join("archives", description),
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin=f"artifact_archive:{artifact.get('description', '')}",
                priority=70,
                warnings=warnings,
            )
        elif is_param_sfo(artifact_path):
            _add_param_sfo_json_node(
                artifact_path,
                workspace_root=workspace_root,
                relative_path=_safe_join("structured", description, f"{artifact_path.stem}.PARAM.SFO.json"),
                nodes=nodes,
                seen_relatives=seen_relatives,
                origin=f"artifact_param_sfo:{artifact.get('description', '')}",
                priority=68,
                warnings=warnings,
            )

    warning_path = workspace_root / "metadata" / "browser_warnings.md"
    if warnings:
        ensure_dir(warning_path.parent)
        warning_path.write_text("# Browser Workspace Warnings\n\n" + "\n".join(f"- {item}" for item in warnings) + "\n", encoding="utf-8")
        _add_existing_file_node(
            warning_path,
            workspace_root=workspace_root,
            relative_path="metadata/browser_warnings.md",
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin="browser_warnings",
            priority=80,
            editable=True,
        )

    nodes = _with_stable_node_ids(sorted(nodes, key=lambda item: (-int(item.get("priority", 0)), str(item.get("relative_path", "")))))
    manifest = {
        "manifest_version": BROWSER_MANIFEST_VERSION,
        "run_output_dir": str(run_dir),
        "workspace_root": str(workspace_root),
        "manifest_path": str(workspace_root / BROWSER_MANIFEST_NAME),
        "edits_path": str(workspace_root / BROWSER_EDITS_NAME),
        "summary": {
            "node_count": len(nodes),
            "editable_count": sum(1 for node in nodes if node.get("editable")),
            "source_like_count": sum(1 for node in nodes if str(node.get("relative_path", "")).startswith("source/")),
            "archive_member_count": sum(1 for node in nodes if str(node.get("origin", "")).startswith(("target_archive", "artifact_archive"))),
        },
        "nodes": nodes,
    }
    (workspace_root / BROWSER_MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if not (workspace_root / BROWSER_EDITS_NAME).exists():
        (workspace_root / BROWSER_EDITS_NAME).write_text(json.dumps({"edits": []}, indent=2), encoding="utf-8")
    return manifest


def list_browser_nodes(run_output_dir: str | Path, *, rebuild: bool = False) -> dict[str, Any]:
    run_dir = Path(run_output_dir).resolve()
    manifest_path = run_dir / BROWSER_WORKSPACE_DIR / BROWSER_MANIFEST_NAME
    if rebuild or not manifest_path.exists():
        return build_browser_workspace(run_dir)
    manifest = _read_json(manifest_path)
    if int(manifest.get("manifest_version", 0) or 0) < BROWSER_MANIFEST_VERSION:
        return build_browser_workspace(run_dir)
    return manifest


def read_browser_node(
    run_output_dir: str | Path,
    node_id: str,
    *,
    mode: str = "auto",
    offset: int = 0,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    manifest, node = _load_manifest_and_node(run_output_dir, node_id)
    path = Path(str(node.get("path", "")))
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)
    view_mode = str(node.get("view_mode") or "hex") if mode == "auto" else mode
    total_size = path.stat().st_size
    if view_mode == "json":
        text = _read_text(path, max_bytes=max_bytes or MAX_TEXT_READ_BYTES)
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, indent=2)
        except json.JSONDecodeError:
            pass
        return _read_result(manifest, node, view_mode, text, total_size=total_size, offset=0, returned_bytes=len(text.encode("utf-8")))
    if view_mode == "text":
        text = _read_text(path, max_bytes=max_bytes or MAX_TEXT_READ_BYTES)
        return _read_result(manifest, node, view_mode, text, total_size=total_size, offset=0, returned_bytes=len(text.encode("utf-8")))
    if view_mode == "base64":
        data = _read_chunk(path, offset=offset, max_bytes=max_bytes)
        return _read_result(
            manifest,
            node,
            view_mode,
            base64.b64encode(data).decode("ascii"),
            total_size=total_size,
            offset=max(0, offset),
            returned_bytes=len(data),
        )
    data = _read_chunk(path, offset=offset, max_bytes=max_bytes or MAX_BINARY_READ_BYTES)
    return _read_result(
        manifest,
        node,
        "hex",
        _format_hex(data, base_offset=max(0, offset)),
        total_size=total_size,
        offset=max(0, offset),
        returned_bytes=len(data),
    )


def write_browser_node(run_output_dir: str | Path, node_id: str, content: str, *, mode: str = "text") -> dict[str, Any]:
    manifest, node = _load_manifest_and_node(run_output_dir, node_id)
    _assert_editable_node(manifest, node)
    path = Path(str(node.get("path", "")))
    ensure_dir(path.parent)
    if mode == "hex":
        payload = _parse_hex_dump(content)
        path.write_bytes(payload)
        written = len(payload)
    elif mode == "base64":
        payload = base64.b64decode(content)
        path.write_bytes(payload)
        written = len(payload)
    else:
        path.write_text(content, encoding="utf-8")
        written = len(content.encode("utf-8"))
    rebuild = rebuild_browser_node(run_output_dir, node_id)
    edit = _record_edit(
        manifest,
        {
            "operation": "write_node",
            "node_id": node_id,
            "relative_path": node.get("relative_path"),
            "path": str(path),
            "mode": mode,
            "written_bytes": written,
            "rebuild": rebuild,
        },
    )
    return {"ok": True, "node_id": node_id, "path": str(path), "written_bytes": written, "rebuild": rebuild, "edit": edit}


def patch_browser_node_bytes(run_output_dir: str | Path, node_id: str, offset: int, hex_bytes: str) -> dict[str, Any]:
    manifest, node = _load_manifest_and_node(run_output_dir, node_id)
    _assert_editable_node(manifest, node)
    path = Path(str(node.get("path", "")))
    patch = _parse_hex_patch(hex_bytes)
    if not patch:
        raise ValueError("No patch bytes were provided.")
    size = path.stat().st_size if path.exists() else 0
    if offset < 0 or offset > size:
        raise ValueError(f"Offset {offset} is outside file size {size}.")
    with path.open("r+b") as handle:
        handle.seek(offset)
        handle.write(patch)
    rebuild = rebuild_browser_node(run_output_dir, node_id)
    edit = _record_edit(
        manifest,
        {
            "operation": "patch_bytes",
            "node_id": node_id,
            "relative_path": node.get("relative_path"),
            "path": str(path),
            "offset": offset,
            "hex_bytes": patch.hex(),
            "written_bytes": len(patch),
            "rebuild": rebuild,
        },
    )
    return {"ok": True, "node_id": node_id, "path": str(path), "offset": offset, "written_bytes": len(patch), "rebuild": rebuild, "edit": edit}


def rebuild_browser_node(run_output_dir: str | Path, node_id: str) -> dict[str, Any]:
    """Compile/rebuild the edited unit represented by a browser node."""

    manifest, node = _load_manifest_and_node(run_output_dir, node_id)
    relative_path = str(node.get("relative_path", ""))
    origin = str(node.get("origin", ""))
    if node.get("rebuild_kind") == "param_sfo":
        return _rebuild_param_sfo_node(manifest, node)
    if node.get("rebuild_kind") in {"psp_reencrypt_data_psp", "psp_repack_data_psar"}:
        return _rebuild_psp_tool_node(manifest, node)
    if node.get("archive_overlay_root") and node.get("container_path"):
        return _rebuild_archive_node(manifest, node)
    if relative_path.startswith("source/"):
        return _recompile_source_workspace(Path(run_output_dir).resolve(), manifest, node)
    if relative_path.startswith("binary/") or origin.endswith("binary") or origin == "target_binary":
        return _emit_patched_binary(manifest, node)
    if str(node.get("view_mode", "")) in {"json", "text"}:
        return _validate_text_node(manifest, node)
    return _emit_patched_binary(manifest, node)


def _rebuild_archive_node(manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    base_archive = Path(str(node.get("container_path", ""))).resolve()
    overlay_root = Path(str(node.get("archive_overlay_root", ""))).resolve()
    rebuilt_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "archives")
    output_path = rebuilt_dir / f"{base_archive.stem}.rebuilt{base_archive.suffix}"
    if is_psarc(base_archive):
        result = rebuild_psarc_with_overlay(base_archive, overlay_root, output_path)
    elif is_pbp(base_archive):
        result = rebuild_pbp_with_overlay(base_archive, overlay_root, output_path.with_suffix(".PBP"))
    elif zipfile.is_zipfile(base_archive):
        result = rebuild_zip_archive_with_overlay(base_archive, overlay_root, output_path)
    elif tarfile.is_tarfile(base_archive):
        result = _rebuild_tar_archive_with_overlay(base_archive, overlay_root, output_path)
    else:
        result = {"ok": False, "error": f"Archive format cannot be rebuilt yet: {base_archive}"}
    result.update(
        {
            "kind": "archive_rebuild",
            "node_id": node.get("id"),
            "relative_path": node.get("relative_path"),
            "archive_member_path": node.get("archive_member_path"),
        }
    )
    return result


def _rebuild_psp_tool_node(manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    base_archive = Path(str(node.get("container_path", ""))).resolve()
    overlay_root = Path(str(node.get("archive_overlay_root", ""))).resolve()
    rebuilt_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "archives")
    work_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "psp_tools")
    output_path = rebuilt_dir / f"{base_archive.stem}.rebuilt.PBP"
    kind = str(node.get("rebuild_kind", ""))
    if kind == "psp_reencrypt_data_psp":
        section_path = overlay_root / "DATA.PSP"
        tool_result = encrypt_data_psp(Path(str(node.get("path", ""))), section_path, work_dir=work_dir)
        if not tool_result.get("ok"):
            return {
                "ok": False,
                "kind": "psp_reencrypt_data_psp",
                "tool": tool_result,
                "error": tool_result.get("message", "DATA.PSP re-encryption failed."),
            }
        rebuild = rebuild_pbp_with_overlay(base_archive, overlay_root, output_path)
        rebuild.update({"kind": "psp_reencrypt_data_psp", "tool": tool_result})
        return rebuild
    if kind == "psp_repack_data_psar":
        psar_root = Path(str(node.get("psar_extract_root", ""))).resolve()
        section_path = overlay_root / "DATA.PSAR"
        tool_result = pack_data_psar(psar_root, section_path, work_dir=work_dir)
        if not tool_result.get("ok"):
            return {
                "ok": False,
                "kind": "psp_repack_data_psar",
                "tool": tool_result,
                "error": tool_result.get("message", "DATA.PSAR repack/encryption failed."),
            }
        rebuild = rebuild_pbp_with_overlay(base_archive, overlay_root, output_path)
        rebuild.update({"kind": "psp_repack_data_psar", "tool": tool_result})
        return rebuild
    return {"ok": False, "kind": kind or "psp_tool_rebuild", "error": "Unsupported PSP tool rebuild kind."}


def _rebuild_param_sfo_node(manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    path = Path(str(node.get("path", ""))).resolve()
    rebuilt_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "files")
    output_path = rebuilt_dir / f"{path.stem}.rebuilt.sfo"
    try:
        payload = build_param_sfo_from_json(path)
        output_path.write_bytes(payload)
        validation = validate_reconstruction_file(output_path, workspace_root=Path(str(manifest.get("workspace_root"))))
        return {
            "ok": True,
            "kind": "param_sfo_rebuild",
            "rebuilt_artifact": str(output_path),
            "size": len(payload),
            "validation": validation,
        }
    except (OSError, ValueError, PspFormatError) as exc:
        return {"ok": False, "kind": "param_sfo_rebuild", "error": str(exc)}


def _recompile_source_workspace(run_dir: Path, manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    report = _read_json(run_dir / "report.json")
    workspace_base = ensure_dir(Path(str(manifest.get("workspace_root"))) / "build")
    metadata = create_recompile_workspace(workspace_base, report, report.get("frameworks") or [])
    workspace_root = Path(metadata["workspace_root"])
    source_root = ensure_dir(Path(metadata["source_root"]))
    staged_path: Path | None = None
    copied: list[dict[str, str]] = []
    for candidate in manifest.get("nodes") or []:
        relative_path = str(candidate.get("relative_path", ""))
        if not relative_path.startswith("source/"):
            continue
        source_path = Path(str(candidate.get("path", "")))
        if not source_path.exists() or not source_path.is_file():
            continue
        destination = source_root / _source_stage_relative(relative_path)
        ensure_dir(destination.parent)
        shutil.copy2(source_path, destination)
        copied.append({"source": str(source_path), "destination": str(destination)})
        if candidate.get("id") == node.get("id"):
            staged_path = destination
    if staged_path is None:
        return {
            "ok": False,
            "kind": "source_recompile",
            "error": "Edited source node could not be staged into the recompile workspace.",
        }
    validation = validate_reconstruction_file(staged_path, workspace_root=workspace_root)
    compile_result = _compile_single_source(staged_path, workspace_root=workspace_root)
    return {
        "ok": bool(validation.get("ok")) and bool(compile_result.get("ok")),
        "kind": "source_recompile",
        "workspace_root": str(workspace_root),
        "source_root": str(source_root),
        "staged_path": str(staged_path),
        "staged_files": len(copied),
        "validation": validation,
        "compile": compile_result,
    }


def _validate_text_node(manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    path = Path(str(node.get("path", ""))).resolve()
    rebuilt_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "files")
    output_path = rebuilt_dir / sanitize_relative_source_path(str(node.get("relative_path", path.name))).replace("/", "__")
    shutil.copy2(path, output_path)
    validation = validate_reconstruction_file(output_path, workspace_root=Path(str(manifest.get("workspace_root"))))
    return {
        "ok": bool(validation.get("ok")),
        "kind": "file_recompile",
        "rebuilt_artifact": str(output_path),
        "validation": validation,
    }


def _emit_patched_binary(manifest: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    path = Path(str(node.get("path", ""))).resolve()
    if not path.exists() or not path.is_file():
        return {"ok": False, "kind": "patched_binary", "error": f"Patched file not found: {path}"}
    rebuilt_dir = ensure_dir(Path(str(manifest.get("workspace_root"))) / "rebuilt" / "binaries")
    suffix = path.suffix
    output_path = rebuilt_dir / f"{path.stem}.patched{suffix or '.bin'}"
    shutil.copy2(path, output_path)
    return {
        "ok": True,
        "kind": "patched_binary",
        "rebuilt_artifact": str(output_path),
        "source_node_path": str(path),
        "size": output_path.stat().st_size,
    }


def _source_stage_relative(relative_path: str) -> Path:
    parts = [part for part in relative_path.replace("\\", "/").split("/") if part]
    if parts and parts[0] == "source":
        parts = parts[1:]
    if parts and parts[0] in {"recovered", "llm_assist", "native", "msvc_rtti", "porting", "tauri", "discovered"}:
        parts = parts[1:]
    if not parts:
        parts = ["edited_source.txt"]
    return Path(sanitize_relative_source_path("/".join(parts)))


def _compile_single_source(path: Path, *, workspace_root: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".c"}:
        command = resolve_command([["cl"], ["clang"], ["gcc"]])
        if command is None:
            return {"ok": True, "command": ["noop"], "note": "No C compiler available for syntax-only compile."}
        compile_args = ["/nologo", "/Zs", str(path)] if Path(command[0]).name.lower() in {"cl", "cl.exe"} else ["-fsyntax-only", str(path)]
    elif suffix in {".cc", ".cpp", ".cxx", ".mm"}:
        command = resolve_command([["cl"], ["clang++"], ["g++"]])
        if command is None:
            return {"ok": True, "command": ["noop"], "note": "No C++ compiler available for syntax-only compile."}
        compile_args = ["/nologo", "/Zs", str(path)] if Path(command[0]).name.lower() in {"cl", "cl.exe"} else ["-fsyntax-only", str(path)]
    else:
        return {"ok": True, "command": ["noop"], "note": f"No syntax-only compiler configured for {suffix or 'extensionless'} files."}
    full_command = command + compile_args
    code, stdout, stderr = run_command_logged(full_command, cwd=workspace_root, timeout=120, logger=None, label="browser-compile")
    return {"ok": code == 0, "command": full_command, "exit_code": code, "stdout": stdout, "stderr": stderr}


def _rebuild_tar_archive_with_overlay(base_archive: Path, overlay_root: Path, output_path: Path) -> dict[str, Any]:
    mode = "w"
    suffixes = "".join(base_archive.suffixes[-2:]).lower()
    if suffixes.endswith(".tar.gz") or base_archive.suffix.lower() == ".tgz":
        mode = "w:gz"
    elif suffixes.endswith(".tar.bz2") or base_archive.suffix.lower() in {".tbz", ".tbz2"}:
        mode = "w:bz2"
    elif suffixes.endswith(".tar.xz") or base_archive.suffix.lower() == ".txz":
        mode = "w:xz"
    replaced: set[str] = set()
    existing: set[str] = set()
    with tarfile.open(base_archive) as source_archive:
        with tarfile.open(output_path, mode) as destination_archive:
            for member in source_archive.getmembers():
                if not member.isfile():
                    continue
                relative = member.name.replace("\\", "/")
                existing.add(relative)
                overlay_file = overlay_root / sanitize_relative_source_path(relative)
                if overlay_file.exists() and overlay_file.is_file():
                    destination_archive.add(overlay_file, arcname=relative)
                    replaced.add(relative)
                    continue
                extracted = source_archive.extractfile(member)
                if extracted is None:
                    continue
                destination_archive.addfile(member, extracted)
            for overlay_file in sorted(overlay_root.rglob("*")):
                if not overlay_file.is_file():
                    continue
                relative = overlay_file.relative_to(overlay_root).as_posix()
                if relative in existing:
                    continue
                destination_archive.add(overlay_file, arcname=relative)
                replaced.add(relative)
    return {
        "ok": True,
        "base_archive": str(base_archive),
        "overlay_root": str(overlay_root),
        "rebuilt_artifact": str(output_path),
        "replaced_entries": sorted(replaced),
    }


def _candidate_source_dirs(run_dir: Path) -> list[tuple[Path, str, int]]:
    candidates = [
        (run_dir / "mcp_reconstruction" / "reconstructed_src", "source/mcp_reconstruction", 98),
        (run_dir / "llm_assist" / "reconstructed_src", "source/llm_assist", 96),
        (run_dir / "llm_assist" / "reconstructed", "source/llm_assist", 94),
        (run_dir / "native" / "recovered_src", "source/native", 92),
        (run_dir / "msvc_rtti" / "recovered_src", "source/msvc_rtti", 92),
        (run_dir / "ghidra" / "exports" / "class_pseudo_cpp", "source/ghidra/class_pseudo_cpp", 88),
        (run_dir / "ghidra" / "exports" / "pseudo_code", "source/ghidra/pseudo_code", 82),
        (run_dir / "porting" / "prepared_sources", "source/porting/prepared_sources", 80),
        (run_dir / "tauri" / "recovered_sources", "source/tauri/recovered_sources", 86),
    ]
    discovered: list[tuple[Path, str, int]] = []
    for directory in run_dir.rglob("*"):
        if not directory.is_dir() or BROWSER_WORKSPACE_DIR in directory.parts:
            continue
        if directory.name in {"recovered_sources", "reconstructed_src", "class_pseudo_cpp", "pseudo_code"}:
            relative = directory.relative_to(run_dir).as_posix()
            discovered.append((directory, _safe_join("source/discovered", relative), 74))
    return _dedupe_source_dirs(candidates + discovered)


def _dedupe_source_dirs(candidates: list[tuple[Path, str, int]]) -> list[tuple[Path, str, int]]:
    seen: set[Path] = set()
    result: list[tuple[Path, str, int]] = []
    for path, destination, priority in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append((path, destination, priority))
    return result


def _copy_directory_tree(
    source_dir: Path,
    *,
    workspace_root: Path,
    destination_prefix: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    editable: bool,
    warnings: list[str],
) -> None:
    source_dir = source_dir.resolve()
    workspace_root = workspace_root.resolve()
    if _is_relative_to(source_dir, workspace_root):
        _add_existing_directory_tree(
            source_dir,
            workspace_root=workspace_root,
            destination_prefix=destination_prefix,
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin=origin,
            priority=priority,
            editable=editable,
            warnings=warnings,
        )
        return
    count = 0
    for file_path in sorted(source_dir.rglob("*")):
        if count >= MAX_DIRECTORY_FILES:
            warnings.append(f"Skipped remaining files under {source_dir}; browse tree cap is {MAX_DIRECTORY_FILES} files.")
            break
        if not file_path.is_file() or _should_skip_path(file_path, skip_browser_workspace=True):
            continue
        try:
            relative = file_path.relative_to(source_dir).as_posix()
        except ValueError:
            continue
        node = _copy_file_node(
            file_path,
            workspace_root=workspace_root,
            relative_path=_safe_join(destination_prefix, relative),
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin=origin,
            priority=priority,
            editable=editable and file_path.stat().st_size <= MAX_COPY_BYTES,
        )
        if node is not None:
            count += 1


def _add_existing_directory_tree(
    source_dir: Path,
    *,
    workspace_root: Path,
    destination_prefix: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    editable: bool,
    warnings: list[str],
) -> None:
    count = 0
    for file_path in sorted(source_dir.rglob("*")):
        if count >= MAX_DIRECTORY_FILES:
            warnings.append(f"Skipped remaining files under {source_dir}; browse tree cap is {MAX_DIRECTORY_FILES} files.")
            break
        if not file_path.is_file() or _should_skip_path(file_path):
            continue
        relative = file_path.relative_to(source_dir).as_posix()
        _add_existing_file_node(
            file_path,
            workspace_root=workspace_root,
            relative_path=_safe_join(destination_prefix, relative),
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin=origin,
            priority=priority,
            editable=editable,
        )
        count += 1


def _copy_file_node(
    source: Path,
    *,
    workspace_root: Path,
    relative_path: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    editable: bool,
    label: str = "",
    force_view_mode: str = "",
    overwrite: bool = False,
) -> dict[str, Any] | None:
    if not source.exists() or not source.is_file():
        return None
    source = source.resolve()
    destination_relative = _unique_relative(_normalize_relative(relative_path), seen_relatives)
    if source.stat().st_size <= MAX_COPY_BYTES:
        destination = (workspace_root / destination_relative).resolve()
        ensure_dir(destination.parent)
        if overwrite or not destination.exists():
            shutil.copy2(source, destination)
        return _add_node(
            path=destination,
            workspace_root=workspace_root,
            relative_path=destination_relative,
            source_path=source,
            nodes=nodes,
            origin=origin,
            priority=priority,
            editable=editable,
            label=label,
            force_view_mode=force_view_mode,
        )
    return _add_node(
        path=source,
        workspace_root=workspace_root,
        relative_path=destination_relative,
        source_path=source,
        nodes=nodes,
        origin=origin,
        priority=priority,
        editable=False,
        label=label,
        force_view_mode=force_view_mode or "hex",
    )


def _add_existing_file_node(
    path: Path,
    *,
    workspace_root: Path,
    relative_path: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    editable: bool,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    destination_relative = _unique_relative(_normalize_relative(relative_path), seen_relatives)
    return _add_node(
        path=path.resolve(),
        workspace_root=workspace_root,
        relative_path=destination_relative,
        source_path=path.resolve(),
        nodes=nodes,
        origin=origin,
        priority=priority,
        editable=editable,
        extra=extra,
    )


def _add_node(
    *,
    path: Path,
    workspace_root: Path,
    relative_path: str,
    source_path: Path,
    nodes: list[dict[str, Any]],
    origin: str,
    priority: int,
    editable: bool,
    label: str = "",
    force_view_mode: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stat = path.stat()
    node = {
        "id": "",
        "kind": "file",
        "label": label or Path(relative_path).name,
        "relative_path": relative_path,
        "path": str(path),
        "source_path": str(source_path),
        "origin": origin,
        "priority": priority,
        "editable": bool(editable and _is_relative_to(path.resolve(), workspace_root.resolve())),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "view_mode": force_view_mode or _infer_view_mode(path),
    }
    if extra:
        node.update(extra)
    nodes.append(node)
    return node


def _with_stable_node_ids(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for index, node in enumerate(nodes, start=1):
        node["id"] = f"node_{index:05d}"
    return nodes


def _extract_archive_node(
    archive_path: Path,
    *,
    workspace_root: Path,
    destination_prefix: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    warnings: list[str],
) -> None:
    destination_root = ensure_dir((workspace_root / _normalize_relative(destination_prefix)).resolve())
    extracted = 0
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if extracted >= MAX_ARCHIVE_MEMBERS:
                        warnings.append(f"Skipped remaining members in {archive_path}; archive member cap is {MAX_ARCHIVE_MEMBERS}.")
                        break
                    if info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    relative = sanitize_relative_source_path(info.filename)
                    destination = (destination_root / relative).resolve()
                    if not _is_relative_to(destination, destination_root):
                        continue
                    ensure_dir(destination.parent)
                    if not destination.exists():
                        destination.write_bytes(archive.read(info))
                    extracted += 1
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    if extracted >= MAX_ARCHIVE_MEMBERS:
                        warnings.append(f"Skipped remaining members in {archive_path}; archive member cap is {MAX_ARCHIVE_MEMBERS}.")
                        break
                    if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    relative = sanitize_relative_source_path(member.name)
                    destination = (destination_root / relative).resolve()
                    if not _is_relative_to(destination, destination_root):
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    ensure_dir(destination.parent)
                    if not destination.exists():
                        destination.write_bytes(source.read())
                    extracted += 1
        elif is_psarc(archive_path):
            result = extract_psarc(
                archive_path,
                destination_root,
                max_members=MAX_ARCHIVE_MEMBERS,
                max_member_bytes=MAX_ARCHIVE_MEMBER_BYTES,
            )
            extracted = int(result.get("extracted_file_count", 0) or 0)
            for warning in result.get("warnings") or []:
                warnings.append(str(warning))
        elif is_pbp(archive_path):
            result = extract_pbp(
                archive_path,
                destination_root,
                max_section_bytes=MAX_ARCHIVE_MEMBER_BYTES,
            )
            extracted = int(result.get("extracted_file_count", 0) or 0)
            for warning in result.get("warnings") or []:
                warnings.append(str(warning))
            tool_result = materialize_pbp_tool_outputs(archive_path, destination_root)
            for item in tool_result.get("results") or []:
                if isinstance(item, dict) and item.get("message"):
                    warnings.append(str(item.get("message")))
        else:
            return
    except (OSError, tarfile.TarError, zipfile.BadZipFile, PsarcFormatError, PspFormatError) as exc:
        warnings.append(f"Could not extract {archive_path}: {exc}")
        return
    count = 0
    for file_path in sorted(destination_root.rglob("*")):
        if count >= MAX_DIRECTORY_FILES:
            warnings.append(f"Skipped remaining files under {destination_root}; browse tree cap is {MAX_DIRECTORY_FILES} files.")
            break
        if (
            not file_path.is_file()
            or _should_skip_path(file_path)
            or file_path.name == PSARC_METADATA_NAME
            or file_path.name in PSP_SECTION_METADATA_NAMES
        ):
            continue
        member_relative = file_path.relative_to(destination_root).as_posix()
        extra = {
            "container_path": str(archive_path.resolve()),
            "archive_overlay_root": str(destination_root),
            "archive_member_path": member_relative,
            "rebuild_kind": "archive_overlay",
        }
        if file_path.name == PARAM_SFO_JSON_NAME and is_pbp(archive_path):
            extra["sfo_json_for"] = "PARAM.SFO"
        if is_pbp(archive_path) and member_relative.startswith("_tools/DATA.PSP/") and file_path.name.endswith(".decrypted.bin"):
            extra["rebuild_kind"] = "psp_reencrypt_data_psp"
            extra["psp_raw_section"] = "DATA.PSP"
            extra["view_mode"] = "hex"
        if is_pbp(archive_path) and member_relative.startswith("_tools/DATA.PSAR/"):
            extra["rebuild_kind"] = "psp_repack_data_psar"
            extra["psp_raw_section"] = "DATA.PSAR"
            extra["psar_extract_root"] = str((destination_root / "_tools" / "DATA.PSAR").resolve())
        _add_existing_file_node(
            file_path,
            workspace_root=workspace_root,
            relative_path=_safe_join(destination_prefix, member_relative),
            nodes=nodes,
            seen_relatives=seen_relatives,
            origin=origin,
            priority=priority,
            editable=True,
            extra=extra,
        )
        count += 1


def _is_supported_archive(path: Path) -> bool:
    suffix = path.suffix.lower()
    compound = "".join(path.suffixes[-2:]).lower() if len(path.suffixes) >= 2 else suffix
    return (
        suffix in {".psarc", ".pbp"}
        or is_psarc(path)
        or is_pbp(path)
        or suffix in ZIP_SUFFIXES
        or compound in TAR_SUFFIXES
        or suffix in TAR_SUFFIXES
        or zipfile.is_zipfile(path)
    )


def _add_param_sfo_json_node(
    source: Path,
    *,
    workspace_root: Path,
    relative_path: str,
    nodes: list[dict[str, Any]],
    seen_relatives: set[str],
    origin: str,
    priority: int,
    warnings: list[str],
) -> None:
    try:
        manifest = parse_param_sfo_file(source)
    except (OSError, PspFormatError) as exc:
        warnings.append(f"Could not parse PARAM.SFO {source}: {exc}")
        return
    destination_relative = _unique_relative(_normalize_relative(relative_path), seen_relatives)
    destination = (workspace_root / destination_relative).resolve()
    ensure_dir(destination.parent)
    destination.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    _add_node(
        path=destination,
        workspace_root=workspace_root,
        relative_path=destination_relative,
        source_path=source.resolve(),
        nodes=nodes,
        origin=origin,
        priority=priority,
        editable=True,
        force_view_mode="json",
        extra={"rebuild_kind": "param_sfo", "sfo_source_path": str(source.resolve())},
    )


def _artifact_priority(artifact: dict[str, Any]) -> int:
    category = str(artifact.get("category", "")).lower()
    description = str(artifact.get("description", "")).lower()
    if "source" in description or "pseudo" in description or "decomp" in description:
        return 78
    if category in {"manifest", "json"}:
        return 60
    if category in {"directory", "resource", "payload", "archive"}:
        return 50
    if category == "binary":
        return 30
    return 40


def _infer_view_mode(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in IMAGE_SUFFIXES:
        return "image"
    if suffix in TEXT_SUFFIXES:
        return "text"
    try:
        head = path.read_bytes()[:8192]
    except OSError:
        return "hex"
    if is_probable_binary(path, head):
        return "hex"
    return "text"


def _read_text(path: Path, *, max_bytes: int) -> str:
    data = path.read_bytes()[: max(1, min(max_bytes, MAX_TEXT_READ_BYTES))]
    return data.decode("utf-8", errors="replace")


def _read_chunk(path: Path, *, offset: int, max_bytes: int) -> bytes:
    start = max(0, offset)
    length = max(1, min(max_bytes, MAX_BINARY_READ_BYTES))
    with path.open("rb") as handle:
        handle.seek(start)
        return handle.read(length)


def _read_result(
    manifest: dict[str, Any],
    node: dict[str, Any],
    view_mode: str,
    content: str,
    *,
    total_size: int,
    offset: int,
    returned_bytes: int,
) -> dict[str, Any]:
    return {
        "workspace_root": manifest.get("workspace_root"),
        "node": node,
        "view_mode": view_mode,
        "offset": offset,
        "returned_bytes": returned_bytes,
        "total_bytes": total_size,
        "truncated": offset + returned_bytes < total_size,
        "content": content,
    }


def _format_hex(data: bytes, *, base_offset: int = 0) -> str:
    lines: list[str] = []
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_bytes = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{base_offset + index:08x}  {hex_bytes:<47}  |{ascii_bytes}|")
    return "\n".join(lines)


def _parse_hex_patch(text: str) -> bytes:
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(compact) % 2:
        raise ValueError("Hex byte input must contain an even number of hexadecimal characters.")
    return bytes.fromhex(compact)


def _parse_hex_dump(text: str) -> bytes:
    parts: list[str] = []
    for line in text.splitlines():
        left = line.split("|", 1)[0]
        left = re.sub(r"^\s*[0-9A-Fa-f]{4,16}\s+", "", left)
        parts.extend(re.findall(r"(?i)(?:0x)?([0-9a-f]{2})(?![0-9a-f])", left))
    if not parts:
        return _parse_hex_patch(text)
    return bytes.fromhex("".join(parts))


def _load_manifest_and_node(run_output_dir: str | Path, node_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = list_browser_nodes(run_output_dir)
    for node in manifest.get("nodes") or []:
        if node.get("id") == node_id:
            return manifest, node
    raise KeyError(node_id)


def _assert_editable_node(manifest: dict[str, Any], node: dict[str, Any]) -> None:
    if not node.get("editable"):
        raise PermissionError(f"Node is not editable: {node.get('relative_path')}")
    workspace_root = Path(str(manifest.get("workspace_root", ""))).resolve()
    path = Path(str(node.get("path", ""))).resolve()
    if not _is_relative_to(path, workspace_root):
        raise PermissionError(f"Editable nodes must stay inside {workspace_root}: {path}")


def _record_edit(manifest: dict[str, Any], edit: dict[str, Any]) -> dict[str, Any]:
    edit = {"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **edit}
    edits_path = Path(str(manifest.get("edits_path", ""))).resolve()
    try:
        payload = _read_json(edits_path)
    except FileNotFoundError:
        payload = {"edits": []}
    edits = payload.setdefault("edits", [])
    if not isinstance(edits, list):
        payload["edits"] = edits = []
    edits.append(edit)
    ensure_dir(edits_path.parent)
    edits_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return edit


def _write_browser_readme(workspace_root: Path) -> None:
    path = workspace_root / "README.md"
    if path.exists():
        return
    path.write_text(
        "# RE-Pro Browse Workspace\n\n"
        "This tree is a non-destructive editable view over one analysis run.\n\n"
        "- `source/` is prioritized and contains source maps, symbol-derived source, and pseudo-source.\n"
        "- `archives/` contains safely extracted archive members when the format is directly reversible.\n"
        "- `binary/` contains editable copies of small raw targets for hex patching.\n"
        "- `artifacts/` mirrors relevant analyzer outputs and extracted payloads.\n"
        "- `edits.json` records text writes and byte patches applied through the browser API.\n",
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object, validating the shape when the artifact is one we own.

    Falls back to a generic object check for unrelated files (the helper is
    also used for arbitrary user-visible JSON previews).
    """
    payload = load_json_object(path)
    name = path.name
    try:
        if name == "report.json":
            return validate_report(path, payload)
        if name == BROWSER_MANIFEST_NAME:
            return validate_browser_manifest(path, payload)
        if name == BROWSER_EDITS_NAME:
            return validate_edits(path, payload)
    except SchemaError:
        raise
    return payload


def _normalize_relative(relative_path: str) -> str:
    return sanitize_relative_source_path(relative_path)


def _safe_join(*parts: str) -> str:
    return "/".join(_normalize_relative(part).strip("/") for part in parts if str(part).strip())


def _unique_relative(relative_path: str, seen_relatives: set[str]) -> str:
    candidate = _normalize_relative(relative_path)
    if candidate not in seen_relatives:
        seen_relatives.add(candidate)
        return candidate
    path = Path(candidate)
    stem = path.stem or "file"
    suffix = path.suffix
    parent = path.parent.as_posix()
    index = 2
    while True:
        renamed = f"{stem}_{index}{suffix}"
        next_candidate = f"{parent}/{renamed}" if parent != "." else renamed
        if next_candidate not in seen_relatives:
            seen_relatives.add(next_candidate)
            return next_candidate
        index += 1


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _should_skip_path(path: Path, *, skip_browser_workspace: bool = False) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".git" in parts or "__pycache__" in parts or (skip_browser_workspace and BROWSER_WORKSPACE_DIR.lower() in parts)
