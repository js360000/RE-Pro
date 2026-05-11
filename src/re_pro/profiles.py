from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import (
    FrontendSettings,
    LiveProcessSettings,
    LlmAssistSettings,
    OutputSettings,
    PortingSettings,
    RuntimeTraceSettings,
)
from .utils import ensure_dir

PROFILE_SCHEMA_VERSION = 1


def get_profiles_root(profiles_root: str | Path | None = None) -> Path:
    root = Path(profiles_root).resolve() if profiles_root else (Path.cwd() / "profiles").resolve()
    return ensure_dir(root)


def build_analysis_profile(
    *,
    name: str,
    target: str,
    output_root: str,
    plugin_dirs: list[str] | None = None,
    run_external_tools: bool = False,
    run_ghidra: bool = False,
    llm_settings: LlmAssistSettings | None = None,
    porting_settings: PortingSettings | None = None,
    runtime_trace_settings: RuntimeTraceSettings | None = None,
    live_process_settings: LiveProcessSettings | None = None,
    frontend_settings: FrontendSettings | None = None,
    output_settings: OutputSettings | None = None,
    report: dict[str, Any] | None = None,
    output_dir: str = "",
) -> dict[str, Any]:
    llm_settings = llm_settings or LlmAssistSettings()
    porting_settings = porting_settings or PortingSettings()
    runtime_trace_settings = runtime_trace_settings or RuntimeTraceSettings()
    live_process_settings = live_process_settings or LiveProcessSettings()
    frontend_settings = frontend_settings or FrontendSettings()
    output_settings = output_settings or OutputSettings()
    now = utc_now()
    report = report or {}
    run_summary = {
        "target": report.get("target") or target,
        "target_type": report.get("target_type", ""),
        "output_dir": report.get("output_dir") or output_dir,
        "frameworks": report.get("frameworks") or [],
        "findings_count": len(report.get("findings") or []),
        "artifacts_count": len(report.get("artifacts") or []),
        "recovered_sources_count": len(report.get("recovered_sources") or []),
        "saved_at": now,
    }
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_type": "analysis",
        "name": name.strip() or Path(target).stem,
        "created_at": now,
        "updated_at": now,
        "settings": {
            "target": str(target),
            "output_root": str(output_root),
            "plugin_dirs": [str(path) for path in (plugin_dirs or [])],
            "run_external_tools": bool(run_external_tools),
            "run_ghidra": bool(run_ghidra),
            "llm_settings": llm_settings.to_dict(),
            "porting_settings": porting_settings.to_dict(),
            "runtime_trace_settings": runtime_trace_settings.to_dict(),
            "live_process_settings": live_process_settings.to_dict(),
            "frontend_settings": frontend_settings.to_dict(),
            "output_settings": output_settings.to_dict(),
        },
        "last_run": run_summary,
        "search_text": build_profile_search_text(
            [
                name,
                target,
                output_root,
                *(plugin_dirs or []),
                *(run_summary["frameworks"] or []),
            ]
        ),
    }


def build_package_action_profile(
    *,
    name: str,
    workspace_root: str,
    ecosystem: str,
    action: str,
    artifact_path: str = "",
    output_path: str = "",
    keystore_path: str = "",
    key_alias: str = "",
    patch_bundle_path: str = "",
    target_root: str = "",
    compression: str = "zlib",
    compression_level: int = 9,
    block_size: int = 0x10000,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    result = result or {}
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_type": "package_action",
        "name": name.strip() or f"{ecosystem}-{action}",
        "created_at": now,
        "updated_at": now,
        "settings": {
            "workspace_root": str(workspace_root),
            "ecosystem": str(ecosystem),
            "action": str(action),
            "artifact_path": str(artifact_path),
            "output_path": str(output_path),
            "keystore_path": str(keystore_path),
            "key_alias": str(key_alias),
            "patch_bundle_path": str(patch_bundle_path),
            "target_root": str(target_root),
            "compression": str(compression),
            "compression_level": int(compression_level),
            "block_size": int(block_size),
        },
        "last_result": sanitize_package_result(result, saved_at=now),
        "search_text": build_profile_search_text(
            [
                name,
                workspace_root,
                ecosystem,
                action,
                artifact_path,
                output_path,
                keystore_path,
                key_alias,
                patch_bundle_path,
                target_root,
                compression,
                result.get("rebuilt_artifact", ""),
                result.get("signed_artifact", ""),
            ]
        ),
    }


def save_profile(profile: dict[str, Any], *, profiles_root: str | Path | None = None) -> Path:
    root = get_profiles_root(profiles_root)
    profile_type = str(profile.get("profile_type", "generic")).strip().lower() or "generic"
    target_dir = ensure_dir(root / profile_type)
    profile_id = str(profile.get("profile_id", "")).strip() or build_profile_id(profile)
    path = target_dir / f"{profile_id}.json"
    if path.exists():
        suffix = 2
        while True:
            candidate_id = f"{profile_id}-{suffix}"
            candidate_path = target_dir / f"{candidate_id}.json"
            if not candidate_path.exists():
                profile_id = candidate_id
                path = candidate_path
                break
            suffix += 1
    profile["profile_id"] = profile_id
    profile["updated_at"] = utc_now()
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path


def list_profiles(
    *,
    profiles_root: str | Path | None = None,
    query: str = "",
    profile_type: str = "",
) -> list[dict[str, Any]]:
    root = get_profiles_root(profiles_root)
    normalized_query = query.strip().lower()
    normalized_type = profile_type.strip().lower()
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.json")):
        profile = read_profile(path)
        if profile is None:
            continue
        if normalized_type and str(profile.get("profile_type", "")).strip().lower() != normalized_type:
            continue
        summary = summarize_profile(profile, path)
        haystack = " ".join(
            [
                summary.get("profile_id", ""),
                summary.get("name", ""),
                summary.get("profile_type", ""),
                summary.get("primary_target", ""),
                summary.get("secondary_target", ""),
                summary.get("search_text", ""),
            ]
        ).lower()
        if normalized_query and normalized_query not in haystack:
            continue
        entries.append(summary)
    entries.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return entries


def load_profile(identifier: str | Path, *, profiles_root: str | Path | None = None) -> dict[str, Any]:
    path = resolve_profile_path(identifier, profiles_root=profiles_root)
    profile = read_profile(path)
    if profile is None:
        raise FileNotFoundError(path)
    profile.setdefault("profile_path", str(path))
    return profile


def read_profile(path: str | Path) -> dict[str, Any] | None:
    candidate = Path(path)
    if not candidate.exists() or not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    payload.setdefault("profile_path", str(candidate.resolve()))
    return payload


def resolve_profile_path(identifier: str | Path, *, profiles_root: str | Path | None = None) -> Path:
    candidate = Path(identifier)
    if candidate.exists():
        return candidate.resolve()
    normalized_identifier = str(identifier).strip().lower()
    matches: list[Path] = []
    for entry in list_profiles(profiles_root=profiles_root):
        for value in [entry.get("profile_id", ""), Path(str(entry.get("path", ""))).stem, entry.get("name", "")]:
            if str(value).strip().lower() == normalized_identifier:
                matches.append(Path(str(entry["path"])))
                break
    if not matches:
        raise FileNotFoundError(identifier)
    if len(matches) > 1:
        raise ValueError(f"Profile identifier is ambiguous: {identifier}")
    return matches[0].resolve()


def summarize_profile(profile: dict[str, Any], path: str | Path) -> dict[str, Any]:
    profile_type = str(profile.get("profile_type", "")).strip().lower()
    settings = profile.get("settings") or {}
    primary_target = ""
    secondary_target = ""
    if profile_type == "analysis":
        primary_target = str(settings.get("target", ""))
        secondary_target = str((profile.get("last_run") or {}).get("output_dir", ""))
    elif profile_type == "package_action":
        primary_target = str(settings.get("workspace_root", ""))
        secondary_target = f"{settings.get('ecosystem', '')}:{settings.get('action', '')}".strip(":")
    return {
        "profile_id": str(profile.get("profile_id", "")),
        "name": str(profile.get("name", "")),
        "profile_type": profile_type,
        "path": str(Path(path).resolve()),
        "updated_at": str(profile.get("updated_at", "")),
        "primary_target": primary_target,
        "secondary_target": secondary_target,
        "search_text": str(profile.get("search_text", "")),
    }


def analysis_settings_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    settings = profile.get("settings") or {}
    return {
        "target": str(settings.get("target", "")),
        "output_root": str(settings.get("output_root", "")),
        "plugin_dirs": [str(path) for path in (settings.get("plugin_dirs") or [])],
        "run_external_tools": bool(settings.get("run_external_tools", False)),
        "run_ghidra": bool(settings.get("run_ghidra", False)),
        "llm_settings": LlmAssistSettings.from_dict(settings.get("llm_settings")),
        "porting_settings": PortingSettings.from_dict(settings.get("porting_settings")),
        "runtime_trace_settings": RuntimeTraceSettings.from_dict(settings.get("runtime_trace_settings")),
        "live_process_settings": LiveProcessSettings.from_dict(settings.get("live_process_settings")),
        "frontend_settings": FrontendSettings.from_dict(settings.get("frontend_settings")),
        "output_settings": OutputSettings.from_dict(settings.get("output_settings")),
    }


def package_settings_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    settings = profile.get("settings") or {}
    return {
        "workspace_root": str(settings.get("workspace_root", "")),
        "ecosystem": str(settings.get("ecosystem", "")),
        "action": str(settings.get("action", "")),
        "artifact_path": str(settings.get("artifact_path", "")),
        "output_path": str(settings.get("output_path", "")),
        "keystore_path": str(settings.get("keystore_path", "")),
        "key_alias": str(settings.get("key_alias", "")),
        "patch_bundle_path": str(settings.get("patch_bundle_path", "")),
        "target_root": str(settings.get("target_root", "")),
        "compression": str(settings.get("compression", "zlib")),
        "compression_level": int(settings.get("compression_level", 9) or 9),
        "block_size": int(settings.get("block_size", 0x10000) or 0x10000),
    }


def build_profile_id(profile: dict[str, Any]) -> str:
    name = str(profile.get("name", "profile"))
    profile_type = str(profile.get("profile_type", "generic"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{profile_type}-{slugify(name)}-{stamp}"


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return cleaned or "profile"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_package_result(result: dict[str, Any], *, saved_at: str) -> dict[str, Any]:
    sanitized: dict[str, Any] = {"saved_at": saved_at, "ok": bool(result.get("ok", False))}
    for key in [
        "error",
        "rebuilt_artifact",
        "signed_artifact",
        "output_path",
        "artifact_path",
        "target_root",
        "bundle_root",
        "operations_applied",
        "copied_files",
        "stdout",
        "stderr",
        "command",
        "note",
    ]:
        if key not in result:
            continue
        value = result.get(key)
        if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
            sanitized[key] = value
    return sanitized


def build_profile_search_text(parts: list[str]) -> str:
    return " ".join(part.strip() for part in parts if str(part).strip())
