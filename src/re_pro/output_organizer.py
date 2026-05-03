from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .models import AnalysisReport
from .models import Artifact
from .models import OutputSettings
from .utils import ensure_dir
from .utils import safe_slug


PROFILE_INCLUDES: dict[str, set[str]] = {
    "full": {"all"},
    "compact": {"reports", "recovered_sources", "usability", "manifests", "logs"},
    "minimal": {"reports", "recovered_sources", "usability"},
    "source-first": {"reports", "recovered_sources", "frontend", "native", "decompiler", "usability"},
    "tool-first": {"reports", "decompiler", "manifests", "logs", "runtime", "native", "usability"},
    "rebuild": {"reports", "recovered_sources", "porting", "browser", "packages", "manifests"},
}

DEFAULT_FOLDER_MAP: dict[str, str] = {
    "reports": "00_reports",
    "recovered_sources": "01_recovered_sources",
    "usability": "02_recovery_quality",
    "frontend": "03_frontend",
    "native": "04_native",
    "decompiler": "05_decompiler_outputs",
    "extracted": "06_extracted_payloads",
    "resources": "07_resources",
    "browser": "08_file_browser",
    "porting": "09_porting_rebuild",
    "runtime": "10_runtime",
    "llm": "11_llm",
    "packages": "12_packages",
    "manifests": "13_manifests",
    "logs": "14_logs",
    "artifacts": "90_other_artifacts",
}


def organize_output_view(report: AnalysisReport, output_dir: Path, settings: OutputSettings) -> dict[str, Any] | None:
    if not settings.enabled:
        return None
    output_dir = output_dir.resolve()
    view_root = ensure_dir(output_dir / safe_slug(settings.view_name or "operator_view"))
    include_buckets = _selected_buckets(settings)
    exclude_buckets = {bucket.lower() for bucket in settings.exclude}
    folder_map = {**DEFAULT_FOLDER_MAP, **{key.lower(): value for key, value in settings.folder_map.items()}}
    entries = _collect_entries(report)
    selected = [
        entry
        for entry in entries
        if _entry_is_selected(entry["bucket"], include_buckets)
        and entry["bucket"] not in exclude_buckets
        and Path(entry["path"]).exists()
    ]
    buckets: dict[str, list[dict[str, Any]]] = {}
    for entry in selected:
        buckets.setdefault(entry["bucket"], []).append(entry)

    copied_bytes = 0
    bucket_summaries: dict[str, dict[str, Any]] = {}
    materialized_entries: list[dict[str, Any]] = []
    for bucket, bucket_entries in sorted(buckets.items()):
        bucket_root = ensure_dir(view_root / _folder_for_bucket(bucket, folder_map))
        bucket_index: list[dict[str, Any]] = []
        for index, entry in enumerate(bucket_entries, start=1):
            materialized, copied = _materialize_entry(entry, bucket_root, index, settings, copied_bytes)
            copied_bytes += copied
            bucket_index.append(materialized)
            materialized_entries.append(materialized)
        (bucket_root / "index.md").write_text(_render_bucket_index(bucket, bucket_index), encoding="utf-8")
        bucket_summaries[bucket] = {
            "folder": str(bucket_root),
            "entry_count": len(bucket_index),
            "copied_count": sum(1 for item in bucket_index if item.get("copied_path")),
            "reference_count": sum(1 for item in bucket_index if item.get("link_descriptor")),
        }

    manifest = {
        "view_root": str(view_root),
        "mode": settings.mode,
        "profile": settings.profile,
        "include": sorted(include_buckets),
        "exclude": sorted(exclude_buckets),
        "folder_map": folder_map,
        "entry_count": len(materialized_entries),
        "copied_bytes": copied_bytes,
        "bucket_summaries": bucket_summaries,
        "entries": materialized_entries,
    }
    manifest_path = view_root / "output_view_manifest.json"
    readme_path = view_root / "README.md"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    readme_path.write_text(_render_view_readme(manifest), encoding="utf-8")
    return {
        "view_root": str(view_root),
        "manifest_path": str(manifest_path),
        "readme_path": str(readme_path),
        "entry_count": len(materialized_entries),
        "bucket_count": len(bucket_summaries),
        "copied_bytes": copied_bytes,
        "mode": settings.mode,
        "profile": settings.profile,
    }


def _collect_entries(report: AnalysisReport) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for artifact in report.artifacts:
        bucket = _bucket_for_artifact(artifact)
        entry = {
            "bucket": bucket,
            "kind": "artifact",
            "path": artifact.path,
            "category": artifact.category,
            "description": artifact.description,
            "label": Path(artifact.path).name or artifact.description,
        }
        key = (entry["kind"], str(Path(entry["path"]).resolve()) if Path(entry["path"]).exists() else entry["path"])
        if key not in seen:
            seen.add(key)
            entries.append(entry)
    for source in report.recovered_sources:
        entry = {
            "bucket": "recovered_sources",
            "kind": "recovered_source",
            "path": source.restored_path,
            "category": "source",
            "description": source.original_path,
            "source_map": source.source_map,
            "label": source.original_path or Path(source.restored_path).name,
        }
        key = (entry["kind"], str(Path(entry["path"]).resolve()) if Path(entry["path"]).exists() else entry["path"])
        if key not in seen:
            seen.add(key)
            entries.append(entry)
    return entries


def _bucket_for_artifact(artifact: Artifact) -> str:
    path_text = artifact.path.lower()
    description = artifact.description.lower()
    category = artifact.category.lower()
    haystack = " ".join([path_text, description, category])
    if any(token in description for token in ["recovery quality", "evidence graph", "stub elimination", "function evidence"]):
        return "usability"
    if "\\usability\\" in path_text or "/usability/" in path_text:
        return "usability"
    if category == "report" or "report." in path_text:
        return "reports"
    if "recovered source" in description:
        return "recovered_sources"
    if "browser_workspace" in path_text or "source-first browser" in description:
        return "browser"
    if any(token in haystack for token in ["llm", "codex", "assistant_summary", "reconstructed_src"]):
        return "llm"
    if any(token in haystack for token in ["porting", "recompile", "rebuild", "signing plan", "patch plan"]):
        return "porting"
    if any(token in haystack for token in ["runtime", "frida", "live process", "memory_dumps", "carved_payloads"]):
        return "runtime"
    if any(token in haystack for token in ["ghidra", "rizin", "radare2", "jadx", "apktool", "ilspy", "decompiled", "pseudo_code"]):
        return "decompiler"
    if any(token in haystack for token in ["asar", "source map", "sourcemap", "tauri", "electron", "frontend", "beautified", "webview"]):
        return "frontend"
    if any(token in haystack for token in ["pe ", "pe_", "pdb", "msvc", "rtti", "vftable", "mach-o", "elf", "native"]):
        return "native"
    if "extract" in description or path_text.endswith("_extract") or "_extract\\" in path_text or "_extract/" in path_text:
        return "extracted"
    if category in {"resource", "binary", "payload"} or "resource" in description:
        return "resources"
    if category in {"manifest", "metadata"} or path_text.endswith(".json") or path_text.endswith(".xml") or path_text.endswith(".plist"):
        return "manifests"
    if category == "log" or path_text.endswith(".log"):
        return "logs"
    if any(token in haystack for token in ["psarc", "pbp", "pkg", "package", "archive", "patch bundle"]):
        return "packages"
    return "artifacts"


def _selected_buckets(settings: OutputSettings) -> set[str]:
    profile = settings.profile.strip().lower() or "full"
    buckets = set(PROFILE_INCLUDES.get(profile, set() if profile == "custom" else PROFILE_INCLUDES["full"]))
    buckets.update(bucket.strip().lower() for bucket in settings.include if bucket.strip())
    return buckets


def _entry_is_selected(bucket: str, include_buckets: set[str]) -> bool:
    return "all" in include_buckets or bucket in include_buckets


def _folder_for_bucket(bucket: str, folder_map: dict[str, str]) -> str:
    raw = folder_map.get(bucket, bucket)
    parts = [safe_slug(part) for part in raw.replace("\\", "/").split("/") if part.strip() and part.strip() not in {".", ".."}]
    return str(Path(*parts)) if parts else safe_slug(bucket)


def _materialize_entry(
    entry: dict[str, Any],
    bucket_root: Path,
    index: int,
    settings: OutputSettings,
    copied_so_far: int,
) -> tuple[dict[str, Any], int]:
    source_path = Path(entry["path"])
    base_name = f"{index:04d}_{safe_slug(entry.get('label') or source_path.name or entry['bucket'])}"
    materialized = dict(entry)
    materialized["original_path"] = str(source_path)
    materialized["exists"] = source_path.exists()
    if settings.mode == "copy":
        destination = bucket_root / base_name
        copied, skipped_reason = _copy_path_limited(source_path, destination, settings.max_copy_bytes - copied_so_far)
        if copied:
            materialized["copied_path"] = str(destination)
            materialized["copied_bytes"] = copied
            return materialized, copied
        materialized["copy_skipped_reason"] = skipped_reason or "copy limit reached"

    descriptor = bucket_root / f"{base_name}.repro-link.json"
    descriptor.write_text(json.dumps(materialized, indent=2), encoding="utf-8")
    materialized["link_descriptor"] = str(descriptor)
    return materialized, 0


def _copy_path_limited(source: Path, destination: Path, remaining_bytes: int) -> tuple[int, str]:
    if remaining_bytes <= 0:
        return 0, "copy byte budget exhausted"
    try:
        if source.is_file():
            size = source.stat().st_size
            if size > remaining_bytes:
                return 0, f"file exceeds remaining copy budget ({size} > {remaining_bytes})"
            ensure_dir(destination.parent)
            if destination.exists() and destination.is_dir():
                destination = destination / source.name
            shutil.copy2(source, destination)
            return size, ""
        if source.is_dir():
            total = _directory_size(source, limit=remaining_bytes + 1)
            if total > remaining_bytes:
                return 0, f"directory exceeds remaining copy budget ({total} > {remaining_bytes})"
            _copy_tree(source, destination)
            return total, ""
    except OSError as exc:
        return 0, str(exc)
    return 0, "path is neither file nor directory"


def _directory_size(path: Path, *, limit: int) -> int:
    total = 0
    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        try:
            total += candidate.stat().st_size
        except OSError:
            continue
        if total > limit:
            return total
    return total


def _copy_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def _render_bucket_index(bucket: str, entries: list[dict[str, Any]]) -> str:
    lines = [f"# {bucket.replace('_', ' ').title()}", ""]
    if not entries:
        lines.append("No entries selected.")
    for entry in entries:
        target = entry.get("copied_path") or entry.get("original_path") or entry.get("path")
        lines.append(f"- [{entry.get('label') or Path(str(target)).name}]({target})")
        if entry.get("description"):
            lines.append(f"  - {entry['description']}")
        if entry.get("copy_skipped_reason"):
            lines.append(f"  - Copy skipped: {entry['copy_skipped_reason']}")
    return "\n".join(lines) + "\n"


def _render_view_readme(manifest: dict[str, Any]) -> str:
    lines = [
        "# RE-Pro Output View",
        "",
        f"- Profile: `{manifest['profile']}`",
        f"- Mode: `{manifest['mode']}`",
        f"- Entries: `{manifest['entry_count']}`",
        f"- Copied bytes: `{manifest['copied_bytes']}`",
        "",
        "## Folders",
        "",
    ]
    for bucket, summary in sorted((manifest.get("bucket_summaries") or {}).items()):
        lines.append(f"- `{bucket}` -> `{summary.get('folder')}` ({summary.get('entry_count', 0)} entries)")
    lines.extend(["", "See `output_view_manifest.json` for the machine-readable routing manifest."])
    return "\n".join(lines) + "\n"
