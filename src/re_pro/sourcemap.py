from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import unquote

from .models import RecoveredSource
from .utils import ensure_dir, safe_output_path, safe_slug


def restore_sources_from_map(map_path: Path, destination_root: Path) -> tuple[list[RecoveredSource], list[str]]:
    try:
        payload = json.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [], [f"Failed to parse source map {map_path}: {exc}"]

    return _restore_sources_from_payload(
        payload,
        map_path.name,
        destination_root,
        source_map_label=str(map_path),
        source_base_dir=map_path.parent,
    )


def restore_inline_source_maps_from_file(source_path: Path, destination_root: Path) -> tuple[list[RecoveredSource], list[str]]:
    try:
        text = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [], [f"Failed to read {source_path}: {exc}"]
    recovered: list[RecoveredSource] = []
    notes: list[str] = []
    for index, payload in enumerate(_iter_inline_source_map_payloads(text), start=1):
        map_name = f"{source_path.name}.inline-{index}.map"
        restored, map_notes = _restore_sources_from_payload(payload, map_name, destination_root, source_map_label=str(source_path))
        recovered.extend(restored)
        notes.extend(map_notes)
    return recovered, notes


def _restore_sources_from_payload(
    payload: dict[str, object],
    map_name: str,
    destination_root: Path,
    *,
    source_map_label: str,
    source_base_dir: Path | None = None,
) -> tuple[list[RecoveredSource], list[str]]:
    recovered: list[RecoveredSource] = []
    notes: list[str] = []
    sources = payload.get("sources") or []
    sources_content = payload.get("sourcesContent") or []
    source_root = payload.get("sourceRoot") or ""
    bundle_name = payload.get("file") or Path(map_name).stem
    recovery_root = ensure_dir(destination_root / safe_slug(str(bundle_name)))
    if not sources:
        return [], [f"Source map {map_name} did not contain any sources."]
    for index, source in enumerate(sources):
        content = sources_content[index] if index < len(sources_content) else None
        if content is None:
            content = _read_referenced_source(source_base_dir, str(source_root), str(source))
            if content is None:
                notes.append(f"No sourcesContent entry or readable source file existed for {source} in {map_name}.")
                continue
        candidate_path = f"{source_root}/{source}" if source_root else str(source)
        destination = safe_output_path(recovery_root, candidate_path)
        ensure_dir(destination.parent)
        destination.write_text(str(content), encoding="utf-8")
        recovered.append(RecoveredSource(original_path=str(source), restored_path=str(destination), source_map=source_map_label))
    return recovered, notes


def _iter_inline_source_map_payloads(text: str) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    pattern = re.compile(r"sourceMappingURL=data:application/json(?:;charset=[^;,]+)?(?P<base64>;base64)?,(?P<data>[^\s*]+)")
    for match in pattern.finditer(text):
        encoded = match.group("data")
        try:
            if match.group("base64"):
                raw = base64.b64decode(encoded).decode("utf-8")
            else:
                raw = unquote(encoded)
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads


def _read_referenced_source(source_base_dir: Path | None, source_root: str, source: str) -> str | None:
    if source_base_dir is None:
        return None
    for candidate in _referenced_source_candidates(source_base_dir, source_root, source):
        try:
            if candidate.exists() and candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    return None


def _referenced_source_candidates(source_base_dir: Path, source_root: str, source: str) -> list[Path]:
    normalized_source = _normalize_source_reference(source)
    normalized_root = _normalize_source_reference(source_root)
    pieces = [piece for piece in (normalized_root, normalized_source) if piece]
    joined = "/".join(pieces)
    candidates: list[Path] = []
    if joined:
        candidates.append(source_base_dir / Path(joined))
    if normalized_source:
        candidates.append(source_base_dir / Path(normalized_source))
        parts = Path(normalized_source).parts
        for index, part in enumerate(parts):
            if part in {"src", "source", "sources", "app", "renderer"}:
                candidates.append(source_base_dir / Path(*parts[index:]))
                break
    return candidates


def _normalize_source_reference(value: str) -> str:
    value = unquote(str(value or "")).replace("\\", "/").strip()
    value = value.split("?", 1)[0].split("#", 1)[0]
    value = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", value)
    value = value.lstrip("/")
    while value.startswith("../"):
        value = value[3:]
    while value.startswith("./"):
        value = value[2:]
    return value
