from __future__ import annotations

import json
from pathlib import Path

from .models import RecoveredSource
from .utils import ensure_dir, safe_output_path, safe_slug


def restore_sources_from_map(map_path: Path, destination_root: Path) -> tuple[list[RecoveredSource], list[str]]:
    recovered: list[RecoveredSource] = []
    notes: list[str] = []

    try:
        payload = json.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [], [f"Failed to parse source map {map_path}: {exc}"]

    sources = payload.get("sources") or []
    sources_content = payload.get("sourcesContent") or []
    source_root = payload.get("sourceRoot") or ""
    bundle_name = payload.get("file") or map_path.stem
    recovery_root = ensure_dir(destination_root / safe_slug(bundle_name))

    if not sources:
        return [], [f"Source map {map_path.name} did not contain any sources."]

    if not sources_content:
        return [], [f"Source map {map_path.name} listed sources but omitted sourcesContent."]

    for index, source in enumerate(sources):
        content = sources_content[index] if index < len(sources_content) else None
        if content is None:
            notes.append(f"No sourcesContent entry existed for {source} in {map_path.name}.")
            continue

        candidate_path = f"{source_root}/{source}" if source_root else source
        destination = safe_output_path(recovery_root, candidate_path)
        ensure_dir(destination.parent)
        destination.write_text(content, encoding="utf-8")
        recovered.append(
            RecoveredSource(
                original_path=source,
                restored_path=str(destination),
                source_map=str(map_path),
            )
        )

    return recovered, notes
