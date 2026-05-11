from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .json_schemas import load_analysis_index, load_report
from .utils import ensure_dir


def compare_analysis_runs(base_run_dir: Path, head_run_dir: Path, output_dir: Path | None = None) -> dict[str, Any]:
    base_run_dir = base_run_dir.resolve()
    head_run_dir = head_run_dir.resolve()
    base_report = load_report(base_run_dir / "report.json")
    head_report = load_report(head_run_dir / "report.json")
    base_index = load_analysis_index(base_run_dir / "analysis_index.json")
    head_index = load_analysis_index(head_run_dir / "analysis_index.json")

    diff = {
        "base_run_dir": str(base_run_dir),
        "head_run_dir": str(head_run_dir),
        "target_pair": {
            "base": base_report.get("target"),
            "head": head_report.get("target"),
        },
        "frameworks": _list_delta(base_report.get("frameworks") or [], head_report.get("frameworks") or []),
        "findings": _list_delta(
            [finding.get("title") for finding in (base_report.get("findings") or []) if finding.get("title")],
            [finding.get("title") for finding in (head_report.get("findings") or []) if finding.get("title")],
        ),
        "recovered_sources": _list_delta(
            [source.get("original_path") for source in (base_report.get("recovered_sources") or []) if source.get("original_path")],
            [source.get("original_path") for source in (head_report.get("recovered_sources") or []) if source.get("original_path")],
        ),
        "artifacts": {
            "base_count": len(base_report.get("artifacts") or []),
            "head_count": len(head_report.get("artifacts") or []),
            "delta": len(head_report.get("artifacts") or []) - len(base_report.get("artifacts") or []),
        },
        "analysis_index": _compare_analysis_index(base_index, head_index),
    }

    summary_lines = [
        f"Base: {base_run_dir}",
        f"Head: {head_run_dir}",
        f"Frameworks added: {len(diff['frameworks']['added'])}",
        f"Frameworks removed: {len(diff['frameworks']['removed'])}",
        f"Recovered sources added: {len(diff['recovered_sources']['added'])}",
        f"Recovered sources removed: {len(diff['recovered_sources']['removed'])}",
        f"Analysis-index entity delta: {diff['analysis_index']['entity_delta']}",
    ]
    diff["summary"] = "\n".join(summary_lines)

    if output_dir is not None:
        output_dir = ensure_dir(output_dir.resolve())
        json_path = output_dir / "analysis_diff.json"
        md_path = output_dir / "analysis_diff.md"
        json_path.write_text(json.dumps(diff, indent=2), encoding="utf-8")
        md_path.write_text(_render_diff_markdown(diff), encoding="utf-8")
        diff["json_path"] = str(json_path)
        diff["markdown_path"] = str(md_path)

    return diff


def create_patch_bundle_from_runs(base_run_dir: Path, head_run_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir = ensure_dir(output_dir.resolve())
    diff = compare_analysis_runs(base_run_dir, head_run_dir)
    head_report = load_report(head_run_dir.resolve() / "report.json")
    files_root = ensure_dir(output_dir / "files")
    operations: list[dict[str, Any]] = []

    for source in head_report.get("recovered_sources") or []:
        original_path = str(source.get("original_path", "")).replace("\\", "/").strip()
        restored_path = str(source.get("restored_path", "")).strip()
        if not original_path or original_path not in diff["recovered_sources"]["added"]:
            continue
        source_path = Path(restored_path)
        if not source_path.exists() or not source_path.is_file():
            continue
        destination = files_root / original_path
        ensure_dir(destination.parent)
        destination.write_bytes(source_path.read_bytes())
        operations.append(
            {
                "kind": "recovered_source",
                "relative_path": original_path,
                "source_path": str(source_path),
            }
        )

    for artifact in head_report.get("artifacts") or []:
        category = str(artifact.get("category", "")).lower()
        if category not in {"manifest", "resource", "payload"}:
            continue
        artifact_path = Path(str(artifact.get("path", "")).strip())
        if not artifact_path.exists() or not artifact_path.is_file():
            continue
        relative_path = f"artifacts/{artifact_path.name}"
        destination = files_root / relative_path
        ensure_dir(destination.parent)
        destination.write_bytes(artifact_path.read_bytes())
        operations.append(
            {
                "kind": "artifact",
                "relative_path": relative_path,
                "source_path": str(artifact_path),
                "category": category,
                "description": artifact.get("description"),
            }
        )

    payload = {
        "base_run_dir": str(base_run_dir),
        "head_run_dir": str(head_run_dir),
        "summary": diff["summary"],
        "operations": operations,
    }
    operations_path = output_dir / "operations.json"
    summary_path = output_dir / "summary.json"
    operations_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    summary_path.write_text(json.dumps(diff, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "bundle_root": str(output_dir),
        "operations_path": str(operations_path),
        "summary_path": str(summary_path),
        "operation_count": len(operations),
    }


def _list_delta(base_items: list[Any], head_items: list[Any]) -> dict[str, list[Any]]:
    base_set = {item for item in base_items if item not in (None, "")}
    head_set = {item for item in head_items if item not in (None, "")}
    return {
        "added": sorted(head_set - base_set),
        "removed": sorted(base_set - head_set),
        "unchanged_count": len(base_set & head_set),
    }


def _compare_analysis_index(base_index: dict[str, Any], head_index: dict[str, Any]) -> dict[str, Any]:
    base_entities = base_index.get("entities") or []
    head_entities = head_index.get("entities") or []
    base_relations = base_index.get("relations") or []
    head_relations = head_index.get("relations") or []

    base_entity_ids = {f"{entity.get('kind')}:{entity.get('key')}" for entity in base_entities}
    head_entity_ids = {f"{entity.get('kind')}:{entity.get('key')}" for entity in head_entities}
    base_relation_ids = {_relation_key(relation) for relation in base_relations}
    head_relation_ids = {_relation_key(relation) for relation in head_relations}

    return {
        "base_entity_count": len(base_entities),
        "head_entity_count": len(head_entities),
        "entity_delta": len(head_entities) - len(base_entities),
        "added_entities": sorted(head_entity_ids - base_entity_ids)[:500],
        "removed_entities": sorted(base_entity_ids - head_entity_ids)[:500],
        "base_relation_count": len(base_relations),
        "head_relation_count": len(head_relations),
        "relation_delta": len(head_relations) - len(base_relations),
        "added_relations": sorted(head_relation_ids - base_relation_ids)[:500],
        "removed_relations": sorted(base_relation_ids - head_relation_ids)[:500],
        "entity_kind_counts": {
            "base": _count_by_kind(base_entities),
            "head": _count_by_kind(head_entities),
        },
    }


def _count_by_kind(entities: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entity in entities:
        kind = str(entity.get("kind", "")).strip() or "unknown"
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def _relation_key(relation: dict[str, Any]) -> str:
    return f"{relation.get('source')}::{relation.get('predicate')}::{relation.get('target')}"


def _render_diff_markdown(diff: dict[str, Any]) -> str:
    lines = [
        "# Analysis Diff",
        "",
        f"- Base run: `{diff['base_run_dir']}`",
        f"- Head run: `{diff['head_run_dir']}`",
        f"- Frameworks added: {len(diff['frameworks']['added'])}",
        f"- Frameworks removed: {len(diff['frameworks']['removed'])}",
        f"- Recovered sources added: {len(diff['recovered_sources']['added'])}",
        f"- Recovered sources removed: {len(diff['recovered_sources']['removed'])}",
        "",
        "## Framework Changes",
        "",
    ]
    lines.extend(f"- Added: `{item}`" for item in diff["frameworks"]["added"][:50])
    lines.extend(f"- Removed: `{item}`" for item in diff["frameworks"]["removed"][:50])
    lines.extend(
        [
            "",
            "## Analysis Index",
            "",
            f"- Entity delta: {diff['analysis_index']['entity_delta']}",
            f"- Relation delta: {diff['analysis_index']['relation_delta']}",
        ]
    )
    return "\n".join(lines) + "\n"
