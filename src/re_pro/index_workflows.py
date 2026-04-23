from __future__ import annotations

from pathlib import Path


def build_entity_workflow(report: dict, analysis_index: dict, entity_id: str) -> dict[str, object]:
    entity = _find_entity(analysis_index, entity_id)
    relations = _related_relations(analysis_index, entity_id)
    entities_by_id = {
        f"{candidate.get('kind')}:{candidate.get('key')}": candidate
        for candidate in analysis_index.get("entities") or []
    }
    related_entities = []
    for relation in relations:
        other_id = relation.get("target") if relation.get("source") == entity_id else relation.get("source")
        other = entities_by_id.get(str(other_id))
        if other is not None:
            related_entities.append(other)

    artifact_candidates = _collect_artifact_candidates(entity, related_entities, relations)
    recovered_sources = _collect_recovered_sources(report, analysis_index, entity, related_entities)
    framework_context = _collect_framework_context(report, entity, related_entities)
    action_targets = _build_action_targets(report, artifact_candidates, recovered_sources)
    workflow_summary = _build_workflow_summary(
        entity=entity,
        artifact_candidates=artifact_candidates,
        recovered_sources=recovered_sources,
        framework_context=framework_context,
        action_targets=action_targets,
    )
    return {
        "entity": entity,
        "relations": relations,
        "related_entities": related_entities,
        "artifact_candidates": artifact_candidates,
        "recovered_sources": recovered_sources,
        "framework_context": framework_context,
        "action_targets": action_targets,
        "workflow_summary": workflow_summary,
    }


def _find_entity(analysis_index: dict, entity_id: str) -> dict:
    for candidate in analysis_index.get("entities") or []:
        candidate_id = f"{candidate.get('kind')}:{candidate.get('key')}"
        if candidate_id == entity_id:
            return candidate
    raise KeyError(entity_id)


def _related_relations(analysis_index: dict, entity_id: str) -> list[dict]:
    return [
        relation
        for relation in analysis_index.get("relations") or []
        if relation.get("source") == entity_id or relation.get("target") == entity_id
    ]


def _collect_artifact_candidates(entity: dict, related_entities: list[dict], relations: list[dict]) -> list[dict]:
    seen_paths: set[str] = set()
    candidates: list[dict] = []
    for candidate in [entity, *related_entities]:
        path = _path_from_entity(candidate)
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        candidates.append(
            {
                "path": path,
                "label": str(candidate.get("label", "")) or Path(path).name,
                "kind": str(candidate.get("kind", "")),
                "relation_predicates": [
                    relation.get("predicate")
                    for relation in relations
                    if _relation_touches_entity(relation, candidate)
                ],
            }
        )
    return candidates


def _collect_recovered_sources(report: dict, analysis_index: dict, entity: dict, related_entities: list[dict]) -> list[dict]:
    by_restored_path = {
        str(source.get("restored_path", "")): source
        for source in report.get("recovered_sources") or []
        if source.get("restored_path")
    }
    collected: list[dict] = []
    seen: set[str] = set()
    for candidate in [entity, *related_entities]:
        path = _path_from_entity(candidate)
        if not path:
            continue
        source = by_restored_path.get(path)
        if source and path not in seen:
            seen.add(path)
            collected.append(source)
    if collected:
        return collected

    for source in report.get("recovered_sources") or []:
        original = str(source.get("original_path", "")).lower()
        restored = str(source.get("restored_path", "")).lower()
        label = str(entity.get("label", "")).lower()
        key = str(entity.get("key", "")).lower()
        if label and (label in original or label in restored):
            restored_path = str(source.get("restored_path", ""))
            if restored_path not in seen:
                seen.add(restored_path)
                collected.append(source)
        elif key and (key in original or key in restored):
            restored_path = str(source.get("restored_path", ""))
            if restored_path not in seen:
                seen.add(restored_path)
                collected.append(source)
    return collected[:12]


def _collect_framework_context(report: dict, entity: dict, related_entities: list[dict]) -> list[str]:
    frameworks = list(report.get("frameworks") or [])
    if str(entity.get("kind", "")) == "framework":
        entity_label = str(entity.get("label", ""))
        if entity_label and entity_label not in frameworks:
            frameworks.insert(0, entity_label)
    for candidate in related_entities:
        if str(candidate.get("kind", "")) != "framework":
            continue
        label = str(candidate.get("label", ""))
        if label and label not in frameworks:
            frameworks.append(label)
    return frameworks[:12]


def _build_action_targets(report: dict, artifact_candidates: list[dict], recovered_sources: list[dict]) -> dict[str, object]:
    artifact_paths = [candidate["path"] for candidate in artifact_candidates if candidate.get("path")]
    recovered_paths = [str(source.get("restored_path")) for source in recovered_sources if source.get("restored_path")]
    return {
        "artifact_paths": artifact_paths,
        "recovered_source_paths": recovered_paths,
        "porting_notes_path": _find_artifact_path(report, "Porting guidance"),
        "prepared_sources_path": _find_artifact_path(report, "Prepared sources for porting work"),
        "recompile_workspace_path": _find_artifact_path(report, "Recompile workspace"),
        "recompile_manifest_path": _find_artifact_path(report, "Recompile workspace manifest"),
        "llm_summary_path": _find_artifact_path(report, "LLM reconstruction summary"),
    }


def _build_workflow_summary(
    *,
    entity: dict,
    artifact_candidates: list[dict],
    recovered_sources: list[dict],
    framework_context: list[str],
    action_targets: dict[str, object],
) -> str:
    lines = [
        f"Entity: {entity.get('kind', '')} -> {entity.get('label', '')}",
        f"Related artifact candidates: {len(artifact_candidates)}",
        f"Related recovered sources: {len(recovered_sources)}",
    ]
    if framework_context:
        lines.append(f"Framework context: {', '.join(framework_context)}")
    if action_targets.get("porting_notes_path"):
        lines.append("Porting guidance available.")
    if action_targets.get("recompile_workspace_path"):
        lines.append("Recompile workspace available.")
    label = str(entity.get("label", "")).lower()
    kind = str(entity.get("kind", "")).lower()
    if kind in {"function", "string"}:
        lines.append("Suggested workflow: inspect the originating export artifact, then pivot to recovered or reconstructed sources.")
    elif kind == "framework":
        lines.append("Suggested workflow: open the porting notes and prepared sources first, then inspect framework-specific artifacts.")
    elif kind in {"artifact", "resource"}:
        lines.append("Suggested workflow: preview or open the artifact directly, then follow correlated entities for surrounding context.")
    elif "imgui" in label or "direct3d" in label or "vulkan" in label:
        lines.append("UI or rendering markers present: prioritize startup flow, renderer setup, and platform window bindings.")
    return "\n".join(lines)


def _find_artifact_path(report: dict, description_contains: str) -> str | None:
    lowered = description_contains.lower()
    for artifact in report.get("artifacts") or []:
        if lowered in str(artifact.get("description", "")).lower():
            return str(artifact.get("path", ""))
    return None


def _path_from_entity(entity: dict) -> str | None:
    if not isinstance(entity, dict):
        return None
    attributes = entity.get("attributes") or {}
    for key in ("path", "source_path", "restored_path"):
        value = attributes.get(key)
        if isinstance(value, str) and value.strip():
            return value
    kind = str(entity.get("kind", ""))
    if kind in {"artifact", "resource", "recovered_source"}:
        key = str(entity.get("key", ""))
        if key.strip():
            return key
    return None


def _relation_touches_entity(relation: dict, entity: dict) -> bool:
    entity_id = f"{entity.get('kind')}:{entity.get('key')}"
    return relation.get("source") == entity_id or relation.get("target") == entity_id
