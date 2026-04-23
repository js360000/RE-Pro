from __future__ import annotations

import json
from pathlib import Path

from .analysis_index import AnalysisIndex


FUNCTION_EXPORT_DESCRIPTIONS = {
    "Ghidra function export": "ghidra",
    "rizin function list": "rizin",
    "radare2 function list": "radare2",
    "rizin Mach-O function list": "rizin",
    "radare2 Mach-O function list": "radare2",
}

STRING_EXPORT_DESCRIPTIONS = {
    "Ghidra strings export": "ghidra",
    "rizin strings export": "rizin",
    "radare2 strings export": "radare2",
    "rizin Mach-O strings export": "rizin",
    "radare2 Mach-O strings export": "radare2",
}

PROGRAM_INFO_DESCRIPTIONS = {
    "Ghidra program metadata export": "ghidra",
}


def ingest_structured_artifacts(index: AnalysisIndex, report) -> dict[str, int]:
    target_id = index.make_id("target", report.target)
    function_entities: dict[tuple[str, str], str] = {}
    string_entities: dict[tuple[str, str], str] = {}

    for artifact in report.artifacts:
        path = Path(artifact.path)
        if not path.exists() or not path.is_file():
            continue
        tool_name = FUNCTION_EXPORT_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_function_export(index, target_id, path, tool_name, function_entities)
            continue
        tool_name = STRING_EXPORT_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_string_export(index, target_id, path, tool_name, string_entities)
            continue
        tool_name = PROGRAM_INFO_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_program_info(index, target_id, path, tool_name)

    function_correlations = _correlate_by_address(index, function_entities, predicate="correlates_with")
    string_correlations = _correlate_by_address(index, string_entities, predicate="correlates_with")
    return {
        "indexed_functions": len(function_entities),
        "indexed_strings": len(string_entities),
        "correlated_functions": function_correlations,
        "correlated_strings": string_correlations,
    }


def _ingest_function_export(
    index: AnalysisIndex,
    target_id: str,
    path: Path,
    tool_name: str,
    function_entities: dict[tuple[str, str], str],
) -> None:
    artifact_id = index.add_entity(
        "artifact",
        str(path),
        path.name,
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} function export"},
    )
    for entry in _load_json_list(path):
        address = _normalize_address(
            entry.get("entry_point")
            or entry.get("offset")
            or entry.get("minbound")
            or entry.get("body_min")
        )
        name = str(entry.get("name") or entry.get("signature") or address or "function")
        key = f"{tool_name}:{address or name.lower()}"
        function_id = index.add_entity(
            "function",
            key,
            name,
            attributes={
                "tool": tool_name,
                "address": address,
                "signature": entry.get("signature"),
                "calling_convention": entry.get("calling_convention") or entry.get("calltype"),
                "size": entry.get("size"),
                "namespace": entry.get("namespace"),
                "source_path": str(path),
            },
        )
        index.add_relation(target_id, "has_function_candidate", function_id, attributes={"tool": tool_name})
        tool_id = index.add_entity("tool", tool_name, tool_name, attributes={"kind": "external_re_tool"})
        index.add_relation(tool_id, "identified_function", function_id, attributes={"source_path": str(path)})
        index.add_relation(function_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
        if address:
            function_entities[(tool_name, address)] = function_id


def _ingest_string_export(
    index: AnalysisIndex,
    target_id: str,
    path: Path,
    tool_name: str,
    string_entities: dict[tuple[str, str], str],
) -> None:
    artifact_id = index.add_entity(
        "artifact",
        str(path),
        path.name,
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} string export"},
    )
    for entry in _load_json_list(path):
        address = _normalize_address(entry.get("address") or entry.get("offset") or entry.get("vaddr"))
        value = str(entry.get("value") or entry.get("string") or "").strip()
        if not value:
            continue
        key = f"{tool_name}:{address or value[:80].lower()}"
        string_id = index.add_entity(
            "string",
            key,
            value[:200],
            attributes={
                "tool": tool_name,
                "address": address,
                "length": entry.get("length") or len(value),
                "source": entry.get("source"),
                "source_path": str(path),
            },
        )
        index.add_relation(target_id, "contains_string_candidate", string_id, attributes={"tool": tool_name})
        tool_id = index.add_entity("tool", tool_name, tool_name, attributes={"kind": "external_re_tool"})
        index.add_relation(tool_id, "identified_string", string_id, attributes={"source_path": str(path)})
        index.add_relation(string_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
        if address:
            string_entities[(tool_name, address)] = string_id


def _ingest_program_info(index: AnalysisIndex, target_id: str, path: Path, tool_name: str) -> None:
    payload = _load_json_object(path)
    if not payload:
        return
    artifact_id = index.add_entity(
        "artifact",
        str(path),
        path.name,
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} program metadata export"},
    )
    info_id = index.add_entity(
        "program_info",
        f"{tool_name}:{path}",
        f"{tool_name} program info",
        attributes={**payload, "tool": tool_name, "source_path": str(path)},
    )
    index.add_relation(target_id, "has_program_info", info_id, attributes={"tool": tool_name})
    tool_id = index.add_entity("tool", tool_name, tool_name, attributes={"kind": "external_re_tool"})
    index.add_relation(tool_id, "reported_program_info", info_id, attributes={"source_path": str(path)})
    index.add_relation(info_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})


def _correlate_by_address(
    index: AnalysisIndex,
    entities: dict[tuple[str, str], str],
    *,
    predicate: str,
) -> int:
    grouped: dict[str, list[str]] = {}
    for (_, address), entity_id in entities.items():
        grouped.setdefault(address, []).append(entity_id)

    count = 0
    for address, ids in grouped.items():
        if len(ids) < 2:
            continue
        canonical_id = index.add_entity("address", address, address, attributes={"address": address})
        for entity_id in ids:
            index.add_relation(entity_id, "at_address", canonical_id)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                index.add_relation(ids[i], predicate, ids[j], attributes={"address": address})
                index.add_relation(ids[j], predicate, ids[i], attributes={"address": address})
                count += 1
    return count


def _load_json_list(path: Path) -> list[dict[str, object]]:
    payload = _load_json_object(path)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _load_json_object(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _normalize_address(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return f"0x{int(text, 16):x}"
        except ValueError:
            return text.lower()
    if all(character in "0123456789abcdefABCDEF" for character in text):
        return f"0x{int(text, 16):x}"
    try:
        parsed = int(text, 10)
    except ValueError:
        return text
    return f"0x{parsed:x}"
