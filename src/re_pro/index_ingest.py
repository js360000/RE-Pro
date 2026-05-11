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

DECOMPILED_EXPORT_DESCRIPTIONS = {
    "Ghidra targeted pseudo-code export": "ghidra",
}

CLASS_EXPORT_DESCRIPTIONS = {
    "MSVC RTTI class manifest": "msvc_rtti",
    "Ghidra enriched class manifest": "msvc_rtti",
}

CLASS_CONTEXT_EXPORT_DESCRIPTIONS = {
    "Ghidra class callgraph manifest": "class_context",
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
            continue
        tool_name = DECOMPILED_EXPORT_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_decompiled_export(index, target_id, path, tool_name, function_entities)
            continue
        tool_name = CLASS_EXPORT_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_class_manifest(index, target_id, path, tool_name, function_entities)
            continue
        tool_name = CLASS_CONTEXT_EXPORT_DESCRIPTIONS.get(artifact.description)
        if tool_name:
            _ingest_class_context_manifest(index, target_id, path, tool_name, function_entities)

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


def _ingest_decompiled_export(
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
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} targeted pseudo-code export"},
    )
    tool_id = index.add_entity("tool", tool_name, tool_name, attributes={"kind": "external_re_tool"})
    for entry in _load_json_list(path):
        address = _normalize_address(entry.get("entry_point") or entry.get("requested_address"))
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
                "namespace": entry.get("namespace"),
                "decompile_success": entry.get("decompile_success"),
                "decompiled_c": entry.get("decompiled_c"),
                "pseudo_path": entry.get("pseudo_path"),
                "return_type": entry.get("return_type"),
                "params": entry.get("parameters"),
                "caller_count": entry.get("caller_count"),
                "callee_count": entry.get("callee_count"),
                "callers": entry.get("callers"),
                "callees": entry.get("callees"),
                "callsite_argument_hints": entry.get("callsite_argument_hints"),
                "result_hints": entry.get("result_hints"),
                "target_selection": entry.get("target_selection"),
                "source_path": str(path),
            },
        )
        index.add_relation(target_id, "has_function_candidate", function_id, attributes={"tool": tool_name})
        index.add_relation(tool_id, "decompiled_function", function_id, attributes={"source_path": str(path)})
        index.add_relation(function_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
        if address:
            function_entities[(tool_name, address)] = function_id


def _ingest_class_context_manifest(
    index: AnalysisIndex,
    target_id: str,
    path: Path,
    tool_name: str,
    function_entities: dict[tuple[str, str], str],
) -> None:
    payload = _load_json_object(path)
    if not isinstance(payload, dict):
        return
    artifact_id = index.add_entity(
        "artifact",
        str(path),
        path.name,
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} class callgraph manifest"},
    )
    tool_id = index.add_entity("tool", tool_name, "Ghidra class context", attributes={"kind": "class_callgraph_fusion"})
    for class_entry in payload.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        class_name = str(class_entry.get("name") or "").strip()
        if not class_name:
            continue
        class_id = index.add_entity(
            "class",
            f"{tool_name}:{class_name.lower()}",
            class_name,
            attributes={
                "tool": tool_name,
                "source_path": str(path),
                "base_classes": class_entry.get("base_classes"),
                "estimated_object_size": class_entry.get("estimated_object_size"),
                "members": class_entry.get("members"),
                "recovery_capabilities": class_entry.get("recovery_capabilities"),
            },
        )
        index.add_relation(target_id, "contains_class_context", class_id, attributes={"tool": tool_name})
        index.add_relation(tool_id, "contextualized_class", class_id, attributes={"source_path": str(path)})
        index.add_relation(class_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
        for method in class_entry.get("methods") or []:
            if not isinstance(method, dict):
                continue
            address = _normalize_address(method.get("address"))
            label = str(method.get("qualified_name") or method.get("name") or address or "method")
            function_id = index.add_entity(
                "function",
                f"{tool_name}:{address or label.lower()}",
                label,
                attributes={
                    "tool": tool_name,
                    "address": address,
                    "class_name": class_name,
                    "slot": method.get("slot"),
                    "vtable_rva": method.get("vtable_rva"),
                    "method_kind": method.get("method_kind"),
                    "semantic_alias": method.get("semantic_alias"),
                    "name_inference_source": method.get("name_inference_source"),
                    "name_inference_evidence": method.get("name_inference_evidence"),
                    "original_vtable_name": method.get("original_vtable_name"),
                    "return_type": method.get("return_type"),
                    "params": method.get("params"),
                    "decompiler": method.get("decompiler"),
                    "callers": method.get("callers"),
                    "callees": method.get("callees"),
                    "call_edges": method.get("call_edges"),
                    "llm_priority": method.get("llm_priority"),
                    "evidence": method.get("evidence"),
                    "source_path": str(path),
                },
            )
            index.add_relation(class_id, "declares_contextualized_method", function_id, attributes={"tool": tool_name})
            index.add_relation(tool_id, "contextualized_function", function_id, attributes={"source_path": str(path)})
            index.add_relation(function_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
            if address:
                function_entities[(tool_name, address)] = function_id
            for callee in method.get("callees") or []:
                if not isinstance(callee, dict):
                    continue
                callee_address = _normalize_address(callee.get("entry_point") or callee.get("to_address"))
                callee_label = str(callee.get("name") or callee_address or "callee")
                callee_id = index.add_entity(
                    "function",
                    f"{tool_name}:{callee_address or callee_label.lower()}",
                    callee_label,
                    attributes={
                        "tool": tool_name,
                        "address": callee_address,
                        "signature": callee.get("signature"),
                        "namespace": callee.get("namespace"),
                        "source_path": str(path),
                    },
                )
                index.add_relation(function_id, "calls", callee_id, attributes={"tool": tool_name, "callsite": callee.get("from_address")})
                if callee_address:
                    function_entities[(tool_name, callee_address)] = callee_id
            for caller in method.get("callers") or []:
                if not isinstance(caller, dict):
                    continue
                caller_address = _normalize_address(caller.get("caller_entry_point"))
                caller_label = str(caller.get("caller_name") or caller_address or "caller")
                caller_id = index.add_entity(
                    "function",
                    f"{tool_name}:{caller_address or caller_label.lower()}",
                    caller_label,
                    attributes={"tool": tool_name, "address": caller_address, "source_path": str(path)},
                )
                index.add_relation(caller_id, "calls", function_id, attributes={"tool": tool_name, "callsite": caller.get("from_address")})
                if caller_address:
                    function_entities[(tool_name, caller_address)] = caller_id


def _ingest_class_manifest(
    index: AnalysisIndex,
    target_id: str,
    path: Path,
    tool_name: str,
    function_entities: dict[tuple[str, str], str],
) -> None:
    payload = _load_json_object(path)
    if not isinstance(payload, dict):
        return

    artifact_id = index.add_entity(
        "artifact",
        str(path),
        path.name,
        attributes={"path": str(path), "category": "json", "description": f"{tool_name} class manifest"},
    )
    tool_id = index.add_entity("tool", tool_name, tool_name, attributes={"kind": "class_recovery_tool"})

    for class_entry in payload.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        class_name = str(class_entry.get("name", "")).strip()
        if not class_name:
            continue
        class_key = f"{tool_name}:{class_name.lower()}"
        class_id = index.add_entity(
            "class",
            class_key,
            class_name,
            attributes={
                "tool": tool_name,
                "kind": class_entry.get("kind"),
                "mangled_name": class_entry.get("mangled_name"),
                "type_descriptor_rva": class_entry.get("type_descriptor_rva"),
                "estimated_base_size": class_entry.get("estimated_base_size"),
                "estimated_object_size": class_entry.get("estimated_object_size"),
                "estimated_tail_padding": class_entry.get("estimated_tail_padding"),
                "layout_strategy": class_entry.get("layout_strategy"),
                "layout_sources": class_entry.get("layout_sources"),
                "subobjects": class_entry.get("subobjects"),
                "constructor_phases": class_entry.get("constructor_phases"),
                "destructor_phases": class_entry.get("destructor_phases"),
                "class_call_edges": class_entry.get("class_call_edges"),
                "flag_domains": class_entry.get("flag_domains"),
                "symbol_recovery": class_entry.get("symbol_recovery"),
                "benchmark_capabilities": class_entry.get("benchmark_capabilities"),
                "recovery_capabilities": class_entry.get("recovery_capabilities"),
                "cross_tool_fusion": class_entry.get("cross_tool_fusion"),
                "source_path": str(path),
            },
        )
        index.add_relation(target_id, "contains_class_candidate", class_id, attributes={"tool": tool_name})
        index.add_relation(tool_id, "identified_class", class_id, attributes={"source_path": str(path)})
        index.add_relation(class_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})

        for base_name in class_entry.get("base_classes") or []:
            base_label = str(base_name).strip()
            if not base_label:
                continue
            base_id = index.add_entity("class", f"{tool_name}:{base_label.lower()}", base_label, attributes={"tool": tool_name})
            index.add_relation(class_id, "inherits_from", base_id, attributes={"tool": tool_name})

        for vtable in class_entry.get("vtables") or []:
            if not isinstance(vtable, dict):
                continue
            vtable_rva = _normalize_address(vtable.get("rva") or vtable.get("address"))
            if not vtable_rva:
                continue
            vtable_id = index.add_entity(
                "vtable",
                f"{tool_name}:{vtable_rva}",
                f"{class_name}::{vtable_rva}",
                attributes={
                    "tool": tool_name,
                    "rva": vtable.get("rva"),
                    "address": vtable.get("address"),
                    "method_count": vtable.get("method_count"),
                    "source_path": str(path),
                },
            )
            index.add_relation(class_id, "owns_vtable", vtable_id, attributes={"tool": tool_name})
            index.add_relation(vtable_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})

        for method in class_entry.get("methods") or []:
            if not isinstance(method, dict):
                continue
            address = _normalize_address(method.get("address") or method.get("rva"))
            method_name = str(method.get("name", "")).strip() or address or "virtual_method"
            display_name = str(method.get("display_name", "")).strip() or method_name
            label = str(method.get("qualified_name", "")).strip() or f"{class_name}::{display_name}"
            key = f"{tool_name}:{address or method_name.lower()}"
            method_id = index.add_entity(
                "function",
                key,
                label,
                attributes={
                    "tool": tool_name,
                    "address": address,
                    "slot": method.get("slot"),
                    "class_name": class_name,
                    "vtable_rva": method.get("vtable_rva"),
                    "method_name": display_name,
                    "method_kind": method.get("method_kind"),
                    "semantic_alias": method.get("semantic_alias"),
                    "name_inference_source": method.get("name_inference_source"),
                    "name_inference_evidence": method.get("name_inference_evidence"),
                    "original_vtable_name": method.get("original_vtable_name"),
                    "return_type": method.get("return_type"),
                    "params": method.get("params"),
                    "caller_count": method.get("caller_count"),
                    "caller_names": method.get("caller_names"),
                    "callsite_argument_hints": method.get("callsite_argument_hints"),
                    "result_hints": method.get("result_hints"),
                    "return_type_inference": method.get("return_type_inference"),
                    "is_thunk": method.get("is_thunk"),
                    "thunk_target": method.get("thunk_target"),
                    "thunk_kind": method.get("thunk_kind"),
                    "class_call_edges": method.get("class_call_edges"),
                    "flag_inferences": method.get("flag_inferences"),
                    "enum_flag_domain": method.get("enum_flag_domain"),
                    "namespace": "::".join(class_name.split("::")[:-1]) if "::" in class_name else None,
                    "source_path": str(path),
                },
            )
            index.add_relation(class_id, "declares_method_candidate", method_id, attributes={"tool": tool_name})
            index.add_relation(tool_id, "identified_function", method_id, attributes={"source_path": str(path)})
            index.add_relation(method_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})
            if address:
                function_entities[(tool_name, address)] = method_id

        for member in class_entry.get("members") or []:
            if not isinstance(member, dict):
                continue
            member_name = str(member.get("name") or "").strip()
            if not member_name:
                continue
            member_id = index.add_entity(
                "field",
                f"{tool_name}:{class_name.lower()}::{member_name.lower()}",
                f"{class_name}::{member_name}",
                attributes={
                    "tool": tool_name,
                    "class_name": class_name,
                    "field_name": member_name,
                    "type": member.get("type"),
                    "inference_reason": member.get("inference_reason"),
                    "evidence": member.get("evidence"),
                    "estimated_offset": member.get("estimated_offset"),
                    "estimated_size": member.get("estimated_size"),
                    "layout_index": member.get("layout_index"),
                    "layout_confidence": member.get("layout_confidence"),
                    "layout_basis": member.get("layout_basis"),
                    "storage_shape": member.get("storage_shape"),
                    "declaration_confidence": member.get("declaration_confidence"),
                    "primary_provenance": member.get("primary_provenance"),
                    "layout_provenance": member.get("layout_provenance"),
                    "source_path": str(path),
                },
            )
            index.add_relation(class_id, "declares_field_candidate", member_id, attributes={"tool": tool_name})
            index.add_relation(member_id, "originates_from_artifact", artifact_id, attributes={"tool": tool_name})


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
