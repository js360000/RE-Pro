from __future__ import annotations

import copy
import re
from pathlib import Path

from .api_semantics import infer_argument_hint_from_callee
from .utils import safe_slug

GENERIC_FUNCTION_PREFIXES = ("sub_", "fcn.", "fun_", "thunk_", "vf_")
CALLING_CONVENTION_TOKENS = {
    "__cdecl",
    "__stdcall",
    "__fastcall",
    "__thiscall",
    "__vectorcall",
    "__usercall",
    "__golang",
}
RECOVERY_CAPABILITIES = [
    "subobject_layout_recovery",
    "field_storage_shape_inference",
    "thunk_folding",
    "constructor_destructor_phase_modeling",
    "class_aware_callgraph_propagation",
    "enum_flag_inference",
    "symbol_rich_source_recovery",
    "fixture_benchmark_regression",
    "cross_tool_decomp_fusion",
    "llm_evidence_guided_reconstruction",
]


def write_pseudo_class_sources(
    output_dir: Path,
    recovered: dict[str, object],
    *,
    decompiled_entries: list[dict[str, object]] | None = None,
    max_classes: int = 64,
) -> list[tuple[str, str]]:
    generated: list[tuple[str, str]] = []
    enriched = enrich_recovered_classes(recovered, decompiled_entries=decompiled_entries)
    decompiled_map = _build_decompiled_map(decompiled_entries or [])
    classes = list(enriched.get("classes") or [])
    output_dir.mkdir(parents=True, exist_ok=True)
    for class_entry in classes[:max_classes]:
        name = str(class_entry.get("name", "")).strip()
        if not name:
            continue
        header_path, source_path = class_output_paths(output_dir, name)
        header_path.write_text(render_class_header(class_entry, decompiled_map), encoding="utf-8")
        source_path.write_text(render_class_source(class_entry, header_path.name, decompiled_map), encoding="utf-8")
        generated.append((f"msvc_rtti::{name}.hpp", str(header_path)))
        generated.append((f"msvc_rtti::{name}.cpp", str(source_path)))
    return generated


def enrich_recovered_classes(
    recovered: dict[str, object],
    *,
    decompiled_entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    payload = copy.deepcopy(recovered if isinstance(recovered, dict) else {})
    decompiled_map = _build_decompiled_map(decompiled_entries or [])
    class_hierarchy = _build_class_hierarchy(payload)
    for class_entry in payload.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        class_name = str(class_entry.get("name") or "").strip()
        if not class_name:
            continue
        _annotate_shared_vtable_targets(class_entry)
        for method in class_entry.get("methods") or []:
            if not isinstance(method, dict):
                continue
            decompiled_entry = decompiled_map.get(_normalize_address(method.get("address")))
            method.update(_infer_method_metadata(method, class_entry, decompiled_entry, class_hierarchy))
        _append_symbol_discovered_methods(class_entry, decompiled_map)
        _ensure_unique_method_display_names(class_entry)
        class_entry["members"] = _infer_class_members(class_entry, decompiled_map, class_hierarchy)
    class_size_hints = _build_class_size_hints(payload, decompiled_map)
    for class_entry in payload.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        _annotate_class_layout(class_entry, payload, class_size_hints)
    _annotate_recovery_features(payload, decompiled_map, class_hierarchy)
    return payload


def class_output_paths(output_dir: Path, class_name: str) -> tuple[Path, Path]:
    safe_name = safe_slug(class_name.replace("::", "__"))
    return output_dir / f"{safe_name}.hpp", output_dir / f"{safe_name}.cpp"


def render_class_header(
    class_entry: dict[str, object],
    decompiled_map: dict[str, dict[str, object]] | None = None,
) -> str:
    decompiled_map = decompiled_map or {}
    full_name = str(class_entry.get("name", "RecoveredClass"))
    namespace_parts = [part for part in full_name.split("::") if part]
    class_name = namespace_parts[-1] if namespace_parts else "RecoveredClass"
    namespaces = namespace_parts[:-1]
    base_classes = [str(value) for value in class_entry.get("base_classes", []) if value]
    methods = list(class_entry.get("methods") or [])
    members = list(class_entry.get("members") or [])
    kind = str(class_entry.get("kind", "class")) or "class"
    lines = [
        "#pragma once",
        "",
        "// Pseudo-source synthesized from MSVC RTTI / vftable recovery.",
        f"// Original RTTI name: {class_entry.get('mangled_name', '')}",
        f"// Type descriptor RVA: {class_entry.get('type_descriptor_rva', '')}",
    ]
    estimated_object_size = class_entry.get("estimated_object_size")
    if isinstance(estimated_object_size, int) and estimated_object_size > 0:
        lines.append(f"// Estimated object size: 0x{estimated_object_size:x}")
    subobject_count = len([entry for entry in class_entry.get("subobjects") or [] if isinstance(entry, dict)])
    if subobject_count:
        lines.append(f"// Recovered subobjects: {subobject_count}")
    layout_strategy = str(class_entry.get("layout_strategy") or "").strip()
    if layout_strategy:
        lines.append(f"// Layout strategy: {layout_strategy}")
    layout_sources = [str(value).strip() for value in class_entry.get("layout_sources") or [] if str(value).strip()]
    if layout_sources:
        lines.append(f"// Layout evidence: {', '.join(layout_sources)}")
    for namespace_name in namespaces:
        lines.extend(["", f"namespace {namespace_name} {{"])
    lines.extend(["", f"{kind} {class_name}" + _render_base_clause(base_classes) + " {", "public:"])
    if not methods:
        lines.append("    // No direct virtual methods were recovered from the vftable scan.")
    for method in methods:
        decompiled_entry = decompiled_map.get(_normalize_address(method.get("address")))
        prototype = _method_declaration(method, class_name, decompiled_entry)
        method_info = _resolved_method_info(method, class_name, decompiled_entry)
        if method_info["method_kind"] == "pure_virtual":
            prototype = f"{prototype} = 0"
        lines.append(
            f"    {prototype};"
            f" // {method.get('address')} slot {method.get('slot')} vtable {method.get('vtable_rva')}"
        )
    if members:
        lines.extend(["", "private:"])
        for member in members:
            declaration = _member_declaration(member)
            lines.append(f"    {declaration};{_member_comment(member)}")
    lines.append("};")
    for namespace_name in reversed(namespaces):
        lines.append(f"}} // namespace {namespace_name}")
    lines.append("")
    return "\n".join(lines)


def render_class_source(
    class_entry: dict[str, object],
    header_name: str,
    decompiled_map: dict[str, dict[str, object]] | None = None,
) -> str:
    decompiled_map = decompiled_map or {}
    full_name = str(class_entry.get("name", "RecoveredClass"))
    namespace_parts = [part for part in full_name.split("::") if part]
    class_name = namespace_parts[-1] if namespace_parts else "RecoveredClass"
    namespaces = namespace_parts[:-1]
    methods = list(class_entry.get("methods") or [])
    lines = [
        f'#include "{header_name}"',
        "",
        "// Pseudo-source synthesized from MSVC RTTI / vftable recovery.",
        "// When available, method bodies are adapted from Ghidra targeted decompilation output.",
    ]
    for namespace_name in namespaces:
        lines.extend(["", f"namespace {namespace_name} {{"])
    if not methods:
        lines.extend(["", f"// {class_name} had no directly recoverable virtual methods in the scanned vftables."])
    for method in methods:
        decompiled_entry = decompiled_map.get(_normalize_address(method.get("address")))
        method_info = _resolved_method_info(method, class_name, decompiled_entry)
        if method_info["method_kind"] == "pure_virtual":
            lines.extend(
                [
                    "",
                    f"// {class_name}::{method_info['display_name']} is declared pure virtual in the header.",
                    f"// Recovered slot {method.get('slot')} resolves to shared target {method.get('address')}.",
                ]
            )
            continue
        lines.extend(["", f"{_definition_signature(method, class_name, decompiled_entry)} {{"])
        lines.append(f"    // Recovered address: {method.get('address')}")
        lines.append(f"    // Slot: {method.get('slot')} from vtable {method.get('vtable_rva')}")
        ghidra_name = str((decompiled_entry or {}).get("name") or "").strip()
        ghidra_signature = str((decompiled_entry or {}).get("signature") or "").strip()
        if method.get("method_kind") in {"destructor", "scalar_deleting_destructor", "vector_deleting_destructor"}:
            lines.append(f"    // Inferred method role: {method.get('method_kind')}")
        if method.get("semantic_alias"):
            lines.append(f"    // Human-readable alias: {method.get('semantic_alias')}")
        if method.get("name_inference_source"):
            evidence = str(method.get("name_inference_evidence") or "").strip()
            suffix = f": {evidence}" if evidence else ""
            lines.append(f"    // Method name inferred from {method.get('name_inference_source')}{suffix}")
        if method.get("original_vtable_name"):
            lines.append(f"    // Original recovered vtable name: {method.get('original_vtable_name')}")
        if method.get("shared_vtable_target_count"):
            lines.append(
                "    // Shared vtable target: "
                f"{method.get('shared_vtable_target_count')} slot(s) -> {method.get('address')}"
            )
        if method.get("return_type_inference"):
            lines.append(f"    // Return type inferred from callsite usage: {method.get('return_type_inference')}")
        caller_count = int(method.get("caller_count") or 0)
        if caller_count:
            lines.append(f"    // Observed direct callers: {caller_count}")
        caller_names = [str(value) for value in method.get("caller_names") or [] if value]
        if caller_names:
            lines.append(f"    // Caller examples: {', '.join(caller_names[:6])}")
        if ghidra_name:
            lines.append(f"    // Decompiled from Ghidra function: {ghidra_name}")
        if ghidra_signature:
            lines.append(f"    // Original Ghidra signature: {ghidra_signature}")
        body = _method_body(decompiled_entry)
        if body:
            lines.extend(body.splitlines())
        else:
            lines.append("    // TODO: map this stub to decompiler output and rebuild the original body.")
        lines.append("}")
    for namespace_name in reversed(namespaces):
        lines.extend(["", f"}} // namespace {namespace_name}"])
    lines.append("")
    return "\n".join(lines)


def _method_declaration(
    method: dict[str, object],
    class_name: str,
    decompiled_entry: dict[str, object] | None,
) -> str:
    method_info = _resolved_method_info(method, class_name, decompiled_entry)
    prefix = "virtual " if method_info["is_virtual"] else ""
    params = _render_params(method_info["params"])
    return_type = str(method_info["return_type"]).strip()
    display_name = str(method_info["display_name"]).strip() or str(method.get("name") or "method").strip()
    if method_info["method_kind"] in {"constructor", "destructor"}:
        if params == "void":
            params = ""
        return f"{prefix}{display_name}({params})"
    return f"{prefix}{return_type or 'void'} {display_name}({params})"


def _definition_signature(
    method: dict[str, object],
    class_name: str,
    decompiled_entry: dict[str, object] | None,
) -> str:
    method_info = _resolved_method_info(method, class_name, decompiled_entry)
    params = _render_params(method_info["params"])
    display_name = str(method_info["display_name"]).strip() or str(method.get("name") or "method").strip()
    if method_info["method_kind"] in {"constructor", "destructor"}:
        if params == "void":
            params = ""
        return f"{class_name}::{display_name}({params})"
    return_type = str(method_info["return_type"]).strip() or "void"
    return f"{return_type} {class_name}::{display_name}({params})"


def _method_body(decompiled_entry: dict[str, object] | None) -> str:
    if not decompiled_entry or not decompiled_entry.get("decompile_success"):
        return ""
    decompiled_c = str(decompiled_entry.get("decompiled_c") or "").strip()
    if not decompiled_c:
        return ""
    start = decompiled_c.find("{")
    end = decompiled_c.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    body = decompiled_c[start + 1 : end].strip("\r\n")
    if not body.strip():
        return ""
    return "\n".join(f"    {line.rstrip()}" if line.strip() else "" for line in body.splitlines())


def _build_decompiled_map(entries: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        address = _normalize_address(entry.get("entry_point") or entry.get("requested_address"))
        if address:
            result[address] = entry
    return result


def _annotate_shared_vtable_targets(class_entry: dict[str, object]) -> None:
    methods = [method for method in class_entry.get("methods") or [] if isinstance(method, dict)]
    by_address: dict[str, list[dict[str, object]]] = {}
    for method in methods:
        address = _normalize_address(method.get("address"))
        if not address:
            continue
        by_address.setdefault(address, []).append(method)
    for address, address_methods in by_address.items():
        if len(address_methods) < 2:
            continue
        slots = [method.get("slot") for method in address_methods]
        for method in address_methods:
            method["shared_vtable_target_count"] = len(address_methods)
            method["shared_vtable_target_slots"] = slots
            if len(address_methods) >= 3 and _is_generic_function_name(str(method.get("name") or "")):
                method.setdefault("inferred_shared_target_kind", "pure_virtual")


def _append_symbol_discovered_methods(
    class_entry: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
) -> None:
    methods = [method for method in class_entry.get("methods") or [] if isinstance(method, dict)]
    seen_addresses = {_normalize_address(method.get("address")) for method in methods}
    class_name = str(class_entry.get("name") or "").strip()
    short_name = class_name.split("::")[-1]
    for address, decompiled_entry in decompiled_map.items():
        if not address or address in seen_addresses:
            continue
        if not _entry_belongs_to_class(decompiled_entry, class_name, short_name):
            continue
        metadata = _infer_method_metadata(
            {
                "name": str(decompiled_entry.get("name") or "").strip() or f"fn_{address[2:]}",
                "address": address,
                "slot": "symbol",
                "vtable_rva": "symbol",
            },
            class_entry,
            decompiled_entry,
            {},
        )
        synthetic = {
            "name": str(decompiled_entry.get("name") or "").strip() or metadata.get("display_name") or f"fn_{address[2:]}",
            "slot": "symbol",
            "address": address,
            "rva": "",
            "vtable_rva": "symbol",
            "source": "ghidra_class_symbol",
            **metadata,
        }
        methods.append(synthetic)
        seen_addresses.add(address)
    class_entry["methods"] = methods


def _ensure_unique_method_display_names(class_entry: dict[str, object]) -> None:
    methods = [method for method in class_entry.get("methods") or [] if isinstance(method, dict)]
    seen: dict[tuple[str, str], int] = {}
    for method in methods:
        display_name = str(method.get("display_name") or method.get("name") or "method").strip() or "method"
        params = _render_params(list(method.get("params") or []))
        key = (display_name, params)
        count = seen.get(key, 0)
        seen[key] = count + 1
        if count == 0:
            continue
        slot = method.get("slot")
        try:
            slot_suffix = str(int(slot))
        except (TypeError, ValueError):
            address = _normalize_address(method.get("address"))
            slot_suffix = address[2:] if address else str(count)
        method["display_name"] = f"{display_name}_slot_{slot_suffix}"
        method["qualified_name"] = f"{class_entry.get('name')}::{method['display_name']}"


def _normalize_address(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return f"0x{int(text, 16):x}"
    except ValueError:
        return ""


def _render_base_clause(base_classes: list[str]) -> str:
    if not base_classes:
        return ""
    return " : " + ", ".join(f"public {base_name}" for base_name in base_classes)


def _member_declaration(member: dict[str, object]) -> str:
    member_type = str(member.get("type") or "").strip() or "undefined"
    member_name = str(member.get("name") or "").strip() or "field_"
    return f"{member_type} {member_name}".strip()


def _member_comment(member: dict[str, object]) -> str:
    fragments: list[str] = []
    reason = str(member.get("inference_reason") or "").strip()
    if reason:
        fragments.append(f"inferred from {reason}")
    primary_provenance = member.get("primary_provenance")
    if isinstance(primary_provenance, dict):
        source_kind = str(primary_provenance.get("source_kind") or "").strip()
        source_function = str(primary_provenance.get("source_function") or "").strip()
        provenance_label = " ".join(piece for piece in (source_kind, source_function) if piece).strip()
        if provenance_label:
            fragments.append(f"via {provenance_label}")
    estimated_offset = member.get("estimated_offset")
    if isinstance(estimated_offset, int) and estimated_offset >= 0:
        fragments.append(f"approx +0x{estimated_offset:x}")
    estimated_size = member.get("estimated_size")
    if isinstance(estimated_size, int) and estimated_size > 0:
        fragments.append(f"size 0x{estimated_size:x}")
    confidence = str(member.get("layout_confidence") or "").strip()
    if confidence:
        fragments.append(f"layout {confidence}")
    if not fragments:
        return ""
    return " // " + ", ".join(fragments)


def _infer_method_metadata(
    method: dict[str, object],
    class_entry: dict[str, object],
    decompiled_entry: dict[str, object] | None,
    class_hierarchy: dict[str, set[str]] | None = None,
) -> dict[str, object]:
    full_class_name = str(class_entry.get("name") or "RecoveredClass").strip() or "RecoveredClass"
    class_name = full_class_name.split("::")[-1]
    explicit_name = str(method.get("name") or "").strip()
    decompiled_name = str((decompiled_entry or {}).get("name") or "").strip()
    namespace = str((decompiled_entry or {}).get("namespace") or "").strip()
    signature = str((decompiled_entry or {}).get("signature") or "").strip()
    parsed = _parse_signature(signature)
    candidate_name = _choose_candidate_method_name(explicit_name, decompiled_name, parsed["name"])
    method_kind = _infer_method_kind(candidate_name, class_name)
    if (
        not decompiled_entry
        and str(method.get("inferred_shared_target_kind") or "") == "pure_virtual"
        and _is_generic_function_name(candidate_name)
    ):
        method_kind = "pure_virtual"
    params = _normalize_params(
        _extract_parameter_entries(decompiled_entry, parsed["params"]),
        full_class_name,
        class_name,
    )
    params = _apply_callsite_hints_to_params(params, decompiled_entry, full_class_name, class_name)
    params = _apply_body_hints_to_params(params, decompiled_entry)
    params = _apply_method_name_hints_to_params(params, candidate_name)
    return_type = _normalize_return_type(str((decompiled_entry or {}).get("return_type") or parsed["return_type"]))
    return_type, return_type_inference = _apply_result_hints_to_return_type(return_type, decompiled_entry, class_hierarchy or {})
    return_type, body_return_inference = _apply_body_hints_to_return_type(
        return_type,
        decompiled_entry,
        method_kind,
        class_hierarchy or {},
    )
    name_inference = _infer_semantic_method_name(
        candidate_name,
        method,
        full_class_name,
        class_name,
        decompiled_entry,
        params,
        return_type,
        method_kind,
    )
    if name_inference:
        candidate_name = str(name_inference.get("name") or candidate_name)
        method_kind = _infer_method_kind(candidate_name, class_name)
        params = _apply_method_name_hints_to_params(params, candidate_name)
    display_name = _display_name_for_method(candidate_name, class_name, method_kind, method)
    semantic_alias = _semantic_alias_for_method(class_name, method_kind)
    caller_names = _extract_caller_names(decompiled_entry)
    callsite_argument_hints = _extract_callsite_argument_hints(decompiled_entry)
    if method_kind in {"constructor", "destructor"}:
        return_type = ""
    elif method_kind in {"scalar_deleting_destructor", "vector_deleting_destructor"}:
        return_type = "void"
        if not body_return_inference:
            body_return_inference = "deleting_destructor"
    return {
        "display_name": display_name,
        "qualified_name": f"{full_class_name}::{display_name}",
        "method_kind": method_kind,
        "semantic_alias": semantic_alias,
        "return_type": return_type,
        "params": params,
        "namespace": namespace,
        "ghidra_name": decompiled_name,
        "ghidra_signature": signature,
        "caller_count": int((decompiled_entry or {}).get("caller_count") or len((decompiled_entry or {}).get("callers") or [])),
        "caller_names": caller_names,
        "callsite_argument_hints": callsite_argument_hints,
        "result_hints": _extract_result_hints(decompiled_entry),
        "return_type_inference": body_return_inference or return_type_inference,
        "name_inference_source": (name_inference or {}).get("source"),
        "name_inference_evidence": (name_inference or {}).get("evidence"),
        "original_vtable_name": explicit_name if _is_generic_function_name(explicit_name) and display_name != explicit_name else None,
        "is_virtual": method_kind != "constructor",
        "inference_source": _inference_source(explicit_name, decompiled_name, parsed["name"]),
    }


def _choose_candidate_method_name(explicit_name: str, decompiled_name: str, signature_name: str) -> str:
    for candidate in (decompiled_name, signature_name):
        normalized = _normalize_qualified_function_name(candidate)
        if normalized and not _is_generic_function_name(normalized):
            return normalized
    return explicit_name or _normalize_qualified_function_name(signature_name) or decompiled_name or "method"


def _infer_semantic_method_name(
    candidate_name: str,
    method: dict[str, object],
    full_class_name: str,
    class_name: str,
    decompiled_entry: dict[str, object] | None,
    params: list[dict[str, str]],
    return_type: str,
    method_kind: str,
) -> dict[str, str] | None:
    if method_kind not in {"virtual_method", ""}:
        return None
    if not _is_generic_function_name(candidate_name):
        return None
    decompiled_c = str((decompiled_entry or {}).get("decompiled_c") or "")
    if not decompiled_c:
        return None

    returned_member = _extract_returned_member_name(decompiled_c)
    if returned_member:
        suffix = _member_name_to_method_suffix(returned_member)
        if suffix:
            return {
                "name": f"Get{suffix}",
                "source": "returned_member",
                "evidence": f"return of this->{returned_member}",
            }

    c_str_member = _extract_c_str_member_name(decompiled_c)
    if c_str_member:
        suffix = _member_name_to_method_suffix(c_str_member)
        if suffix:
            return {
                "name": f"Get{suffix}",
                "source": "string_member_c_str",
                "evidence": f"c_str(&this->{c_str_member})",
            }

    assigned_member = _extract_assigned_member_name(decompiled_c)
    if assigned_member and params:
        suffix = _member_name_to_method_suffix(assigned_member)
        if suffix:
            return {
                "name": f"Set{suffix}",
                "source": "member_assignment",
                "evidence": f"write to this->{assigned_member}",
            }

    bool_member = _extract_boolean_member_name(decompiled_c)
    if bool_member and _normalized_type_is_bool(return_type):
        suffix = _member_name_to_method_suffix(bool_member)
        if suffix:
            return {
                "name": f"Is{suffix}",
                "source": "boolean_member_return",
                "evidence": f"boolean use of this->{bool_member}",
            }

    if _body_calls_any(decompiled_entry, ("MessageBoxA", "MessageBoxW", "TaskDialog", "DialogBox")):
        return {"name": "ShowAlert", "source": "ui_callee", "evidence": "message-box API call"}

    if _class_or_body_suggests_logger(full_class_name, decompiled_entry) and _has_string_like_param(params):
        return {"name": "Log", "source": "logger_callee", "evidence": "logger class/API with string parameter"}

    if _body_calls_any(decompiled_entry, ("OutputDebugStringA", "OutputDebugStringW", "puts", "printf", "fprintf", "std::cout")):
        return {"name": "WriteMessage", "source": "text_output_callee", "evidence": "text-output API call"}

    if _body_calls_any(decompiled_entry, ("CreateFileA", "CreateFileW", "fopen", "ifstream", "std::filesystem")) and _has_param_named(params, "path"):
        return {"name": "OpenPath", "source": "file_api_callee", "evidence": "file API call with path parameter"}

    return None


def _extract_returned_member_name(decompiled_c: str) -> str:
    patterns = [
        r"return\s+\([^)]*\)\s*&this->([A-Za-z_]\w*)\s*;",
        r"return\s+&this->([A-Za-z_]\w*)\s*;",
        r"return\s+this->([A-Za-z_]\w*)\s*;",
    ]
    for pattern in patterns:
        match = re.search(pattern, decompiled_c)
        if match is not None:
            member_name = match.group(1)
            if _is_nameable_member(member_name):
                return member_name
    return ""


def _extract_c_str_member_name(decompiled_c: str) -> str:
    match = re.search(r"::c_str(?:<[\s\S]*?>)?\s*\(\s*&this->([A-Za-z_]\w*)", decompiled_c)
    if match is None:
        return ""
    member_name = match.group(1)
    return member_name if _is_nameable_member(member_name) else ""


def _extract_assigned_member_name(decompiled_c: str) -> str:
    patterns = [
        r"this->([A-Za-z_]\w*)\s*=\s*[^;\n]+",
        r"::operator=\s*\(\s*&this->([A-Za-z_]\w*)\s*,",
    ]
    for pattern in patterns:
        match = re.search(pattern, decompiled_c)
        if match is not None:
            member_name = match.group(1)
            if _is_nameable_member(member_name):
                return member_name
    return ""


def _extract_boolean_member_name(decompiled_c: str) -> str:
    patterns = [
        r"return\s+\(?this->([A-Za-z_]\w*)\s*!=\s*0\)?\s*;",
        r"return\s+\(?this->([A-Za-z_]\w*)\s*==\s*0\)?\s*;",
        r"return\s+\(?bool\)?\s*this->([A-Za-z_]\w*)\s*;",
    ]
    for pattern in patterns:
        match = re.search(pattern, decompiled_c)
        if match is not None:
            member_name = match.group(1)
            if _is_nameable_member(member_name):
                return member_name
    return ""


def _is_nameable_member(member_name: str) -> bool:
    lowered = str(member_name or "").strip().lower()
    return bool(lowered and lowered not in {"vftable", "vfptr", "_padding_"} and "vftable" not in lowered)


def _member_name_to_method_suffix(member_name: str) -> str:
    name = str(member_name or "").strip()
    name = re.sub(r"^(m_|m)(?=[A-Z_])", "", name)
    name = name.strip("_")
    if not name:
        return ""
    suffix = ""
    lowered = name.lower()
    if lowered.endswith("_w"):
        name = name[:-2]
        suffix = "W"
    elif lowered.endswith("_a"):
        name = name[:-2]
        suffix = "A"
    tokens = [token for token in re.split(r"[_\s]+", name) if token]
    if len(tokens) <= 1:
        tokens = _tokenize_identifier(name)
    rendered = "".join(_pascal_token(token) for token in tokens)
    return rendered + suffix


def _pascal_token(token: str) -> str:
    text = str(token or "").strip("_")
    if not text:
        return ""
    if len(text) == 1:
        return text.upper()
    if text.isupper():
        return text
    return text[:1].upper() + text[1:]


def _normalized_type_is_bool(return_type: str) -> bool:
    return str(return_type or "").strip().lower() in {"bool", "boolean", "_bool"}


def _body_calls_any(decompiled_entry: dict[str, object] | None, names: tuple[str, ...]) -> bool:
    body = str((decompiled_entry or {}).get("decompiled_c") or "").lower()
    lowered_names = [name.lower() for name in names]
    if any(name in body for name in lowered_names):
        return True
    for callee in (decompiled_entry or {}).get("callees") or []:
        if not isinstance(callee, dict):
            continue
        haystack = " ".join(str(callee.get(key) or "") for key in ("name", "signature", "namespace")).lower()
        if any(name in haystack for name in lowered_names):
            return True
    return False


def _class_or_body_suggests_logger(full_class_name: str, decompiled_entry: dict[str, object] | None) -> bool:
    class_lower = str(full_class_name or "").lower()
    if any(keyword in class_lower for keyword in ("logger", "log", "trace", "console")):
        return True
    return _body_calls_any(decompiled_entry, ("OutputDebugStringA", "OutputDebugStringW", "puts", "printf", "fprintf", "log"))


def _has_string_like_param(params: list[dict[str, str]]) -> bool:
    for parameter in params:
        text = f"{parameter.get('type', '')} {parameter.get('name', '')}".lower()
        if any(keyword in text for keyword in ("char", "string", "text", "message", "name", "path")):
            return True
    return False


def _has_param_named(params: list[dict[str, str]], name: str) -> bool:
    wanted = str(name or "").lower()
    return any(str(parameter.get("name") or "").lower() == wanted for parameter in params)


def _normalize_qualified_function_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("(", 1)[0].strip()
    if "scalar_deleting_destructor" in text:
        return "scalar_deleting_destructor"
    if "vector_deleting_destructor" in text:
        return "vector_deleting_destructor"
    text = text.strip("`' ")
    if "::" in text:
        return text.split("::")[-1].strip()
    return text


def _infer_method_kind(candidate_name: str, class_name: str) -> str:
    lowered = candidate_name.lower()
    class_lower = class_name.lower()
    if candidate_name == class_name:
        return "constructor"
    if candidate_name == f"~{class_name}":
        return "destructor"
    if "scalar deleting destructor" in lowered or "scalar_deleting_destructor" in lowered:
        return "scalar_deleting_destructor"
    if "vector deleting destructor" in lowered or "vector_deleting_destructor" in lowered:
        return "vector_deleting_destructor"
    if lowered == "_purecall" or lowered == "__purecall" or "purecall" == lowered:
        return "pure_virtual"
    if lowered in {f"~{class_lower}", "__destructor", "destructor"} or lowered.endswith("::~" + class_lower):
        return "destructor"
    return "virtual_method"


def _display_name_for_method(
    candidate_name: str,
    class_name: str,
    method_kind: str,
    method: dict[str, object] | None = None,
) -> str:
    if method_kind == "constructor":
        return class_name
    if method_kind == "destructor":
        return f"~{class_name}"
    if method_kind == "scalar_deleting_destructor":
        return "__scalar_deleting_destructor"
    if method_kind == "vector_deleting_destructor":
        return "__vector_deleting_destructor"
    if method_kind == "pure_virtual":
        slot_value = (method or {}).get("slot")
        try:
            slot_index = int(slot_value)
        except (TypeError, ValueError):
            slot_index = -1
        if slot_index >= 0:
            return f"__pure_virtual_slot_{slot_index}"
        address = _normalize_hex((method or {}).get("address"))
        if address:
            return f"__pure_virtual_slot_{address[2:]}"
        return "__pure_virtual_slot"
    return candidate_name or "method"


def _semantic_alias_for_method(class_name: str, method_kind: str) -> str:
    if method_kind in {"destructor", "scalar_deleting_destructor", "vector_deleting_destructor"}:
        return f"~{class_name}"
    if method_kind == "constructor":
        return class_name
    if method_kind == "pure_virtual":
        return "pure virtual"
    return ""


def _inference_source(explicit_name: str, decompiled_name: str, signature_name: str) -> str:
    if decompiled_name and not _is_generic_function_name(decompiled_name):
        return "ghidra_name"
    if signature_name and not _is_generic_function_name(signature_name):
        return "ghidra_signature"
    if explicit_name:
        return "rtti_vtable"
    return "heuristic"


def _parse_signature(signature: str) -> dict[str, object]:
    text = signature.strip().rstrip(";")
    if "(" not in text or ")" not in text:
        return {"return_type": "void", "name": "", "params": []}
    before_paren, after_paren = text.split("(", 1)
    params_text = after_paren.rsplit(")", 1)[0].strip()
    pieces = before_paren.strip().split()
    if not pieces:
        return {"return_type": "void", "name": "", "params": _split_params(params_text)}
    name = pieces[-1]
    return_tokens = [token for token in pieces[:-1] if token not in CALLING_CONVENTION_TOKENS]
    return_type = " ".join(return_tokens).strip() or "void"
    return {"return_type": return_type, "name": name, "params": _split_params(params_text)}


def _split_params(params_text: str) -> list[str]:
    text = params_text.strip()
    if not text or text == "void":
        return []
    return [piece.strip() for piece in text.split(",") if piece.strip()]


def _normalize_params(params: list[dict[str, str]], full_class_name: str, class_name: str) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for index, parameter in enumerate(params, start=1):
        parameter = {
            "type": str(parameter.get("type") or "").strip() or "undefined",
            "name": str(parameter.get("name") or "").strip() or f"arg{index}",
        }
        if _is_this_param(parameter, full_class_name, class_name):
            continue
        normalized.append(parameter)
    return normalized


def _split_param(piece: str, index: int) -> dict[str, str]:
    text = piece.strip()
    pieces = text.rsplit(" ", 1)
    if len(pieces) == 2:
        param_type = pieces[0].strip()
        raw_name = pieces[1].strip()
        pointer_prefix = ""
        while raw_name.startswith(("*", "&")):
            pointer_prefix += raw_name[0]
            raw_name = raw_name[1:]
        param_name = raw_name.strip()
        if pointer_prefix:
            param_type = f"{param_type} {pointer_prefix}".strip()
        if re.match(r"^[A-Za-z_]\w*$", param_name) and param_type:
            return {"type": param_type, "name": param_name}
    return {"type": text, "name": f"arg{index}"}


def _is_this_param(parameter: dict[str, str], full_class_name: str, class_name: str) -> bool:
    name = str(parameter.get("name") or "").strip().lower()
    param_type = str(parameter.get("type") or "").strip().lower()
    full_class_lower = full_class_name.lower()
    class_lower = class_name.lower()
    if name == "this":
        return True
    if full_class_lower in param_type and name in {"this", f"{class_lower}_this"}:
        return True
    if class_lower in param_type and name == "this":
        return True
    return False


def _normalize_return_type(value: str) -> str:
    text = str(value or "").strip()
    return text or "void"


def _resolved_method_info(
    method: dict[str, object],
    class_name: str,
    decompiled_entry: dict[str, object] | None,
) -> dict[str, object]:
    if all(
        key in method
        for key in ("display_name", "method_kind", "return_type", "params", "is_virtual")
    ):
        return {
            "display_name": str(method.get("display_name") or method.get("name") or "method"),
            "method_kind": str(method.get("method_kind") or "virtual_method"),
            "return_type": str(method.get("return_type") or ""),
            "params": list(method.get("params") or []),
            "is_virtual": bool(method.get("is_virtual", True)),
        }
    return _infer_method_metadata(method, {"name": class_name}, decompiled_entry)


def _render_params(params: list[dict[str, str]]) -> str:
    if not params:
        return "void"
    rendered = []
    for parameter in params:
        param_type = str(parameter.get("type") or "").strip() or "undefined"
        param_name = str(parameter.get("name") or "").strip()
        rendered.append(f"{param_type} {param_name}".strip())
    return ", ".join(rendered) or "void"


def _is_generic_function_name(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    simple = lowered.split("::")[-1]
    return simple.startswith(GENERIC_FUNCTION_PREFIXES)


def _apply_callsite_hints_to_params(
    params: list[dict[str, str]],
    decompiled_entry: dict[str, object] | None,
    full_class_name: str,
    class_name: str,
) -> list[dict[str, str]]:
    if not params:
        return params
    hints_by_position = _collect_callsite_hints_by_position(decompiled_entry, full_class_name, class_name)
    if not hints_by_position:
        return params
    updated: list[dict[str, str]] = []
    for index, parameter in enumerate(params):
        hint = hints_by_position.get(index)
        if hint is None:
            updated.append(parameter)
            continue
        current_name = str(parameter.get("name") or "").strip()
        current_type = str(parameter.get("type") or "").strip()
        if _is_generic_param_name(current_name) and hint.get("name_hint"):
            parameter = {**parameter, "name": str(hint["name_hint"])}
        if _is_generic_param_type(current_type) and hint.get("type_hint"):
            parameter = {**parameter, "type": str(hint["type_hint"])}
        updated.append(parameter)
    return updated


def _apply_body_hints_to_params(
    params: list[dict[str, str]],
    decompiled_entry: dict[str, object] | None,
) -> list[dict[str, str]]:
    if not params or not isinstance(decompiled_entry, dict):
        return params
    body_hints = _infer_body_parameter_hints(decompiled_entry)
    if not body_hints:
        return params
    updated: list[dict[str, str]] = []
    for parameter in params:
        current_name = str(parameter.get("name") or "").strip()
        hint = body_hints.get(current_name)
        if hint is None:
            updated.append(parameter)
            continue
        replacement = dict(parameter)
        if _is_generic_param_name(current_name) and hint.get("name_hint"):
            replacement["name"] = str(hint["name_hint"])
        current_type = str(parameter.get("type") or "").strip()
        hinted_type = str(hint.get("type_hint") or "").strip()
        if hinted_type and (_is_generic_param_type(current_type) or _is_more_specific_param_type(current_type, hinted_type)):
            replacement["type"] = hinted_type
        updated.append(replacement)
    return updated


def _apply_method_name_hints_to_params(
    params: list[dict[str, str]],
    method_name: str,
) -> list[dict[str, str]]:
    if not params:
        return params
    param_hints = _infer_method_name_param_hints(method_name, params)
    if not param_hints:
        return params
    updated: list[dict[str, str]] = []
    for index, parameter in enumerate(params):
        hint = param_hints.get(index)
        if hint is None:
            updated.append(parameter)
            continue
        replacement = dict(parameter)
        current_name = str(parameter.get("name") or "").strip()
        current_type = str(parameter.get("type") or "").strip()
        hinted_name = str(hint.get("name_hint") or "").strip()
        hinted_type = str(hint.get("type_hint") or "").strip()
        if hinted_name and (_is_generic_param_name(current_name) or _is_weaker_param_name(current_name, hinted_name)):
            replacement["name"] = hinted_name
        if hinted_type and (_is_generic_param_type(current_type) or _is_more_specific_param_type(current_type, hinted_type)):
            replacement["type"] = hinted_type
        updated.append(replacement)
    return updated


def _collect_callsite_hints_by_position(
    decompiled_entry: dict[str, object] | None,
    full_class_name: str,
    class_name: str,
) -> dict[int, dict[str, str]]:
    raw_hints = _extract_callsite_argument_hints(decompiled_entry)
    if not raw_hints:
        return {}
    has_this = _entry_has_this_param(decompiled_entry, full_class_name, class_name)
    hints_by_position: dict[int, list[dict[str, str]]] = {}
    for hint in raw_hints:
        try:
            position = int(hint.get("position"))
        except (TypeError, ValueError):
            continue
        if has_this:
            position -= 1
        if position < 0:
            continue
        hints_by_position.setdefault(position, []).append(hint)
    aggregated: dict[int, dict[str, str]] = {}
    for position, hints in hints_by_position.items():
        name_hint = _most_common_hint_value(hints, "name_hint")
        type_hint = _most_common_hint_value(hints, "type_hint")
        if name_hint or type_hint:
            aggregated[position] = {"name_hint": name_hint, "type_hint": type_hint}
    return aggregated


def _extract_callsite_argument_hints(decompiled_entry: dict[str, object] | None) -> list[dict[str, object]]:
    hints: list[dict[str, object]] = []
    for hint in (decompiled_entry or {}).get("callsite_argument_hints") or []:
        if isinstance(hint, dict):
            hints.append(hint)
    for caller in (decompiled_entry or {}).get("callers") or []:
        if not isinstance(caller, dict):
            continue
        for hint in caller.get("argument_hints") or []:
            if isinstance(hint, dict):
                hints.append(hint)
    return hints


def _extract_result_hints(decompiled_entry: dict[str, object] | None) -> list[dict[str, object]]:
    hints: list[dict[str, object]] = []
    for hint in (decompiled_entry or {}).get("result_hints") or []:
        if isinstance(hint, dict):
            hints.append(hint)
    for caller in (decompiled_entry or {}).get("callers") or []:
        if not isinstance(caller, dict):
            continue
        hint = caller.get("result_hint")
        if isinstance(hint, dict):
            hints.append(hint)
    return hints


def _infer_body_parameter_hints(decompiled_entry: dict[str, object]) -> dict[str, dict[str, str]]:
    decompiled_c = str(decompiled_entry.get("decompiled_c") or "")
    if not decompiled_c:
        return {}
    parameter_entries = _extract_parameter_entries(decompiled_entry, [])
    if not parameter_entries:
        return {}
    parameter_names = [str(entry.get("name") or "").strip() for entry in parameter_entries if str(entry.get("name") or "").strip()]
    if not parameter_names:
        return {}
    hints: dict[str, list[dict[str, str]]] = {}
    for callee_name, arguments in _iter_body_call_arguments(decompiled_c):
        for position, argument in enumerate(arguments):
            for parameter_name in parameter_names:
                if not _argument_mentions_parameter(argument, parameter_name):
                    continue
                inferred = infer_argument_hint_from_callee(callee_name, position)
                if inferred is None:
                    continue
                hints.setdefault(parameter_name, []).append(inferred)
    aggregated: dict[str, dict[str, str]] = {}
    for parameter_name, parameter_hints in hints.items():
        name_hint = _most_common_hint_value(parameter_hints, "name_hint")
        type_hint = _most_common_hint_value(parameter_hints, "type_hint")
        reason = _most_common_hint_value(parameter_hints, "reason")
        if name_hint or type_hint:
            aggregated[parameter_name] = {"name_hint": name_hint, "type_hint": type_hint, "reason": reason}
    return aggregated


def _infer_method_name_param_hints(
    method_name: str,
    params: list[dict[str, str]],
) -> dict[int, dict[str, str]]:
    normalized_name = str(method_name or "").strip()
    if not normalized_name or not params:
        return {}
    tokens = _tokenize_identifier(normalized_name)
    if not tokens:
        return {}
    hints: dict[int, dict[str, str]] = {}
    if len(params) == 1:
        current_type = str(params[0].get("type") or "").strip()
        hinted_type = _guess_string_param_type(current_type, tokens)
        if "path" in tokens:
            hints[0] = {"name_hint": "path", "type_hint": hinted_type}
        elif "name" in tokens:
            hints[0] = {"name_hint": "name", "type_hint": hinted_type}
        elif "title" in tokens:
            hints[0] = {"name_hint": "title", "type_hint": hinted_type}
        elif "message" in tokens or "alert" in tokens or "text" in tokens:
            hints[0] = {"name_hint": "message", "type_hint": hinted_type}
    elif len(params) >= 2 and tokens[0] in {"show", "display"}:
        first_type = _guess_string_param_type(str(params[0].get("type") or "").strip(), tokens)
        second_type = _guess_string_param_type(str(params[1].get("type") or "").strip(), tokens)
        hints[0] = {"name_hint": "title", "type_hint": first_type}
        hints[1] = {"name_hint": "message", "type_hint": second_type}
    return hints


def _tokenize_identifier(value: str) -> list[str]:
    text = str(value or "").replace("::", "_")
    pieces = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", text)
    tokens = [piece.lower() for piece in pieces if piece]
    if not tokens and text:
        tokens = [text.lower()]
    return tokens


def _guess_string_param_type(current_type: str, tokens: list[str]) -> str:
    lowered_type = str(current_type or "").strip().lower()
    if "wchar_t" in lowered_type or lowered_type.endswith("w *") or "wide" in tokens or tokens[-1:] == ["w"]:
        return "const wchar_t *"
    return "const char *"


def _iter_body_call_arguments(decompiled_c: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    for raw_line in decompiled_c.splitlines():
        line = raw_line.strip()
        if not line or "(" not in line or ")" not in line:
            continue
        if line.startswith(("if ", "while ", "switch ", "for ", "return ")):
            continue
        callee, args = _parse_call_line(line)
        if callee and args is not None:
            calls.append((callee, args))
    return calls


def _parse_call_line(line: str) -> tuple[str, list[str] | None]:
    open_index = line.find("(")
    close_index = line.rfind(")")
    if open_index <= 0 or close_index <= open_index:
        return "", None
    prefix = line[:open_index].strip()
    if not prefix:
        return "", None
    callee = prefix.split()[-1].strip()
    if callee.startswith("*"):
        callee = callee.lstrip("*")
    if not callee:
        return "", None
    arguments = _split_call_arguments(line[open_index + 1 : close_index].strip())
    return callee, arguments


def _split_call_arguments(arguments_text: str) -> list[str]:
    if not arguments_text:
        return []
    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    for character in arguments_text:
        if character == "," and depth == 0:
            piece = "".join(current).strip()
            if piece:
                arguments.append(piece)
            current = []
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        current.append(character)
    tail = "".join(current).strip()
    if tail:
        arguments.append(tail)
    return arguments


def _argument_mentions_parameter(argument: str, parameter_name: str) -> bool:
    pattern = r"\b%s\b" % re.escape(parameter_name)
    return re.search(pattern, argument) is not None


def _entry_has_this_param(decompiled_entry: dict[str, object] | None, full_class_name: str, class_name: str) -> bool:
    parameter_entries = _extract_parameter_entries(decompiled_entry, [])
    if not parameter_entries:
        return False
    return _is_this_param(parameter_entries[0], full_class_name, class_name)


def _most_common_hint_value(hints: list[dict[str, object]], key: str) -> str:
    counts: dict[str, int] = {}
    for hint in hints:
        value = str(hint.get(key) or "").strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _is_more_specific_param_type(current_type: str, hinted_type: str) -> bool:
    current = str(current_type or "").strip().lower()
    hinted = str(hinted_type or "").strip().lower()
    if not current or not hinted or current == hinted:
        return False
    if current == "char *" and hinted == "const char *":
        return True
    if current == "wchar_t *" and hinted == "const wchar_t *":
        return True
    return False


def _is_generic_param_name(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    return bool(
        text in {"arg", "param", "parameter"}
        or re.match(r"^(arg|param|parameter)_?\d+$", text)
        or re.match(r"^p\d+$", text)
    )


def _is_weaker_param_name(current_name: str, hinted_name: str) -> bool:
    current = str(current_name or "").strip().lower()
    hinted = str(hinted_name or "").strip().lower()
    if not current or not hinted or current == hinted:
        return False
    weak_names = {"value", "text", "message", "other"}
    specific_names = {"name", "path", "title"}
    return current in weak_names and hinted in specific_names


def _is_generic_param_type(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    return text in {"undefined", "undefined4", "undefined8", "int", "longlong", "ulonglong", "void *"}


def _apply_result_hints_to_return_type(
    current_return_type: str,
    decompiled_entry: dict[str, object] | None,
    class_hierarchy: dict[str, set[str]],
) -> tuple[str, str]:
    normalized = _normalize_return_type(current_return_type)
    hints = _extract_result_hints(decompiled_entry)
    if not hints:
        return normalized, ""
    type_hint = _most_common_hint_value(hints, "type_hint")
    reason = _most_common_hint_value(hints, "reason")
    if not type_hint:
        return normalized, ""
    if not _is_generic_return_type(normalized) and not _is_more_specific_return_type(normalized, type_hint, class_hierarchy):
        return normalized, ""
    return type_hint, reason or "callsite_result_usage"


def _apply_body_hints_to_return_type(
    current_return_type: str,
    decompiled_entry: dict[str, object] | None,
    method_kind: str,
    class_hierarchy: dict[str, set[str]],
) -> tuple[str, str]:
    normalized = _normalize_return_type(current_return_type)
    if method_kind in {"scalar_deleting_destructor", "vector_deleting_destructor"}:
        return "void", "deleting_destructor"
    decompiled_c = str((decompiled_entry or {}).get("decompiled_c") or "")
    if not decompiled_c:
        return normalized, ""
    if normalized == "char *" and "::c_str" in decompiled_c:
        return "const char *", "string_c_str_return"
    if normalized == "wchar_t *" and "::c_str" in decompiled_c:
        return "const wchar_t *", "string_c_str_return"
    promoted_class = _infer_concrete_return_class_from_body(normalized, decompiled_c, class_hierarchy)
    if promoted_class:
        return promoted_class, "returned_member_matches_concrete_class"
    return normalized, ""


def _is_generic_return_type(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    return text in {"undefined", "undefined4", "undefined8", "int", "longlong", "ulonglong", "void *"}


def _is_more_specific_return_type(
    current_type: str,
    hinted_type: str,
    class_hierarchy: dict[str, set[str]],
) -> bool:
    current = str(current_type or "").strip()
    hinted = str(hinted_type or "").strip()
    if not current or not hinted or current == hinted:
        return False
    if _is_generic_return_type(current):
        return True
    if current == "char *" and hinted == "const char *":
        return True
    if current == "wchar_t *" and hinted == "const wchar_t *":
        return True
    current_class = _pointer_target_type(current)
    hinted_class = _pointer_target_type(hinted)
    if not current_class or not hinted_class or current_class == hinted_class:
        return False
    hinted_bases = class_hierarchy.get(hinted_class, set())
    return any(_class_names_match(current_class, base_name) for base_name in hinted_bases)


def _pointer_target_type(value: str) -> str:
    text = str(value or "").strip()
    if not text.endswith("*"):
        return ""
    base = text[:-1].strip()
    if base.startswith("const "):
        base = base[6:].strip()
    return base


def _build_class_hierarchy(recovered: dict[str, object]) -> dict[str, set[str]]:
    hierarchy: dict[str, set[str]] = {}
    for class_entry in recovered.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        class_name = str(class_entry.get("name") or "").strip()
        if not class_name:
            continue
        hierarchy.setdefault(class_name, set())
        for base_name in class_entry.get("base_classes") or []:
            base = str(base_name or "").strip()
            if base:
                hierarchy[class_name].add(base)
    changed = True
    while changed:
        changed = False
        for class_name, bases in list(hierarchy.items()):
            expanded = set(bases)
            for base in list(bases):
                expanded.update(hierarchy.get(base, set()))
            if expanded != bases:
                hierarchy[class_name] = expanded
                changed = True
    return hierarchy


def _infer_class_members(
    class_entry: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
    class_hierarchy: dict[str, set[str]],
) -> list[dict[str, object]]:
    evidence_by_name: dict[str, list[dict[str, object]]] = {}
    for method, decompiled_entry in _iter_class_related_decompiled_entries(class_entry, decompiled_map):
        for evidence in _infer_member_evidence(method, decompiled_entry, class_hierarchy):
            member_name = str(evidence.get("name") or "").strip()
            if not member_name:
                continue
            evidence_by_name.setdefault(member_name, []).append(evidence)
    ordered_names = _order_member_names(evidence_by_name)
    members: list[dict[str, object]] = []
    for member_name in ordered_names:
        evidences = evidence_by_name.get(member_name) or []
        member_type = _choose_member_type(evidences)
        if not member_type:
            continue
        primary_provenance = _serialize_member_provenance(_best_member_evidence(evidences))
        layout_provenance = _serialize_member_provenance_list(evidences)
        members.append(
            {
                "name": member_name,
                "type": member_type,
                "inference_reason": _most_common_hint_value(evidences, "reason"),
                "evidence": _most_common_hint_value(evidences, "evidence"),
                "primary_provenance": primary_provenance,
                "layout_provenance": layout_provenance,
            }
        )
    return members


def _annotate_recovery_features(
    payload: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
    class_hierarchy: dict[str, set[str]],
) -> None:
    payload["recovery_capabilities"] = list(RECOVERY_CAPABILITIES)
    payload["cross_tool_fusion"] = {
        "strategy": "address_keyed_function_and_field_correlation",
        "primary_decompiler": "ghidra",
        "secondary_tools": ["rizin", "radare2"],
    }
    classes = [entry for entry in payload.get("classes") or [] if isinstance(entry, dict)]
    class_size_hints = {
        str(entry.get("name") or "").strip(): int(entry.get("estimated_object_size") or 0)
        for entry in classes
        if str(entry.get("name") or "").strip() and int(entry.get("estimated_object_size") or 0) > 0
    }
    for class_entry in classes:
        class_name = str(class_entry.get("name") or "").strip()
        if not class_name:
            continue
        related_entries = _iter_class_related_decompiled_entries(class_entry, decompiled_map)
        _annotate_member_shapes(class_entry)
        _annotate_method_features(class_entry, related_entries, class_hierarchy)
        class_entry["subobjects"] = _infer_subobjects(class_entry, class_size_hints)
        class_entry["constructor_phases"] = _infer_lifecycle_phases(related_entries, phase="constructor")
        class_entry["destructor_phases"] = _infer_lifecycle_phases(related_entries, phase="destructor")
        class_entry["class_call_edges"] = _infer_class_call_edges(related_entries)
        class_entry["flag_domains"] = _infer_class_flag_domains(class_entry)
        class_entry["symbol_recovery"] = _infer_symbol_recovery(class_entry)
        class_entry["benchmark_capabilities"] = _benchmark_capabilities_for_class(class_entry)
        class_entry["cross_tool_fusion"] = {
            "strategy": "address_keyed_index_correlation",
            "method_addresses": [
                _normalize_address(method.get("address"))
                for method in class_entry.get("methods") or []
                if isinstance(method, dict) and _normalize_address(method.get("address"))
            ],
        }
        class_entry["recovery_capabilities"] = list(RECOVERY_CAPABILITIES)


def _annotate_member_shapes(class_entry: dict[str, object]) -> None:
    for member in class_entry.get("members") or []:
        if not isinstance(member, dict):
            continue
        member_type = str(member.get("type") or "").strip()
        member["storage_shape"] = _storage_shape_for_type(member_type)
        member["declaration_confidence"] = _declaration_confidence(member)


def _storage_shape_for_type(member_type: str) -> str:
    text = str(member_type or "").strip()
    lowered = text.lower()
    if text == "std::string":
        return "std_string_object"
    if text == "std::wstring":
        return "std_wstring_object"
    if text.endswith("*"):
        return "pointer"
    if lowered == "bool":
        return "bool_scalar"
    if lowered in {"char", "unsigned char", "byte"}:
        return "byte_scalar"
    if lowered in {"short", "unsigned short", "wchar_t"}:
        return "word_scalar"
    if lowered in {"int", "uint", "unsigned int", "long", "unsigned long", "float"}:
        return "dword_scalar"
    if lowered in {"long long", "unsigned long long", "undefined8", "ulonglong", "longlong", "double"}:
        return "qword_scalar"
    if "::" in text or text[:1].isupper():
        return "class_object"
    return "unknown"


def _declaration_confidence(member: dict[str, object]) -> str:
    storage_shape = str(member.get("storage_shape") or "").strip()
    provenance = [entry for entry in member.get("layout_provenance") or [] if isinstance(entry, dict)]
    if storage_shape in {"std_string_object", "std_wstring_object", "class_object"} and provenance:
        return "high"
    if storage_shape != "unknown":
        return "medium"
    return "low"


def _annotate_method_features(
    class_entry: dict[str, object],
    related_entries: list[tuple[dict[str, object], dict[str, object]]],
    class_hierarchy: dict[str, set[str]],
) -> None:
    related_by_address = {
        _normalize_address(method.get("address")): (method, decompiled_entry)
        for method, decompiled_entry in related_entries
        if _normalize_address(method.get("address"))
    }
    for method in class_entry.get("methods") or []:
        if not isinstance(method, dict):
            continue
        _, decompiled_entry = related_by_address.get(_normalize_address(method.get("address")), (method, None))
        method.update(_infer_thunk_metadata(method, decompiled_entry))
        method["class_call_edges"] = _infer_method_call_edges(decompiled_entry)
        method["flag_inferences"] = _infer_flag_inferences(method, decompiled_entry)
        if method.get("flag_inferences"):
            method["enum_flag_domain"] = "bitmask_flags"
        if method.get("return_type_inference") in {
            "result_forwarded_to_typed_parameter",
            "returned_member_matches_concrete_class",
        }:
            method["class_propagation"] = str(method.get("return_type_inference"))


def _infer_subobjects(class_entry: dict[str, object], class_size_hints: dict[str, int]) -> list[dict[str, object]]:
    subobjects: list[dict[str, object]] = []
    pointer_size = 8
    offset = 0
    if class_entry.get("methods") or class_entry.get("vtables"):
        subobjects.append({"kind": "primary_vptr", "name": "vftable", "estimated_offset": 0, "estimated_size": pointer_size})
        offset = pointer_size
    for base_name in [str(value).strip() for value in class_entry.get("base_classes") or [] if str(value).strip()]:
        size = class_size_hints.get(base_name, pointer_size)
        subobjects.append(
            {
                "kind": "base_class",
                "name": base_name,
                "estimated_offset": 0 if len(subobjects) <= 1 else offset,
                "estimated_size": size,
            }
        )
        if len(subobjects) > 1:
            offset += size
    for member in class_entry.get("members") or []:
        if not isinstance(member, dict):
            continue
        if str(member.get("storage_shape") or "") != "class_object":
            continue
        subobjects.append(
            {
                "kind": "member_object",
                "name": member.get("name"),
                "type": member.get("type"),
                "estimated_offset": member.get("estimated_offset"),
                "estimated_size": member.get("estimated_size"),
                "provenance": member.get("primary_provenance"),
            }
        )
    return subobjects


def _infer_lifecycle_phases(
    related_entries: list[tuple[dict[str, object], dict[str, object]]],
    *,
    phase: str,
) -> list[dict[str, object]]:
    phases: list[dict[str, object]] = []
    wanted_kinds = {"constructor"} if phase == "constructor" else {"destructor", "scalar_deleting_destructor", "vector_deleting_destructor"}
    for method, decompiled_entry in related_entries:
        if str(method.get("method_kind") or "").strip() not in wanted_kinds:
            continue
        body = str(decompiled_entry.get("decompiled_c") or "")
        if not body:
            continue
        phases.append(
            {
                "function": str(method.get("display_name") or method.get("name") or "").strip(),
                "address": _normalize_address(method.get("address")),
                "steps": _extract_lifecycle_steps(body, phase=phase),
            }
        )
    return phases


def _extract_lifecycle_steps(decompiled_c: str, *, phase: str) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    for index, line in enumerate(_iter_body_statements(decompiled_c)):
        lowered = line.lower()
        step_kind = ""
        if "vftable" in lowered or "vftable" in line:
            step_kind = "vptr_write"
        elif "(i" in lowered and "::" in line and "this" in lowered:
            step_kind = "base_constructor_call" if phase == "constructor" else "base_destructor_call"
        elif "&this->" in line and "::" in line:
            step_kind = "member_constructor_call" if phase == "constructor" else "member_destructor_call"
        elif "operator_delete" in lowered:
            step_kind = "delete_call"
        elif "return this" in lowered:
            step_kind = "return_this"
        if step_kind:
            steps.append({"index": index, "kind": step_kind, "statement": line})
    return steps[:64]


def _iter_body_statements(decompiled_c: str) -> list[str]:
    statements: list[str] = []
    for raw_line in str(decompiled_c or "").splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line in {"{", "}"}:
            continue
        statements.append(line)
    return statements


def _infer_class_call_edges(related_entries: list[tuple[dict[str, object], dict[str, object]]]) -> list[dict[str, object]]:
    edges: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for method, decompiled_entry in related_entries:
        source = str(method.get("display_name") or method.get("name") or "").strip()
        for edge in _infer_method_call_edges(decompiled_entry):
            target = str(edge.get("target") or "")
            key = (source, target)
            if key in seen:
                continue
            seen.add(key)
            edges.append({"source": source, **edge})
    return edges[:256]


def _infer_method_call_edges(decompiled_entry: dict[str, object] | None) -> list[dict[str, object]]:
    body = str((decompiled_entry or {}).get("decompiled_c") or "")
    edges: list[dict[str, object]] = []
    seen: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_]\w*(?:::[A-Za-z_~]\w*)+)::([A-Za-z_~]\w*)\s*\(", body):
        owner = match.group(1)
        method = match.group(2)
        target = f"{owner}::{method}"
        if target in seen:
            continue
        seen.add(target)
        edges.append({"target": target, "owner": owner, "method": method})
    return edges[:64]


def _infer_thunk_metadata(method: dict[str, object], decompiled_entry: dict[str, object] | None) -> dict[str, object]:
    name = str(method.get("display_name") or method.get("name") or "").strip()
    body = str((decompiled_entry or {}).get("decompiled_c") or "")
    metadata: dict[str, object] = {"is_thunk": name.lower().startswith("thunk_")}
    match = re.search(r"(?:return\s+)?([A-Za-z_]\w*(?:::[A-Za-z_~]\w*)+)\s*\(", body)
    if match is not None and len(_iter_body_statements(body)) <= 6:
        metadata["is_thunk"] = True
        metadata["thunk_target"] = match.group(1)
        if re.search(r"this\s*[+-]\s*(0x[0-9a-fA-F]+|\d+)", body):
            metadata["thunk_kind"] = "adjustor_thunk"
        else:
            metadata["thunk_kind"] = "forwarding_thunk"
    return metadata


def _infer_flag_inferences(method: dict[str, object], decompiled_entry: dict[str, object] | None) -> list[dict[str, object]]:
    body = str((decompiled_entry or {}).get("decompiled_c") or "")
    results: list[dict[str, object]] = []
    for param in method.get("params") or []:
        if not isinstance(param, dict):
            continue
        name = str(param.get("name") or "").strip()
        param_type = str(param.get("type") or "").strip()
        if not name:
            continue
        constants = sorted(set(re.findall(rf"\b{re.escape(name)}\s*&\s*(0x[0-9a-fA-F]+|\d+)", body)))
        if "flag" in name.lower() or constants:
            results.append(
                {
                    "parameter": name,
                    "type": param_type,
                    "kind": "bitmask",
                    "constants": constants,
                    "confidence": "high" if constants else "medium",
                }
            )
    return results


def _infer_class_flag_domains(class_entry: dict[str, object]) -> list[dict[str, object]]:
    domains: list[dict[str, object]] = []
    for method in class_entry.get("methods") or []:
        if not isinstance(method, dict):
            continue
        for inference in method.get("flag_inferences") or []:
            if not isinstance(inference, dict):
                continue
            domains.append(
                {
                    "method": method.get("display_name") or method.get("name"),
                    "parameter": inference.get("parameter"),
                    "constants": inference.get("constants"),
                    "kind": inference.get("kind"),
                }
            )
    return domains


def _infer_symbol_recovery(class_entry: dict[str, object]) -> dict[str, object]:
    methods = [method for method in class_entry.get("methods") or [] if isinstance(method, dict)]
    named = [
        method
        for method in methods
        if not _is_generic_function_name(str(method.get("display_name") or method.get("name") or ""))
    ]
    ratio = len(named) / len(methods) if methods else 0.0
    if ratio >= 0.8:
        quality = "high"
    elif ratio >= 0.4:
        quality = "medium"
    else:
        quality = "low"
    return {
        "quality": quality,
        "named_method_ratio": round(ratio, 3),
        "named_methods": [str(method.get("display_name") or method.get("name")) for method in named[:64]],
    }


def _benchmark_capabilities_for_class(class_entry: dict[str, object]) -> list[str]:
    capabilities = []
    if class_entry.get("subobjects"):
        capabilities.append("subobjects")
    if class_entry.get("members"):
        capabilities.append("fields")
    if class_entry.get("constructor_phases"):
        capabilities.append("constructor_phases")
    if class_entry.get("destructor_phases"):
        capabilities.append("destructor_phases")
    if class_entry.get("class_call_edges"):
        capabilities.append("class_callgraph")
    if class_entry.get("flag_domains"):
        capabilities.append("flags")
    if (class_entry.get("symbol_recovery") or {}).get("quality") in {"medium", "high"}:
        capabilities.append("symbols")
    return capabilities


def _iter_class_related_decompiled_entries(
    class_entry: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
) -> list[tuple[dict[str, object], dict[str, object]]]:
    related: list[tuple[dict[str, object], dict[str, object]]] = []
    seen_addresses: set[str] = set()
    class_name = str(class_entry.get("name") or "").strip()
    short_name = class_name.split("::")[-1]
    for method in class_entry.get("methods") or []:
        if not isinstance(method, dict):
            continue
        address = _normalize_address(method.get("address"))
        decompiled_entry = decompiled_map.get(address)
        if decompiled_entry is None:
            continue
        seen_addresses.add(address)
        related.append((method, decompiled_entry))
    for address, decompiled_entry in decompiled_map.items():
        if address in seen_addresses:
            continue
        if not _entry_belongs_to_class(decompiled_entry, class_name, short_name):
            continue
        synthetic_method = {
            "name": str(decompiled_entry.get("name") or "").strip() or "method",
            "address": address,
            "display_name": str(decompiled_entry.get("name") or "").strip() or "method",
            "method_kind": _infer_entry_method_kind(decompiled_entry, short_name),
        }
        related.append((synthetic_method, decompiled_entry))
    return related


def _entry_belongs_to_class(
    decompiled_entry: dict[str, object],
    class_name: str,
    short_name: str,
) -> bool:
    namespace = str(decompiled_entry.get("namespace") or "").strip()
    if namespace == class_name:
        return True
    signature = str(decompiled_entry.get("signature") or "").strip()
    if re.search(r"\b%s \* *this\b" % re.escape(short_name), signature):
        return True
    name = str(decompiled_entry.get("name") or "").strip()
    return name in {short_name, f"~{short_name}", "__scalar_deleting_destructor", "__vector_deleting_destructor"}


def _infer_entry_method_kind(decompiled_entry: dict[str, object], class_name: str) -> str:
    signature = str(decompiled_entry.get("signature") or "").strip()
    name = str(decompiled_entry.get("name") or "").strip()
    candidate = _choose_candidate_method_name(name, name, _parse_signature(signature)["name"])
    return _infer_method_kind(candidate, class_name)


def _order_member_names(evidence_by_name: dict[str, list[dict[str, object]]]) -> list[str]:
    def sort_key(item: tuple[str, list[dict[str, object]]]) -> tuple[int, int, str]:
        member_name, evidences = item
        best = _member_evidence_sort_key(_best_member_evidence(evidences))
        return (best[0], best[1], member_name)

    ordered = sorted(evidence_by_name.items(), key=sort_key)
    return [member_name for member_name, _ in ordered]


def _annotate_class_layout(
    class_entry: dict[str, object],
    recovered: dict[str, object],
    class_size_hints: dict[str, int],
) -> None:
    class_name = str(class_entry.get("name") or "").strip()
    if not class_name:
        return
    pointer_size = _pointer_size_for_machine(str(recovered.get("machine") or class_entry.get("machine") or ""))
    members = [member for member in class_entry.get("members") or [] if isinstance(member, dict)]
    class_entry["layout_strategy"] = "constructor_first_evidence_order"
    class_entry["layout_sources"] = _collect_layout_sources(members)
    base_size = _estimate_base_size(class_entry, class_size_hints, pointer_size)
    offset = base_size
    for index, member in enumerate(members):
        member_type = str(member.get("type") or "").strip()
        estimated_size = _estimate_type_size(member_type, class_size_hints, pointer_size)
        if estimated_size <= 0:
            estimated_size = pointer_size
        offset = _align_value(offset, min(pointer_size, max(1, estimated_size)))
        member["layout_index"] = index
        member["estimated_offset"] = offset
        member["estimated_size"] = estimated_size
        member["layout_confidence"] = _layout_confidence_for_member(member_type, class_size_hints)
        member["layout_basis"] = class_entry.get("layout_strategy")
        offset += estimated_size
    estimated_object_size = class_size_hints.get(class_name)
    if estimated_object_size is None:
        estimated_object_size = _align_value(offset, pointer_size)
    class_entry["estimated_base_size"] = base_size
    class_entry["estimated_object_size"] = estimated_object_size
    tail_padding = estimated_object_size - offset
    if tail_padding > 0:
        class_entry["estimated_tail_padding"] = tail_padding


def _build_class_size_hints(
    recovered: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
) -> dict[str, int]:
    pointer_size = _pointer_size_for_machine(str(recovered.get("machine") or ""))
    classes = [entry for entry in recovered.get("classes") or [] if isinstance(entry, dict)]
    size_hints: dict[str, int] = {}
    for class_entry in classes:
        class_name = str(class_entry.get("name") or "").strip()
        if not class_name:
            continue
        explicit_size = _infer_explicit_object_size(class_entry, decompiled_map)
        if explicit_size is not None:
            size_hints[class_name] = explicit_size
    changed = True
    while changed:
        changed = False
        for class_entry in classes:
            class_name = str(class_entry.get("name") or "").strip()
            if not class_name:
                continue
            if class_name in size_hints:
                continue
            base_size = _estimate_base_size(class_entry, size_hints, pointer_size)
            members = [member for member in class_entry.get("members") or [] if isinstance(member, dict)]
            total_member_size = 0
            for member in members:
                estimated_size = _estimate_type_size(str(member.get("type") or ""), size_hints, pointer_size)
                if estimated_size <= 0:
                    total_member_size = 0
                    break
                total_member_size += estimated_size
            if members and total_member_size == 0:
                continue
            if base_size <= 0 and (members or class_entry.get("methods") or class_entry.get("base_classes")):
                continue
            estimated_total = _align_value(base_size + total_member_size, pointer_size)
            if estimated_total > 0:
                size_hints[class_name] = estimated_total
                changed = True
    return size_hints


def _infer_explicit_object_size(
    class_entry: dict[str, object],
    decompiled_map: dict[str, dict[str, object]],
) -> int | None:
    for method in class_entry.get("methods") or []:
        if not isinstance(method, dict):
            continue
        method_kind = str(method.get("method_kind") or "").strip()
        if method_kind not in {"scalar_deleting_destructor", "vector_deleting_destructor"}:
            continue
        decompiled_entry = decompiled_map.get(_normalize_address(method.get("address")))
        decompiled_c = str((decompiled_entry or {}).get("decompiled_c") or "")
        if not decompiled_c:
            continue
        match = re.search(r"operator_delete\s*\(\s*this\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)", decompiled_c)
        if match is None:
            continue
        try:
            return int(match.group(1), 0)
        except ValueError:
            continue
    return None


def _estimate_base_size(
    class_entry: dict[str, object],
    class_size_hints: dict[str, int],
    pointer_size: int,
) -> int:
    base_classes = [str(value).strip() for value in class_entry.get("base_classes") or [] if str(value).strip()]
    if base_classes:
        total = 0
        for base_class in base_classes:
            total += class_size_hints.get(base_class, pointer_size)
        return total
    has_vtable = bool(class_entry.get("methods") or class_entry.get("vtables"))
    return pointer_size if has_vtable else 0


def _estimate_type_size(member_type: str, class_size_hints: dict[str, int], pointer_size: int) -> int:
    normalized = str(member_type or "").strip()
    if not normalized:
        return 0
    if normalized in class_size_hints:
        return class_size_hints[normalized]
    lowered = normalized.lower()
    if lowered.endswith("*"):
        return pointer_size
    if normalized == "std::string":
        return 0x20 if pointer_size == 8 else 0x1c
    if normalized == "std::wstring":
        return 0x20 if pointer_size == 8 else 0x1c
    primitive_sizes = {
        "bool": 1,
        "char": 1,
        "const char": 1,
        "unsigned char": 1,
        "wchar_t": 2,
        "short": 2,
        "unsigned short": 2,
        "int": 4,
        "uint": 4,
        "unsigned int": 4,
        "long": 4,
        "unsigned long": 4,
        "float": 4,
        "double": 8,
        "long long": 8,
        "unsigned long long": 8,
        "undefined8": 8,
        "ulonglong": 8,
        "longlong": 8,
    }
    return primitive_sizes.get(lowered, 0)


def _pointer_size_for_machine(machine: str) -> int:
    return 8 if str(machine or "").lower() in {"x64", "amd64", "x86_64"} else 4


def _align_value(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    remainder = value % alignment
    if remainder == 0:
        return value
    return value + (alignment - remainder)


def _layout_confidence_for_member(member_type: str, class_size_hints: dict[str, int]) -> str:
    normalized = str(member_type or "").strip()
    if normalized in {"std::string", "std::wstring"}:
        return "high"
    if normalized in class_size_hints:
        return "medium"
    if normalized.endswith("*"):
        return "medium"
    return "low"


def _infer_member_evidence(
    method: dict[str, object],
    decompiled_entry: dict[str, object] | None,
    class_hierarchy: dict[str, set[str]],
) -> list[dict[str, object]]:
    if not isinstance(decompiled_entry, dict):
        return []
    decompiled_c = str(decompiled_entry.get("decompiled_c") or "")
    if not decompiled_c:
        return []
    evidence: list[dict[str, object]] = []
    source_priority = _member_evidence_priority(method, decompiled_entry)
    appearance = _member_appearance_indices(decompiled_c)
    for match in re.finditer(
        r"std::basic_string<char\b[\s\S]*?::\s*(?:basic_string|c_str|operator=|empty)(?:<[\s\S]*?>)?\s*\(\s*&this->([A-Za-z_]\w*)",
        decompiled_c,
    ):
        member_name = match.group(1)
        evidence.append(
            _make_member_evidence(
                method,
                member_name,
                "std::string",
                "std_string_member_usage",
                source_priority,
                appearance.get(member_name, 999),
                decompiled_c,
                match.start(),
                match.end(),
            )
        )
    for match in re.finditer(
        r"std::basic_string<wchar_t\b[\s\S]*?::\s*(?:basic_string|c_str|operator=|empty)(?:<[\s\S]*?>)?\s*\(\s*&this->([A-Za-z_]\w*)",
        decompiled_c,
    ):
        member_name = match.group(1)
        evidence.append(
            _make_member_evidence(
                method,
                member_name,
                "std::wstring",
                "std_wstring_member_usage",
                source_priority,
                appearance.get(member_name, 999),
                decompiled_c,
                match.start(),
                match.end(),
            )
        )
    for match in re.finditer(
        r"([A-Za-z_:][A-Za-z0-9_:]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*&this->([A-Za-z_]\w*)",
        decompiled_c,
    ):
        owner_name = match.group(1)
        constructor_name = match.group(2)
        member_name = match.group(3)
        resolved_type = _resolve_recovered_class_name(owner_name, class_hierarchy)
        if not resolved_type:
            continue
        owner_short_name = owner_name.split("::")[-1]
        resolved_short_name = resolved_type.split("::")[-1]
        if constructor_name not in {owner_short_name, resolved_short_name}:
            continue
        evidence.append(
            _make_member_evidence(
                method,
                member_name,
                resolved_type,
                "constructed_member_matches_recovered_class",
                source_priority,
                appearance.get(member_name, 999),
                decompiled_c,
                match.start(),
                match.end(),
            )
        )
    for match in re.finditer(r"this->([A-Za-z_]\w*)\s*=\s*([^;\n]+)", decompiled_c):
        member_name = match.group(1)
        if member_name in {"_padding_", "vftable", "vfptr"} or "vftable" in member_name.lower():
            continue
        member_type = _infer_assignment_member_type(match.group(2))
        if not member_type:
            continue
        evidence.append(
            _make_member_evidence(
                method,
                member_name,
                member_type,
                "scalar_member_store",
                source_priority,
                appearance.get(member_name, 999),
                decompiled_c,
                match.start(),
                match.end(),
            )
        )
    member_match = re.search(r"return\s+\([^)]*\)\s*&this->([A-Za-z_]\w*)\s*;", decompiled_c)
    if member_match is None:
        member_match = re.search(r"return\s+&this->([A-Za-z_]\w*)\s*;", decompiled_c)
    if member_match is not None:
        member_name = member_match.group(1)
        member_type = _infer_member_type_from_return(method, decompiled_entry, class_hierarchy)
        if member_type:
            evidence.append(
                _make_member_evidence(
                    method,
                    member_name,
                    member_type,
                    "returned_member_matches_concrete_class",
                    source_priority,
                    appearance.get(member_name, 999),
                    decompiled_c,
                    member_match.start(),
                    member_match.end(),
                )
            )
    return evidence


def _make_member_evidence(
    method: dict[str, object],
    member_name: str,
    member_type: str,
    reason: str,
    source_priority: int,
    appearance_index: int,
    decompiled_c: str,
    start: int,
    end: int,
) -> dict[str, object]:
    source_function = str(method.get("display_name") or method.get("name") or "").strip()
    source_kind = str(method.get("method_kind") or "").strip() or "helper_method"
    return {
        "name": member_name,
        "type": member_type,
        "reason": reason,
        "evidence": source_function,
        "source_function": source_function,
        "source_kind": source_kind,
        "statement": _statement_snippet(decompiled_c, start, end),
        "source_priority": source_priority,
        "appearance_index": appearance_index,
    }


def _statement_snippet(decompiled_c: str, start: int, end: int) -> str:
    line_start = decompiled_c.rfind("\n", 0, start)
    line_end = decompiled_c.find("\n", end)
    snippet = decompiled_c[(line_start + 1 if line_start != -1 else 0) : (line_end if line_end != -1 else len(decompiled_c))]
    snippet = " ".join(snippet.strip().split())
    if len(snippet) > 180:
        return snippet[:177] + "..."
    return snippet


def _member_evidence_sort_key(evidence: dict[str, object] | None) -> tuple[int, int, str]:
    if not isinstance(evidence, dict):
        return (9, 999, "")
    return (
        int(evidence.get("source_priority", 9)),
        int(evidence.get("appearance_index", 999)),
        str(evidence.get("evidence") or ""),
    )


def _best_member_evidence(evidences: list[dict[str, object]]) -> dict[str, object] | None:
    if not evidences:
        return None
    return min(evidences, key=_member_evidence_sort_key)


def _serialize_member_provenance(evidence: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(evidence, dict):
        return None
    return {
        "source_function": str(evidence.get("source_function") or "").strip(),
        "source_kind": str(evidence.get("source_kind") or "").strip(),
        "reason": str(evidence.get("reason") or "").strip(),
        "statement": str(evidence.get("statement") or "").strip(),
        "appearance_index": int(evidence.get("appearance_index", 999)),
        "source_priority": int(evidence.get("source_priority", 9)),
    }


def _serialize_member_provenance_list(evidences: list[dict[str, object]], limit: int = 8) -> list[dict[str, object]]:
    ordered = sorted(evidences, key=_member_evidence_sort_key)
    seen: set[tuple[str, str, str, str]] = set()
    payload: list[dict[str, object]] = []
    for evidence in ordered:
        serialized = _serialize_member_provenance(evidence)
        if not serialized:
            continue
        signature = (
            str(serialized.get("source_kind") or ""),
            str(serialized.get("source_function") or ""),
            str(serialized.get("reason") or ""),
            str(serialized.get("statement") or ""),
        )
        if signature in seen:
            continue
        seen.add(signature)
        payload.append(serialized)
        if len(payload) >= limit:
            break
    return payload


def _collect_layout_sources(members: list[dict[str, object]]) -> list[str]:
    sources: list[str] = []
    seen: set[str] = set()
    for member in members:
        primary_provenance = member.get("primary_provenance")
        if not isinstance(primary_provenance, dict):
            continue
        source_kind = str(primary_provenance.get("source_kind") or "").strip()
        if not source_kind or source_kind in seen:
            continue
        seen.add(source_kind)
        sources.append(source_kind)
    return sources


def _member_evidence_priority(
    method: dict[str, object],
    decompiled_entry: dict[str, object],
) -> int:
    method_kind = str(method.get("method_kind") or "").strip()
    if method_kind == "constructor":
        return 0
    if method_kind in {"destructor", "scalar_deleting_destructor", "vector_deleting_destructor"}:
        return 3
    caller_count = int(decompiled_entry.get("caller_count") or 0)
    return 1 if caller_count <= 1 else 2


def _member_appearance_indices(decompiled_c: str) -> dict[str, int]:
    appearance: dict[str, int] = {}
    for index, member_name in enumerate(re.findall(r"(?:&)?this->([A-Za-z_]\w*)", decompiled_c)):
        if member_name not in appearance:
            appearance[member_name] = index
    return appearance


def _infer_member_type_from_return(
    method: dict[str, object],
    decompiled_entry: dict[str, object] | None,
    class_hierarchy: dict[str, set[str]],
) -> str:
    return_type = str(method.get("return_type") or (decompiled_entry or {}).get("return_type") or "").strip()
    return_type, _ = _apply_result_hints_to_return_type(return_type, decompiled_entry, class_hierarchy)
    pointed = _pointer_target_type(return_type)
    if not pointed:
        return ""
    if any(_class_names_match(pointed, known_class) for known_class in class_hierarchy):
        return pointed
    return pointed


def _infer_assignment_member_type(rhs: str) -> str:
    text = str(rhs or "").strip()
    lowered = text.lower()
    if not text:
        return ""
    if text.startswith('L"'):
        return "const wchar_t *"
    if text.startswith('"'):
        return "const char *"
    if lowered in {"true", "false"}:
        return "bool"
    if re.fullmatch(r"[01]", lowered):
        return "bool"
    if re.fullmatch(r"0x[0-9a-f]+|\d+", lowered):
        return "int"
    if re.fullmatch(r"0x[0-9a-f]+ll|\d+ll", lowered):
        return "long long"
    if "nullptr" in lowered or lowered == "null":
        return "void *"
    cast_match = re.match(r"\(([^)]+)\)", text)
    if cast_match:
        candidate = _normalize_return_type(cast_match.group(1))
        if candidate and candidate.lower() not in {"longlong", "ulonglong", "undefined8", "undefined4"}:
            return candidate
    return ""


def _resolve_recovered_class_name(candidate: str, class_hierarchy: dict[str, set[str]]) -> str:
    text = str(candidate or "").strip()
    if not text:
        return ""
    if text in class_hierarchy:
        return text
    short_name = text.split("::")[-1]
    matches = [name for name in class_hierarchy if name.split("::")[-1] == short_name]
    if len(matches) == 1:
        return matches[0]
    return ""


def _choose_member_type(evidences: list[dict[str, object]]) -> str:
    counts: dict[str, int] = {}
    for evidence in evidences:
        member_type = str(evidence.get("type") or "").strip()
        if not member_type:
            continue
        counts[member_type] = counts.get(member_type, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _infer_concrete_return_class_from_body(
    current_return_type: str,
    decompiled_c: str,
    class_hierarchy: dict[str, set[str]],
) -> str:
    base_class = _pointer_target_type(current_return_type)
    if not base_class:
        return ""
    member_match = re.search(r"return\s+\([^)]*\)\s*&this->([A-Za-z_]\w*)\s*;", decompiled_c)
    if member_match is None:
        member_match = re.search(r"return\s+&this->([A-Za-z_]\w*)\s*;", decompiled_c)
    if member_match is None:
        return ""
    member_token = _normalize_identifier_token(member_match.group(1))
    if not member_token:
        return ""
    candidates = []
    for class_name, bases in class_hierarchy.items():
        if not any(_class_names_match(base_class, base_name) for base_name in bases):
            continue
        leaf = class_name.split("::")[-1]
        normalized_leaf = _normalize_identifier_token(leaf)
        if not normalized_leaf:
            continue
        if member_token in normalized_leaf or normalized_leaf in member_token:
            candidates.append(class_name)
    if len(candidates) != 1:
        return ""
    return f"{candidates[0]} *"


def _normalize_identifier_token(value: str) -> str:
    text = str(value or "").strip().lower().strip("_")
    return re.sub(r"[^a-z0-9]+", "", text)


def _class_names_match(left: str, right: str) -> bool:
    left_text = str(left or "").strip()
    right_text = str(right or "").strip()
    if not left_text or not right_text:
        return False
    if left_text == right_text:
        return True
    return left_text.split("::")[-1] == right_text.split("::")[-1]


def _extract_parameter_entries(decompiled_entry: dict[str, object] | None, fallback_params: list[str]) -> list[dict[str, str]]:
    parameters = []
    for entry in (decompiled_entry or {}).get("parameters") or []:
        if not isinstance(entry, dict):
            continue
        param_type = str(entry.get("data_type") or "").strip()
        param_name = str(entry.get("name") or "").strip()
        if not param_type and not param_name:
            continue
        parameters.append({"type": param_type or "undefined", "name": param_name or "arg"})
    if parameters:
        return parameters
    return [_split_param(piece, index) for index, piece in enumerate(fallback_params, start=1)]


def _extract_caller_names(decompiled_entry: dict[str, object] | None) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for caller in (decompiled_entry or {}).get("callers") or []:
        if not isinstance(caller, dict):
            continue
        caller_name = str(caller.get("caller_name") or "").strip()
        if not caller_name or caller_name in seen:
            continue
        seen.add(caller_name)
        names.append(caller_name)
    return names
