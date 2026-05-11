from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .utils import extract_ascii_strings, safe_slug, sanitize_text

DDL_SUFFIXES = {
    ".ddl",
    ".ddls",
    ".schema",
    ".schemas",
    ".struct",
    ".structs",
    ".defs",
    ".def",
    ".fbs",
    ".proto",
    ".capnp",
    ".reflect",
    ".reflection",
    ".json",
    ".types",
}

DDL_NAME_MARKERS = (
    "ddl",
    "schema",
    "schemas",
    "struct",
    "structs",
    "reflection",
    "typeinfo",
    "data_definition",
    "datadefinition",
    "flatbuffers",
    "protobuf",
    "uproperty",
    "ustruct",
)

DDL_TYPE_TOKENS = {
    "bool",
    "boolean",
    "byte",
    "char",
    "double",
    "f32",
    "f64",
    "float",
    "guid",
    "hash",
    "hash32",
    "hash64",
    "half",
    "i8",
    "i16",
    "i32",
    "i64",
    "int",
    "int32_t",
    "int64_t",
    "int16_t",
    "int8_t",
    "int8",
    "int16",
    "int32",
    "int64",
    "mat3",
    "mat4",
    "matrix",
    "name",
    "quaternion",
    "s8",
    "s16",
    "s32",
    "s64",
    "sint32",
    "sint64",
    "sfixed32",
    "sfixed64",
    "fixed32",
    "fixed64",
    "string",
    "fstring",
    "fname",
    "fvector",
    "fvector2d",
    "fvector4",
    "frotator",
    "tarray",
    "u8",
    "u16",
    "u32",
    "u64",
    "uint",
    "uint32_t",
    "uint64_t",
    "uint16_t",
    "uint8_t",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "vec2",
    "vec3",
    "vec4",
    "vector2",
    "vector3",
    "vector4",
}

JSON_SCHEMA_INTEGER_FORMATS = {
    "int8": "int8",
    "int16": "int16",
    "int32": "int32",
    "int64": "int64",
    "uint8": "uint8",
    "uint16": "uint16",
    "uint32": "uint32",
    "uint64": "uint64",
    "byte": "uint8",
}

TYPE_LAYOUTS = {
    "bool": (1, 1),
    "boolean": (1, 1),
    "byte": (1, 1),
    "char": (1, 1),
    "double": (8, 8),
    "f32": (4, 4),
    "f64": (8, 8),
    "float": (4, 4),
    "guid": (16, 4),
    "hash": (4, 4),
    "hash32": (4, 4),
    "hash64": (8, 8),
    "half": (2, 2),
    "i8": (1, 1),
    "i16": (2, 2),
    "i32": (4, 4),
    "i64": (8, 8),
    "int": (4, 4),
    "int8_t": (1, 1),
    "int16_t": (2, 2),
    "int32_t": (4, 4),
    "int64_t": (8, 8),
    "int8": (1, 1),
    "int16": (2, 2),
    "int32": (4, 4),
    "int64": (8, 8),
    "mat3": (36, 4),
    "mat4": (64, 4),
    "matrix": (64, 4),
    "name": (8, 8),
    "quaternion": (16, 4),
    "s8": (1, 1),
    "s16": (2, 2),
    "s32": (4, 4),
    "s64": (8, 8),
    "sint32": (4, 4),
    "sint64": (8, 8),
    "sfixed32": (4, 4),
    "sfixed64": (8, 8),
    "fixed32": (4, 4),
    "fixed64": (8, 8),
    "string": (24, 8),
    "fname": (8, 8),
    "fstring": (24, 8),
    "fvector2d": (8, 4),
    "fvector": (12, 4),
    "fvector4": (16, 4),
    "frotator": (12, 4),
    "u8": (1, 1),
    "u16": (2, 2),
    "u32": (4, 4),
    "u64": (8, 8),
    "uint": (4, 4),
    "uint8_t": (1, 1),
    "uint16_t": (2, 2),
    "uint32_t": (4, 4),
    "uint64_t": (8, 8),
    "uint8": (1, 1),
    "uint16": (2, 2),
    "uint32": (4, 4),
    "uint64": (8, 8),
    "vec2": (8, 4),
    "vec3": (12, 4),
    "vec4": (16, 4),
    "vector2": (8, 4),
    "vector3": (12, 4),
    "vector4": (16, 4),
}

_STRUCT_RE = re.compile(
    r"\b(?P<kind>struct|class|message|record|table)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:\s*:\s*[A-Za-z_][A-Za-z0-9_:<>,\s]*)?"
    r"\s*\{(?P<body>.*?)\}\s*;?",
    re.DOTALL,
)
_ENUM_RE = re.compile(
    r"\benum(?:\s+class)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:\s*:\s*[A-Za-z_][A-Za-z0-9_:<>,\s]*)?"
    r"\s*\{(?P<body>.*?)\}\s*;?",
    re.DOTALL,
)
_TYPE_FIRST_FIELD_RE = re.compile(
    r"^(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*\[\s*(?P<array>[^\]]+)\s*\])?"
    r"(?:\s*=\s*(?P<default>.+))?$"
)
_NAME_FIRST_FIELD_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*?)"
    r"(?:\s*\[\s*(?P<array>[^\]]+)\s*\])?"
    r"(?:\s*=\s*(?P<default>.+))?$"
)
_COMPACT_RECORD_RE = re.compile(
    r"\b(?P<struct>[A-Za-z_][A-Za-z0-9_]{2,})(?:\.|::|/)"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?::|->|=|\s)\s*"
    r"(?P<type>bool|boolean|byte|char|double|f32|f64|float|guid|hash32|hash64|hash|"
    r"i8|i16|i32|i64|int8|int16|int32|int64|int|mat3|mat4|matrix|quaternion|"
    r"s8|s16|s32|s64|string|u8|u16|u32|u64|uint8|uint16|uint32|uint64|uint|vec2|vec3|vec4)\b",
    re.IGNORECASE,
)
_TABULAR_FIELD_RE = re.compile(
    r"^\s*(?P<struct>[A-Za-z_][A-Za-z0-9_]{2,})\s*(?:,|\t|\|)\s*"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\t|\|)\s*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*?)"
    r"(?:\s*(?:,|\t|\|)\s*(?P<offset>0x[0-9A-Fa-f]+|\d+))?"
    r"(?:\s*(?:,|\t|\|)\s*(?P<size>0x[0-9A-Fa-f]+|\d+))?\s*$",
    re.MULTILINE,
)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def looks_like_ddl(path: Path, data: bytes) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in DDL_SUFFIXES or any(marker in name for marker in DDL_NAME_MARKERS):
        return True

    sample = data[:512_000].lower()
    if b"\x00" in sample[:4096]:
        strings = extract_ascii_strings(sample, minimum=4, limit=2000)
        text = "\n".join(strings).lower()
    else:
        text = sample.decode("utf-8", errors="ignore")
    if not text:
        return False
    if re.search(r"\b(struct|class|message|record|table|enum)\s+[a-z_][a-z0-9_:]*\s*\{", text):
        return True
    if re.search(r"\b(uproperty|ustruct|root_type|syntax\s*=|rpc_service)\b", text):
        return True
    if suffix == ".json" and re.search(r'"(structs|classes|records|types|fields|members|properties)"\s*:', text):
        return True
    token_hits = sum(1 for token in DDL_TYPE_TOKENS if re.search(rf"\b{re.escape(token)}\b", text))
    schema_hits = sum(1 for marker in DDL_NAME_MARKERS if marker in text)
    return token_hits >= 4 and schema_hits >= 1


def parse_ddl_from_file(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError as exc:
        return {
            "ok": False,
            "source_path": str(path),
            "source_name": path.name,
            "structs": [],
            "enums": [],
            "summary": {"struct_count": 0, "field_count": 0, "enum_count": 0},
            "notes": [f"failed to read source: {exc}"],
        }
    return parse_ddl_from_bytes(data, source_name=path.name, source_path=str(path))


def parse_ddl_from_bytes(data: bytes, *, source_name: str = "memory", source_path: str = "") -> dict[str, Any]:
    if not data:
        return _empty_result(source_name=source_name, source_path=source_path, notes=["empty input"])

    if b"\x00" in data[:4096]:
        strings = extract_ascii_strings(data, minimum=1, limit=20000)
        text = "\n".join(strings)
        result = parse_ddl_text(text, source_name=source_name, source_path=source_path)
        if not result["ok"]:
            inferred = _infer_structs_from_string_table(strings)
            if inferred:
                result["structs"] = inferred
                result["summary"] = _summary(result["structs"], result["enums"])
                result["ok"] = True
                result["notes"].append("Recovered structs from adjacent binary string-table tokens.")
        return result

    text = data.decode("utf-8", errors="ignore")
    return parse_ddl_text(text, source_name=source_name, source_path=source_path)


def parse_ddl_text(text: str, *, source_name: str = "text", source_path: str = "") -> dict[str, Any]:
    json_result = _parse_json_schema_text(text, source_name=source_name, source_path=source_path)
    if json_result["ok"]:
        return json_result

    normalized = _strip_comments(sanitize_text(text))
    structs: list[dict[str, Any]] = []
    enums = _parse_enums(normalized)
    seen_structs: set[str] = set()

    for match in _STRUCT_RE.finditer(normalized):
        name = _clean_type_name(match.group("name"))
        if not name or name.lower() in seen_structs:
            continue
        fields = _parse_fields(match.group("body"))
        if not fields:
            continue
        seen_structs.add(name.lower())
        structs.append(
            _finalize_struct(
                {
                    "name": name,
                    "kind": match.group("kind"),
                    "fields": fields,
                    "field_count": len(fields),
                    "confidence": _confidence(normalized, fields),
                    "source_name": source_name,
                    "source_path": source_path,
                }
            )
        )

    compact_structs = _parse_compact_records(normalized)
    for struct in compact_structs:
        key = struct["name"].lower()
        if key in seen_structs:
            continue
        seen_structs.add(key)
        struct["source_name"] = source_name
        struct["source_path"] = source_path
        structs.append(_finalize_struct(struct))

    tabular_structs = _parse_tabular_records(normalized)
    for struct in tabular_structs:
        key = struct["name"].lower()
        if key in seen_structs:
            continue
        seen_structs.add(key)
        struct["source_name"] = source_name
        struct["source_path"] = source_path
        structs.append(_finalize_struct(struct))

    result = {
        "ok": bool(structs or enums),
        "source_name": source_name,
        "source_path": source_path,
        "structs": structs,
        "enums": enums,
        "summary": _summary(structs, enums),
        "notes": [],
    }
    if not result["ok"]:
        result["notes"].append("No DDL structs or enums were recovered.")
    return result


def _parse_json_schema_text(text: str, *, source_name: str, source_path: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return _empty_result(source_name=source_name, source_path=source_path)
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return _empty_result(source_name=source_name, source_path=source_path)

    structs: list[dict[str, Any]] = []
    enums: list[dict[str, Any]] = []
    seen: set[str] = set()
    for struct in _walk_json_structs(payload):
        name = _clean_type_name(str(struct.get("name") or ""))
        if not name or name.lower() in seen:
            continue
        fields = [_normalize_json_field(field) for field in struct.get("fields") or []]
        fields = _dedupe_fields([field for field in fields if field])
        if not fields:
            continue
        seen.add(name.lower())
        structs.append(
            _finalize_struct(
                {
                    "name": name,
                    "kind": str(struct.get("kind") or "json_schema"),
                    "fields": fields,
                    "field_count": len(fields),
                    "confidence": float(struct.get("confidence") or 0.88),
                    "source_name": source_name,
                    "source_path": source_path,
                }
            )
        )
    for enum in _walk_json_enums(payload):
        name = _clean_type_name(str(enum.get("name") or ""))
        if not name:
            continue
        values = enum.get("values") or []
        if values:
            enums.append({"name": name, "values": values, "value_count": len(values), "confidence": 0.86})

    result = {
        "ok": bool(structs or enums),
        "source_name": source_name,
        "source_path": source_path,
        "structs": structs,
        "enums": enums,
        "summary": _summary(structs, enums),
        "notes": ["Recovered DDL structs from JSON/reflection schema."] if structs or enums else [],
    }
    if not result["ok"]:
        result["notes"].append("No JSON DDL structs or enums were recovered.")
    return result


def _walk_json_structs(payload: Any) -> list[dict[str, Any]]:
    structs: list[dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            structs.extend(_walk_json_structs(item))
        return structs
    if not isinstance(payload, dict):
        return structs

    direct_items: list[Any] = []
    for key in ("structs", "classes", "records", "types", "schemas"):
        value = payload.get(key)
        if isinstance(value, list):
            direct_items.extend(value)
        elif isinstance(value, dict):
            for name, item in value.items():
                if isinstance(item, dict):
                    direct_items.append({"name": name, **item})
                elif isinstance(item, list):
                    direct_items.append({"name": name, "fields": item})
    for item in direct_items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("typeName") or item.get("className") or item.get("id")
        fields = item.get("fields") or item.get("members") or item.get("properties") or item.get("columns")
        normalized_fields = _json_fields_from_any(fields)
        if name and normalized_fields:
            structs.append(
                {
                    "name": str(name),
                    "kind": str(item.get("kind") or item.get("type") or "json_reflection"),
                    "fields": normalized_fields,
                    "confidence": 0.9,
                }
            )

    if str(payload.get("type", "")).lower() == "object" and isinstance(payload.get("properties"), dict):
        name = payload.get("title") or payload.get("name") or payload.get("$id") or payload.get("id")
        if name:
            structs.append(
                {
                    "name": Path(str(name)).stem,
                    "kind": "json_schema",
                    "fields": _json_fields_from_any(payload.get("properties")),
                    "confidence": 0.86,
                }
            )

    for value in payload.values():
        if isinstance(value, (dict, list)):
            structs.extend(_walk_json_structs(value))
    return structs


def _walk_json_enums(payload: Any) -> list[dict[str, Any]]:
    enums: list[dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            enums.extend(_walk_json_enums(item))
        return enums
    if not isinstance(payload, dict):
        return enums
    for key in ("enums", "enumTypes"):
        value = payload.get(key)
        items = value if isinstance(value, list) else []
        if isinstance(value, dict):
            items = [{"name": name, "values": enum_values} for name, enum_values in value.items()]
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("typeName")
            values = item.get("values") or item.get("members")
            enum_values = _json_enum_values(values)
            if name and enum_values:
                enums.append({"name": str(name), "values": enum_values})
    if "enum" in payload and isinstance(payload.get("enum"), list):
        name = payload.get("title") or payload.get("name")
        if name:
            enums.append({"name": str(name), "values": _json_enum_values(payload.get("enum"))})
    for value in payload.values():
        if isinstance(value, (dict, list)):
            enums.extend(_walk_json_enums(value))
    return enums


def _json_fields_from_any(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        fields: list[dict[str, Any]] = []
        for name, descriptor in value.items():
            if isinstance(descriptor, dict):
                fields.append({"name": name, **descriptor})
            else:
                fields.append({"name": name, "type": descriptor})
        return fields
    return []


def _normalize_json_field(field: dict[str, Any]) -> dict[str, Any] | None:
    name = str(field.get("name") or field.get("field") or field.get("member") or "")
    if not _is_identifier(name):
        return None
    field_type = _json_field_type(field)
    if not _is_reasonable_type(field_type):
        return None
    result: dict[str, Any] = {
        "name": name,
        "type": field_type,
        "array": _json_array_count(field),
        "default": str(field.get("default") or ""),
    }
    offset = _first_present(field, "offset", "field_offset", "offset_hint")
    if offset is not None:
        result["offset_hint"] = _format_offset_hint(offset)
    size = _first_present(field, "size", "byte_size", "sizeof")
    if size is not None:
        parsed_size = _parse_int(size)
        if parsed_size is not None:
            result["declared_size"] = parsed_size
    return {key: value for key, value in result.items() if value not in ("", None)}


def _json_field_type(field: dict[str, Any]) -> str:
    explicit = field.get("typeName") or field.get("fieldType") or field.get("ctype") or field.get("type")
    if isinstance(explicit, str) and explicit.lower() == "array":
        item = field.get("items") or field.get("elementType") or field.get("element_type")
        if isinstance(item, dict):
            return _json_field_type(item)
        if item:
            return str(item)
    if isinstance(explicit, str) and explicit.lower() in {"integer", "number"}:
        fmt = str(field.get("format") or field.get("storage") or "").lower()
        if fmt in JSON_SCHEMA_INTEGER_FORMATS:
            return JSON_SCHEMA_INTEGER_FORMATS[fmt]
        return "float" if explicit.lower() == "number" else "int32"
    if isinstance(explicit, str) and explicit.lower() in {"boolean", "string"}:
        return explicit.lower()
    if explicit:
        return str(explicit)
    return "uint8"


def _json_array_count(field: dict[str, Any]) -> str:
    for key in ("array", "array_count", "count", "fixed_count", "length", "maxItems"):
        value = field.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _json_enum_values(values: Any) -> list[dict[str, str]]:
    if isinstance(values, dict):
        return [{"name": str(name), "value": str(value)} for name, value in values.items()]
    if isinstance(values, list):
        result: list[dict[str, str]] = []
        for index, value in enumerate(values):
            if isinstance(value, dict):
                result.append(
                    {
                        "name": str(value.get("name") or value.get("label") or f"Value_{index}"),
                        "value": str(value.get("value") or value.get("id") or index),
                    }
                )
            else:
                result.append({"name": str(value), "value": str(index)})
        return result
    return []


def _format_offset_hint(value: Any) -> str:
    parsed = _parse_int(value)
    if parsed is None:
        return str(value)
    return f"0x{parsed:x}"


def _first_present(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def _finalize_struct(struct: dict[str, Any]) -> dict[str, Any]:
    fields = [_enrich_field_layout(field) for field in struct.get("fields") or []]
    fields = _assign_field_offsets(fields)
    struct["fields"] = fields
    struct["field_count"] = len(fields)
    estimated_size = _estimate_struct_size(fields)
    if estimated_size is not None:
        struct["estimated_size"] = estimated_size
        struct["estimated_size_hex"] = f"0x{estimated_size:x}"
    if any("offset" in field for field in fields):
        struct["layout_confidence"] = "explicit" if any(field.get("offset_source") == "explicit" for field in fields) else "estimated"
    return struct


def write_ddl_struct_sources(parsed: dict[str, Any], output_dir: Path, *, prefix: str = "") -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []
    used_names: set[str] = set()
    source_name = str(parsed.get("source_name") or "unknown")
    prefix_slug = f"{safe_slug(prefix)}_" if prefix else ""

    for enum in parsed.get("enums") or []:
        enum_name = safe_slug(str(enum.get("name") or "RecoveredEnum"))
        path = _unique_output_path(output_dir, f"{prefix_slug}{enum_name}.hpp", used_names)
        path.write_text(_render_enum_header(enum, source_name), encoding="utf-8")
        generated.append(path)

    for struct in parsed.get("structs") or []:
        struct_name = safe_slug(str(struct.get("name") or "RecoveredStruct"))
        path = _unique_output_path(output_dir, f"{prefix_slug}{struct_name}.hpp", used_names)
        path.write_text(_render_struct_header(struct, source_name), encoding="utf-8")
        generated.append(path)
    return generated


def build_ddl_manifest(results: list[dict[str, Any]]) -> dict[str, Any]:
    struct_count = 0
    field_count = 0
    enum_count = 0
    layout_count = 0
    for result in results:
        summary = result.get("summary") or {}
        struct_count += int(summary.get("struct_count", 0) or 0)
        field_count += int(summary.get("field_count", 0) or 0)
        enum_count += int(summary.get("enum_count", 0) or 0)
        layout_count += int(summary.get("layout_count", 0) or 0)
    return {
        "ok": bool(struct_count or enum_count),
        "summary": {
            "source_count": len(results),
            "struct_count": struct_count,
            "field_count": field_count,
            "enum_count": enum_count,
            "layout_count": layout_count,
        },
        "sources": results,
    }


def write_ddl_manifest(results: list[dict[str, Any]], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_ddl_manifest(results), indent=2), encoding="utf-8")
    return path


def index_ddl_results(
    analysis_index: Any,
    *,
    target_path: str,
    manifest_path: Path,
    results: list[dict[str, Any]],
    target_relation: str = "defines_game_data_struct",
) -> None:
    target_id = analysis_index.make_id("target", target_path)
    manifest_id = analysis_index.add_entity(
        "artifact",
        str(manifest_path),
        "Recovered DDL struct manifest",
        attributes={"path": str(manifest_path), "category": "manifest", "format": "ddl_structs"},
    )
    analysis_index.add_relation(target_id, "produced_artifact", manifest_id)
    for result in results:
        source_path = str(result.get("source_path") or result.get("source_name") or "")
        source_id = analysis_index.add_entity(
            "ddl_schema_source",
            source_path.lower() or str(result.get("source_name", "ddl")).lower(),
            str(result.get("source_name") or Path(source_path).name or "DDL schema"),
            attributes={
                "path": source_path,
                "summary": result.get("summary") or {},
            },
        )
        analysis_index.add_relation(manifest_id, "indexes_ddl_schema_source", source_id)
        for struct in result.get("structs") or []:
            struct_name = str(struct.get("name") or "RecoveredStruct")
            struct_key = f"{source_path}:{struct_name}".lower()
            struct_id = analysis_index.add_entity(
                "ddl_struct",
                struct_key,
                struct_name,
                attributes={
                    "kind": struct.get("kind"),
                    "field_count": struct.get("field_count"),
                    "confidence": struct.get("confidence"),
                    "estimated_size": struct.get("estimated_size"),
                    "estimated_size_hex": struct.get("estimated_size_hex"),
                    "layout_confidence": struct.get("layout_confidence"),
                    "source_path": source_path,
                    "fields": struct.get("fields") or [],
                },
            )
            analysis_index.add_relation(target_id, target_relation, struct_id)
            analysis_index.add_relation(source_id, "declares_ddl_struct", struct_id)
            for index, field in enumerate(struct.get("fields") or []):
                field_name = str(field.get("name") or f"field_{index}")
                field_id = analysis_index.add_entity(
                    "ddl_field",
                    f"{struct_key}:{field_name}".lower(),
                    f"{struct_name}.{field_name}",
                    attributes={
                        **field,
                        "ordinal": index,
                        "struct": struct_name,
                        "source_path": source_path,
                    },
                )
                analysis_index.add_relation(struct_id, "has_field", field_id)


def _empty_result(*, source_name: str, source_path: str, notes: list[str] | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "source_name": source_name,
        "source_path": source_path,
        "structs": [],
        "enums": [],
        "summary": {"struct_count": 0, "field_count": 0, "enum_count": 0},
        "notes": notes or [],
    }


def _strip_comments(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*?$", "", without_blocks, flags=re.MULTILINE)


def _parse_enums(text: str) -> list[dict[str, Any]]:
    enums: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _ENUM_RE.finditer(text):
        name = _clean_type_name(match.group("name"))
        if not name or name.lower() in seen:
            continue
        values: list[dict[str, str]] = []
        for raw in re.split(r",|\n", match.group("body")):
            candidate = raw.strip().strip(";")
            if not candidate or candidate.startswith("#"):
                continue
            value_match = re.match(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(?P<value>[^,]+))?$", candidate)
            if not value_match:
                continue
            values.append(
                {
                    "name": value_match.group("name"),
                    "value": (value_match.group("value") or "").strip(),
                }
            )
        if values:
            seen.add(name.lower())
            enums.append({"name": name, "values": values, "value_count": len(values), "confidence": 0.9})
    return enums


def _parse_fields(body: str) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for statement in _split_field_statements(body):
        field = _parse_field_statement(statement)
        if field:
            fields.append(field)
    return _dedupe_fields(fields)


def _split_field_statements(body: str) -> list[str]:
    normalized = re.sub(r"\b(optional|required|readonly|const)\b", "", body)
    normalized = re.sub(r"\b(GENERATED_BODY|GENERATED_USTRUCT_BODY|GENERATED_UCLASS_BODY)\s*\([^)]*\)?", "", normalized)
    parts: list[str] = []
    for chunk in re.split(r";|\n", normalized):
        candidate = chunk.strip().strip(",")
        if not candidate:
            continue
        if "{" in candidate or "}" in candidate:
            continue
        if re.match(r"^(if|for|while|switch|return|using|typedef|template)\b", candidate):
            continue
        parts.append(candidate)
    return parts


def _parse_field_statement(statement: str) -> dict[str, Any] | None:
    is_repeated = bool(re.search(r"\brepeated\b", statement))
    offset_hint = _extract_offset_hint(statement)
    size_hint = _extract_size_hint(statement)
    cleaned = re.sub(r"\b(?:UPROPERTY|UFUNCTION|USTRUCT|UCLASS|GENERATED_BODY|GENERATED_USTRUCT_BODY)\s*\([^)]*\)", "", statement)
    cleaned = re.sub(r"\brepeated\b", "", cleaned)
    cleaned = _normalize_flatbuffers_vector_field(cleaned)
    cleaned = re.sub(r"@\w+(?:\([^)]*\))?", "", cleaned)
    cleaned = re.sub(r"@\s*(?:0x[0-9A-Fa-f]+|\d+)", "", cleaned)
    cleaned = re.sub(r"\[(?:offset|ofs|field_offset)\s*[:=]\s*[^]]+\]", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b(?:offset|ofs|field_offset)\s*[:=]\s*(?:0x[0-9A-Fa-f]+|\d+)", "", cleaned)
    cleaned = re.sub(r"\b(?:size|byte_size|sizeof)\s*[:=]\s*(?:0x[0-9A-Fa-f]+|\d+)", "", cleaned)
    cleaned = re.sub(r"^\s*(?:0x[0-9A-Fa-f]+|\d{1,5})\s+", "", cleaned)
    cleaned = re.sub(r"\s+\([^)]*\)\s*(?==|$)", "", cleaned)
    cleaned = re.sub(r"\s+\[[^]]*\]\s*$", "", cleaned)
    cleaned = cleaned.strip()
    if not cleaned:
        return None

    match = _NAME_FIRST_FIELD_RE.match(cleaned) or _TYPE_FIRST_FIELD_RE.match(cleaned)
    if not match:
        return None
    field_type = _normalize_type(match.group("type"))
    field_name = match.group("name")
    if not _is_identifier(field_name) or _looks_like_type(field_name):
        return None
    if not _is_reasonable_type(field_type):
        return None
    result: dict[str, Any] = {
        "name": field_name,
        "type": field_type,
        "array": (match.group("array") or "").strip(),
        "default": (match.group("default") or "").strip(),
    }
    if is_repeated:
        result["array"] = result.get("array") or "dynamic"
    if result.get("default"):
        field_id = _extract_numeric_field_id(str(result["default"]))
        if field_id is not None:
            result["field_id"] = field_id
            result["default"] = ""
    if offset_hint:
        result["offset_hint"] = offset_hint
    if size_hint:
        result["declared_size"] = size_hint
    return {key: value for key, value in result.items() if value not in ("", None)}


def _normalize_flatbuffers_vector_field(statement: str) -> str:
    return re.sub(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*\[\s*(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*)\s*\]",
        lambda match: f"{match.group('name')}:{match.group('type')}[dynamic]",
        statement,
    )


def _extract_numeric_field_id(value: str) -> int | None:
    cleaned = re.sub(r"\[[^]]*\]", "", value).strip()
    if re.fullmatch(r"\d+", cleaned):
        return int(cleaned)
    return None


def _parse_compact_records(text: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for match in _COMPACT_RECORD_RE.finditer(text):
        struct_name = _clean_type_name(match.group("struct"))
        field_name = match.group("field")
        if not struct_name or not _is_identifier(field_name):
            continue
        grouped.setdefault(struct_name, []).append(
            {
                "name": field_name,
                "type": _normalize_type(match.group("type")),
            }
        )
    structs: list[dict[str, Any]] = []
    for name, fields in grouped.items():
        fields = _dedupe_fields(fields)
        if len(fields) < 2:
            continue
        structs.append(
            {
                "name": name,
                "kind": "inferred_record",
                "fields": fields,
                "field_count": len(fields),
                "confidence": min(0.85, 0.55 + len(fields) * 0.06),
            }
        )
    return structs


def _parse_tabular_records(text: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for match in _TABULAR_FIELD_RE.finditer(text):
        struct_name = _clean_type_name(match.group("struct"))
        field_name = match.group("field")
        field_type = _normalize_type(match.group("type"))
        if not struct_name or not _is_identifier(field_name) or not _is_reasonable_type(field_type):
            continue
        field: dict[str, Any] = {"name": field_name, "type": field_type}
        if match.group("offset"):
            field["offset_hint"] = match.group("offset")
        if match.group("size"):
            parsed_size = _parse_int(match.group("size"))
            if parsed_size is not None:
                field["declared_size"] = parsed_size
        grouped.setdefault(struct_name, []).append(field)
    structs: list[dict[str, Any]] = []
    for name, fields in grouped.items():
        fields = _dedupe_fields(fields)
        if len(fields) < 2:
            continue
        structs.append(
            {
                "name": name,
                "kind": "tabular_reflection",
                "fields": fields,
                "field_count": len(fields),
                "confidence": min(0.9, 0.62 + len(fields) * 0.05),
            }
        )
    return structs


def _infer_structs_from_string_table(strings: list[str]) -> list[dict[str, Any]]:
    cleaned = [sanitize_text(value).strip() for value in strings if 1 <= len(sanitize_text(value).strip()) <= 128]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for index, value in enumerate(cleaned[:-2]):
        if not _looks_like_struct_name(value):
            continue
        fields: list[dict[str, Any]] = []
        window = cleaned[index + 1 : index + 40]
        cursor = 0
        while cursor + 1 < len(window):
            first = window[cursor]
            second = window[cursor + 1]
            if _looks_like_type(first) and _looks_like_field_name(second):
                field, consumed = _string_table_field(second, first, window[cursor + 2 :])
                fields.append(field)
                cursor += consumed + 2
                continue
            if _looks_like_field_name(first) and _looks_like_type(second):
                field, consumed = _string_table_field(first, second, window[cursor + 2 :])
                fields.append(field)
                cursor += consumed + 2
                continue
            tuple_value = _parse_string_table_tuple(first)
            if tuple_value:
                fields.append(tuple_value)
                cursor += 1
                continue
            cursor += 1
        fields = _dedupe_fields(fields)
        if len(fields) >= 2:
            grouped[value] = fields
    structs: list[dict[str, Any]] = []
    for name, fields in list(grouped.items())[:64]:
        structs.append(
            _finalize_struct(
                {
                    "name": _clean_type_name(name),
                    "kind": "inferred_string_table",
                    "fields": fields,
                    "field_count": len(fields),
                    "confidence": min(0.75, 0.45 + len(fields) * 0.05),
                }
            )
        )
    return structs


def _string_table_field(name: str, field_type: str, rest: list[str]) -> tuple[dict[str, Any], int]:
    field: dict[str, Any] = {"name": name, "type": _normalize_type(field_type)}
    consumed = 0
    if rest:
        first = _parse_int(rest[0])
        second = _parse_int(rest[1]) if len(rest) > 1 else None
        if first is not None and second is not None:
            field["offset_hint"] = f"0x{first:x}"
            field["declared_size"] = second
            consumed = 2
        elif first is not None and first <= 0x10000:
            field["offset_hint"] = f"0x{first:x}"
            consumed = 1
    return field, consumed


def _parse_string_table_tuple(value: str) -> dict[str, Any] | None:
    parts = [part.strip() for part in re.split(r"\||,|;", value) if part.strip()]
    if len(parts) < 2:
        return None
    if len(parts) >= 3 and _looks_like_field_name(parts[0]) and _is_reasonable_type(parts[1]):
        field: dict[str, Any] = {"name": parts[0], "type": _normalize_type(parts[1])}
        offset = _parse_int(parts[2])
        if offset is not None:
            field["offset_hint"] = f"0x{offset:x}"
        size = _parse_int(parts[3]) if len(parts) > 3 else None
        if size is not None:
            field["declared_size"] = size
        return field
    parsed = _parse_field_tuple(value)
    if parsed:
        name, field_type = parsed
        return {"name": name, "type": _normalize_type(field_type)}
    return None


def _summary(structs: list[dict[str, Any]], enums: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "struct_count": len(structs),
        "field_count": sum(len(struct.get("fields") or []) for struct in structs),
        "enum_count": len(enums),
        "layout_count": sum(1 for struct in structs if struct.get("estimated_size") is not None),
    }


def _confidence(text: str, fields: list[dict[str, Any]]) -> float:
    confidence = 0.5 + min(len(fields), 8) * 0.04
    lowered = text.lower()
    if any(marker in lowered for marker in DDL_NAME_MARKERS):
        confidence += 0.1
    if any(_looks_like_type(str(field.get("type", ""))) for field in fields):
        confidence += 0.1
    return round(min(confidence, 0.95), 2)


def _clean_type_name(value: str) -> str:
    value = value.strip().split("::")[-1]
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not value or not _is_identifier(value):
        return ""
    return value


def _normalize_type(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).replace(" *", "*").replace(" &", "&")


def _is_identifier(value: str) -> bool:
    return bool(_IDENT_RE.match(value))


def _looks_like_type(value: str) -> bool:
    normalized = _normalize_type(value).lower().strip("*&")
    return normalized in DDL_TYPE_TOKENS or normalized.endswith("_t") or "::" in value


def _looks_like_struct_name(value: str) -> bool:
    if not _is_identifier(value) or _looks_like_type(value):
        return False
    return bool(re.match(r"^[A-Z][A-Za-z0-9_]{2,}$", value) or value.endswith("_t"))


def _looks_like_field_name(value: str) -> bool:
    if not _is_identifier(value) or _looks_like_type(value):
        return False
    return bool(re.match(r"^[a-z_][A-Za-z0-9_]{1,}$", value))


def _is_reasonable_type(value: str) -> bool:
    if not value or len(value) > 80:
        return False
    if any(token in value for token in ("(", ")", "{", "}", ";")):
        return False
    return bool(re.search(r"[A-Za-z_]", value))


def _dedupe_fields(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for field in fields:
        name = str(field.get("name") or "")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        result.append(field)
    return result


def _enrich_field_layout(field: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(field)
    field_type = str(enriched.get("type") or "")
    cxx_type = _to_cpp_type(field_type)
    enriched["cxx_type"] = cxx_type
    array_count = _array_count(enriched.get("array"))
    if array_count is not None:
        enriched["array_count"] = array_count
    elif str(enriched.get("array") or "").strip():
        enriched["dynamic_array"] = True
    declared_size = _parse_int(enriched.get("declared_size"))
    if declared_size is not None:
        enriched["estimated_size"] = declared_size
    else:
        size, alignment = _estimate_type_layout(field_type)
        if size is not None:
            if enriched.get("dynamic_array"):
                enriched["estimated_size"] = 24
                enriched["estimated_alignment"] = 8
            else:
                enriched["estimated_size"] = size * (array_count or 1)
                enriched["estimated_alignment"] = alignment
    offset = _parse_int(enriched.get("offset_hint"))
    if offset is not None:
        enriched["offset"] = offset
        enriched["offset_hex"] = f"0x{offset:x}"
        enriched["offset_source"] = "explicit"
    return enriched


def _assign_field_offsets(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cursor = 0
    for field in fields:
        size = _parse_int(field.get("estimated_size")) or 0
        alignment = _parse_int(field.get("estimated_alignment")) or min(max(size, 1), 8)
        if "offset" in field:
            cursor = max(cursor, int(field["offset"]) + size)
            continue
        offset = _align_up(cursor, alignment)
        field["offset"] = offset
        field["offset_hex"] = f"0x{offset:x}"
        field["offset_source"] = "estimated"
        cursor = offset + size
    return fields


def _estimate_struct_size(fields: list[dict[str, Any]]) -> int | None:
    if not fields:
        return None
    max_end = 0
    max_align = 1
    saw_sized_field = False
    for field in fields:
        offset = _parse_int(field.get("offset"))
        size = _parse_int(field.get("estimated_size"))
        alignment = _parse_int(field.get("estimated_alignment")) or 1
        max_align = max(max_align, alignment)
        if offset is None or size is None:
            continue
        saw_sized_field = True
        max_end = max(max_end, offset + size)
    if not saw_sized_field:
        return None
    return _align_up(max_end, max_align)


def _estimate_type_layout(value: str) -> tuple[int | None, int]:
    normalized = _normalize_type(value).lower().strip("*&")
    if normalized in TYPE_LAYOUTS:
        return TYPE_LAYOUTS[normalized]
    if normalized.endswith("_t") and normalized[:-2] in TYPE_LAYOUTS:
        return TYPE_LAYOUTS[normalized[:-2]]
    if "*" in value or "&" in value:
        return 8, 8
    return None, 1


def _array_count(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", text):
        return _parse_int(text)
    return None


def _align_up(value: int, alignment: int) -> int:
    alignment = max(1, int(alignment))
    return ((int(value) + alignment - 1) // alignment) * alignment


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _extract_offset_hint(statement: str) -> str:
    match = re.search(r"(?:offset|ofs|field_offset)\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)", statement, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"@\s*(0x[0-9A-Fa-f]+|\d+)", statement)
    if match:
        return match.group(1)
    match = re.search(r"^\s*(0x[0-9A-Fa-f]+|\d{1,5})\s+", statement)
    return match.group(1) if match else ""


def _extract_size_hint(statement: str) -> int | None:
    match = re.search(r"(?:size|byte_size|sizeof)\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)", statement, re.IGNORECASE)
    return _parse_int(match.group(1)) if match else None


def _parse_field_tuple(value: str) -> tuple[str, str] | None:
    parts = [part.strip() for part in re.split(r"[:=,]", value) if part.strip()]
    if len(parts) < 2:
        return None
    if _looks_like_type(parts[0]) and _is_identifier(parts[1]):
        return parts[1], parts[0]
    if _is_identifier(parts[0]) and _is_reasonable_type(parts[1]):
        return parts[0], parts[1]
    return None


def _unique_output_path(output_dir: Path, filename: str, used_names: set[str]) -> Path:
    stem = safe_slug(Path(filename).stem)
    suffix = Path(filename).suffix or ".hpp"
    candidate_name = f"{stem}{suffix}"
    counter = 2
    while candidate_name.lower() in used_names or (output_dir / candidate_name).exists():
        candidate_name = f"{stem}_{counter}{suffix}"
        counter += 1
    used_names.add(candidate_name.lower())
    return output_dir / candidate_name


def _render_enum_header(enum: dict[str, Any], source_name: str) -> str:
    name = _clean_type_name(str(enum.get("name") or "RecoveredEnum")) or "RecoveredEnum"
    lines = [
        "#pragma once",
        "",
        f"// Recovered DDL enum from {source_name}.",
        f"enum class {name} {{",
    ]
    for value in enum.get("values") or []:
        value_name = _clean_type_name(str(value.get("name") or "Value")) or "Value"
        assignment = f" = {value.get('value')}" if value.get("value") else ""
        lines.append(f"    {value_name}{assignment},")
    lines.extend(["};", ""])
    return "\n".join(lines)


def _render_struct_header(struct: dict[str, Any], source_name: str) -> str:
    name = _clean_type_name(str(struct.get("name") or "RecoveredStruct")) or "RecoveredStruct"
    lines = [
        "#pragma once",
        "#include <array>",
        "#include <cstdint>",
        "#include <string>",
        "#include <vector>",
        "",
        f"// Recovered DDL struct from {source_name}.",
        f"// Confidence: {struct.get('confidence', 'unknown')}",
        f"// Estimated layout size: {struct.get('estimated_size_hex', 'unknown')}",
        f"struct {name} {{",
    ]
    for field in struct.get("fields") or []:
        field_name = _clean_type_name(str(field.get("name") or "field")) or "field"
        field_type = str(field.get("cxx_type") or _to_cpp_type(str(field.get("type") or "uint8_t")))
        array = str(field.get("array") or "").strip()
        comments: list[str] = []
        if field.get("offset_hex"):
            comments.append(f"offset {field.get('offset_hex')} ({field.get('offset_source', 'unknown')})")
        if field.get("estimated_size") is not None:
            comments.append(f"size {field.get('estimated_size')}")
        comment = f" // {', '.join(comments)}" if comments else ""
        if array and not _array_count(array):
            lines.append(f"    std::vector<{field_type}> {field_name};{comment}")
        elif array:
            lines.append(f"    {field_type} {field_name}[{array}];{comment}")
        else:
            lines.append(f"    {field_type} {field_name};{comment}")
    lines.extend(["};", ""])
    return "\n".join(lines)


def _to_cpp_type(value: str) -> str:
    normalized = _normalize_type(value)
    tarray_match = re.match(r"(?i)^TArray\s*<\s*(?P<inner>[^>]+)\s*>$", normalized)
    if tarray_match:
        return f"std::vector<{_to_cpp_type(tarray_match.group('inner'))}>"
    mapping = {
        "bool": "bool",
        "boolean": "bool",
        "byte": "uint8_t",
        "char": "char",
        "double": "double",
        "f32": "float",
        "f64": "double",
        "float": "float",
        "hash": "uint32_t",
        "hash32": "uint32_t",
        "hash64": "uint64_t",
        "half": "uint16_t",
        "i8": "int8_t",
        "i16": "int16_t",
        "i32": "int32_t",
        "i64": "int64_t",
        "int8": "int8_t",
        "int16": "int16_t",
        "int32": "int32_t",
        "int64": "int64_t",
        "int8_t": "int8_t",
        "int16_t": "int16_t",
        "int32_t": "int32_t",
        "int64_t": "int64_t",
        "sint32": "int32_t",
        "sint64": "int64_t",
        "sfixed32": "int32_t",
        "sfixed64": "int64_t",
        "s8": "int8_t",
        "s16": "int16_t",
        "s32": "int32_t",
        "s64": "int64_t",
        "string": "std::string",
        "fname": "std::string",
        "fstring": "std::string",
        "fvector2d": "std::array<float, 2>",
        "fvector": "std::array<float, 3>",
        "fvector4": "std::array<float, 4>",
        "frotator": "std::array<float, 3>",
        "u8": "uint8_t",
        "u16": "uint16_t",
        "u32": "uint32_t",
        "u64": "uint64_t",
        "uint": "uint32_t",
        "uint8": "uint8_t",
        "uint16": "uint16_t",
        "uint32": "uint32_t",
        "uint64": "uint64_t",
        "uint8_t": "uint8_t",
        "uint16_t": "uint16_t",
        "uint32_t": "uint32_t",
        "uint64_t": "uint64_t",
        "fixed32": "uint32_t",
        "fixed64": "uint64_t",
        "mat3": "std::array<float, 9>",
        "mat4": "std::array<float, 16>",
        "matrix": "std::array<float, 16>",
        "quaternion": "std::array<float, 4>",
        "vec2": "std::array<float, 2>",
        "vec3": "std::array<float, 3>",
        "vec4": "std::array<float, 4>",
        "vector2": "std::array<float, 2>",
        "vector3": "std::array<float, 3>",
        "vector4": "std::array<float, 4>",
    }
    return mapping.get(normalized.lower(), re.sub(r"[^A-Za-z0-9_:<>,*& ]", "_", normalized) or "uint8_t")
