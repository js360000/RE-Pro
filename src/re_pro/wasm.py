from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
    13: "tag",
}


@dataclass
class WasmSection:
    section_id: int
    name: str
    size: int
    offset: int
    custom_name: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.section_id,
            "name": self.name,
            "size": self.size,
            "offset": self.offset,
            "custom_name": self.custom_name,
        }


def is_wasm_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x00asm"
    except OSError:
        return False


def parse_wasm_module(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 8 or data[:4] != b"\x00asm":
        return None

    version = int.from_bytes(data[4:8], "little")
    offset = 8
    sections: list[WasmSection] = []
    imports: list[dict[str, object]] = []
    exports: list[dict[str, object]] = []
    custom_sections: list[dict[str, object]] = []
    producers: dict[str, list[dict[str, str]]] = {}
    names: list[str] = []
    source_mapping_url = ""

    while offset < len(data):
        section_offset = offset
        try:
            section_id, offset = _read_u8(data, offset)
            payload_size, offset = _read_uleb128(data, offset)
        except ValueError:
            break
        payload_end = offset + payload_size
        if payload_end > len(data):
            break
        payload_offset = offset
        payload = data[payload_offset:payload_end]
        section_name = SECTION_NAMES.get(section_id, f"section_{section_id}")
        custom_name = ""
        if section_id == 0:
            try:
                custom_name, cursor = _read_name(payload, 0)
            except ValueError:
                custom_name = ""
                cursor = len(payload)
            custom_sections.append(
                {
                    "name": custom_name,
                    "size": payload_size,
                }
            )
            if custom_name == "name":
                names.extend(_parse_name_section(payload[cursor:]))
            elif custom_name == "producers":
                producers = _parse_producers_section(payload[cursor:])
            elif custom_name == "sourceMappingURL":
                try:
                    source_mapping_url, _ = _read_name(payload, cursor)
                except ValueError:
                    source_mapping_url = ""
        elif section_id == 2:
            imports = _parse_import_section(payload)
        elif section_id == 7:
            exports = _parse_export_section(payload)
        sections.append(
            WasmSection(
                section_id=section_id,
                name=section_name,
                size=payload_size,
                offset=section_offset,
                custom_name=custom_name,
            )
        )
        offset = payload_end

    return {
        "version": version,
        "sections": [section.to_dict() for section in sections],
        "imports": imports,
        "exports": exports,
        "custom_sections": custom_sections,
        "producers": producers,
        "name_entries": names,
        "source_mapping_url": source_mapping_url,
    }


def find_adjacent_wasm_map(path: Path, module_info: dict[str, object]) -> Path | None:
    candidates: list[Path] = []
    source_mapping_url = str(module_info.get("source_mapping_url") or "").strip()
    if source_mapping_url:
        candidates.append(path.parent / source_mapping_url)
    candidates.append(path.with_suffix(path.suffix + ".map"))
    candidates.append(path.with_suffix(".map"))
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def describe_wasm_toolchains(module_info: dict[str, object]) -> list[str]:
    producers = module_info.get("producers") or {}
    imports = module_info.get("imports") or []
    exports = module_info.get("exports") or []
    strings = json.dumps(module_info, ensure_ascii=False).lower()
    frameworks: list[str] = ["WebAssembly (WASM)"]
    if "emscripten" in strings:
        frameworks.append("WebAssembly toolchain: Emscripten")
    if "__wbindgen" in strings or "wbindgen" in strings:
        frameworks.append("WebAssembly toolchain: wasm-bindgen")
    if "assemblyscript" in strings:
        frameworks.append("WebAssembly toolchain: AssemblyScript")
    if "tinygo" in strings:
        frameworks.append("WebAssembly toolchain: TinyGo")
    if "go" in {entry.get("name", "").lower() for entry in producers.get("language", [])}:
        frameworks.append("WebAssembly language: Go")
    if "rust" in {entry.get("name", "").lower() for entry in producers.get("language", [])}:
        frameworks.append("WebAssembly language: Rust")
    if "c" in {entry.get("name", "").lower() for entry in producers.get("language", [])} or "c++" in {
        entry.get("name", "").lower() for entry in producers.get("language", [])
    }:
        frameworks.append("WebAssembly language: C/C++")
    if any(entry.get("module") == "wasi_snapshot_preview1" for entry in imports if isinstance(entry, dict)):
        frameworks.append("WebAssembly ABI: WASI")
    return frameworks


def _parse_import_section(data: bytes) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    try:
        count, offset = _read_uleb128(data, 0)
    except ValueError:
        return items
    for _ in range(count):
        try:
            module, offset = _read_name(data, offset)
            name, offset = _read_name(data, offset)
            kind, offset = _read_u8(data, offset)
        except ValueError:
            break
        item = {"module": module, "name": name, "kind": _external_kind_name(kind)}
        try:
            offset = _skip_import_type(data, offset, kind)
        except ValueError:
            break
        items.append(item)
    return items


def _parse_export_section(data: bytes) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    try:
        count, offset = _read_uleb128(data, 0)
    except ValueError:
        return items
    for _ in range(count):
        try:
            name, offset = _read_name(data, offset)
            kind, offset = _read_u8(data, offset)
            index, offset = _read_uleb128(data, offset)
        except ValueError:
            break
        items.append({"name": name, "kind": _external_kind_name(kind), "index": index})
    return items


def _parse_name_section(data: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset < len(data):
        try:
            subsection_id, offset = _read_u8(data, offset)
            subsection_size, offset = _read_uleb128(data, offset)
        except ValueError:
            break
        payload = data[offset : offset + subsection_size]
        offset += subsection_size
        if subsection_id not in {1, 2, 4, 5, 7, 8, 9, 10, 11}:
            continue
        try:
            count, cursor = _read_uleb128(payload, 0)
        except ValueError:
            continue
        for _ in range(count):
            try:
                _, cursor = _read_uleb128(payload, cursor)
                name, cursor = _read_name(payload, cursor)
            except ValueError:
                break
            names.append(name)
    return names


def _parse_producers_section(data: bytes) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = {}
    try:
        field_count, offset = _read_uleb128(data, 0)
    except ValueError:
        return result
    for _ in range(field_count):
        try:
            field_name, offset = _read_name(data, offset)
            value_count, offset = _read_uleb128(data, offset)
        except ValueError:
            break
        values: list[dict[str, str]] = []
        for _ in range(value_count):
            try:
                name, offset = _read_name(data, offset)
                version, offset = _read_name(data, offset)
            except ValueError:
                break
            values.append({"name": name, "version": version})
        result[field_name] = values
    return result


def _skip_import_type(data: bytes, offset: int, kind: int) -> int:
    if kind == 0:
        _, offset = _read_uleb128(data, offset)
        return offset
    if kind == 1:
        _, offset = _read_u8(data, offset)
        flags, offset = _read_uleb128(data, offset)
        _, offset = _read_uleb128(data, offset)
        if flags & 0x01:
            _, offset = _read_uleb128(data, offset)
        return offset
    if kind == 2:
        flags, offset = _read_uleb128(data, offset)
        _, offset = _read_uleb128(data, offset)
        if flags & 0x01:
            _, offset = _read_uleb128(data, offset)
        return offset
    if kind == 3:
        _, offset = _read_u8(data, offset)
        _, offset = _read_u8(data, offset)
        return offset
    if kind == 4:
        _, offset = _read_uleb128(data, offset)
        return offset
    raise ValueError("Unknown import kind")


def _external_kind_name(kind: int) -> str:
    return {
        0: "function",
        1: "table",
        2: "memory",
        3: "global",
        4: "tag",
    }.get(kind, str(kind))


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of data")
    return data[offset], offset + 1


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Unexpected end of LEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift > 35:
            raise ValueError("LEB128 too large")


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    length, offset = _read_uleb128(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("Unexpected end of name")
    return data[offset:end].decode("utf-8", errors="ignore"), end
