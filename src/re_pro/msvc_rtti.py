from __future__ import annotations

import re
import struct
from pathlib import Path

from .utils import pe_offset_to_rva, pe_rva_to_offset


TYPE_NAME_PATTERN = re.compile(rb"\.\?A[VUTW][^\x00\r\n]{3,220}?@@")


def recover_msvc_rtti(
    path: Path,
    pe_metadata: dict[str, object] | None,
    pe_sections: list[dict[str, object]],
) -> dict[str, object] | None:
    if pe_metadata is None or not pe_sections:
        return None

    machine = str(pe_metadata.get("machine", "")).lower()
    if machine not in {"x64", "x86"}:
        return None

    try:
        data = path.read_bytes()
    except OSError:
        return None

    image_base = int(pe_metadata.get("image_base", 0) or (0x140000000 if machine == "x64" else 0x400000))
    pointer_size = 8 if machine == "x64" else 4
    type_descriptors = _scan_type_descriptors(data, pe_sections, pointer_size)
    if not type_descriptors:
        return None

    if machine == "x64":
        col_entries = _scan_complete_object_locators_x64(data, pe_sections, type_descriptors)
        vtables = _scan_vtables(data, pe_sections, image_base, col_entries, pointer_size)
        classes = _build_class_entries(type_descriptors, col_entries, vtables, machine)
    else:
        col_entries = []
        vtables = []
        classes = _build_class_entries(type_descriptors, col_entries, vtables, machine)

    if not classes:
        return None

    return {
        "machine": machine,
        "image_base": f"0x{image_base:x}",
        "type_descriptor_count": len(type_descriptors),
        "complete_object_locator_count": len(col_entries),
        "vtable_count": len(vtables),
        "class_count": len(classes),
        "classes": classes,
        "vtables": vtables,
    }


def _scan_type_descriptors(
    data: bytes,
    pe_sections: list[dict[str, object]],
    pointer_size: int,
) -> dict[int, dict[str, object]]:
    descriptors: dict[int, dict[str, object]] = {}
    for match in TYPE_NAME_PATTERN.finditer(data):
        name_offset = match.start()
        descriptor_offset = name_offset - (pointer_size * 2)
        if descriptor_offset < 0:
            continue
        descriptor_rva = pe_offset_to_rva(descriptor_offset, pe_sections)
        if descriptor_rva is None:
            continue
        mangled_name = match.group(0).decode("ascii", errors="ignore")
        demangled_name, kind = demangle_msvc_type_name(mangled_name)
        if not demangled_name:
            continue
        descriptors[descriptor_rva] = {
            "rva": f"0x{descriptor_rva:x}",
            "offset": descriptor_offset,
            "mangled_name": mangled_name,
            "demangled_name": demangled_name,
            "kind": kind,
        }
    return descriptors


def _scan_complete_object_locators_x64(
    data: bytes,
    pe_sections: list[dict[str, object]],
    type_descriptors: dict[int, dict[str, object]],
) -> list[dict[str, object]]:
    section_ranges = _candidate_rtti_sections(pe_sections)
    type_rvas = set(type_descriptors)
    complete_object_locators: dict[int, dict[str, object]] = {}

    for section in section_ranges:
        start = int(section.get("raw_offset", 0))
        size = int(section.get("raw_size", 0))
        end = min(start + size, len(data))
        for cursor in range(start, max(start, end - 24), 4):
            signature, offset, cd_offset, type_rva, class_rva, self_rva = struct.unpack_from("<IIIIII", data, cursor)
            if signature not in {0, 1}:
                continue
            if type_rva not in type_rvas:
                continue
            if pe_rva_to_offset(class_rva, pe_sections) is None:
                continue
            rva = pe_offset_to_rva(cursor, pe_sections)
            if rva is None:
                continue
            if self_rva not in {0, rva}:
                continue
            hierarchy = _parse_class_hierarchy_x64(data, class_rva, pe_sections, type_descriptors)
            if hierarchy is None:
                continue
            complete_object_locators[rva] = {
                "rva": f"0x{rva:x}",
                "offset": f"0x{cursor:x}",
                "signature": signature,
                "offset_from_top": offset,
                "constructor_displacement_offset": cd_offset,
                "type_descriptor_rva": f"0x{type_rva:x}",
                "class_hierarchy_rva": f"0x{class_rva:x}",
                "self_rva": f"0x{self_rva:x}",
                "class_name": str(type_descriptors[type_rva]["demangled_name"]),
                "mangled_name": str(type_descriptors[type_rva]["mangled_name"]),
                "base_classes": hierarchy["base_classes"],
                "inheritance_attributes": hierarchy["attributes"],
            }

    return sorted(complete_object_locators.values(), key=lambda item: item["class_name"])


def _parse_class_hierarchy_x64(
    data: bytes,
    class_hierarchy_rva: int,
    pe_sections: list[dict[str, object]],
    type_descriptors: dict[int, dict[str, object]],
) -> dict[str, object] | None:
    hierarchy_offset = pe_rva_to_offset(class_hierarchy_rva, pe_sections)
    if hierarchy_offset is None or hierarchy_offset + 16 > len(data):
        return None

    signature, attributes, base_count, base_array_rva = struct.unpack_from("<IIII", data, hierarchy_offset)
    if signature not in {0, 1} or base_count <= 0 or base_count > 64:
        return None

    base_array_offset = pe_rva_to_offset(base_array_rva, pe_sections)
    if base_array_offset is None or base_array_offset + (base_count * 4) > len(data):
        return None

    base_classes: list[str] = []
    for index in range(base_count):
        base_descriptor_rva = struct.unpack_from("<I", data, base_array_offset + (index * 4))[0]
        descriptor_offset = pe_rva_to_offset(base_descriptor_rva, pe_sections)
        if descriptor_offset is None or descriptor_offset + 28 > len(data):
            continue
        type_rva = struct.unpack_from("<I", data, descriptor_offset)[0]
        entry = type_descriptors.get(type_rva)
        if entry is None:
            continue
        base_name = str(entry["demangled_name"])
        if base_name not in base_classes:
            base_classes.append(base_name)

    if not base_classes:
        return None
    return {"base_classes": base_classes, "attributes": attributes}


def _scan_vtables(
    data: bytes,
    pe_sections: list[dict[str, object]],
    image_base: int,
    complete_object_locators: list[dict[str, object]],
    pointer_size: int,
) -> list[dict[str, object]]:
    col_by_va = {
        image_base + int(str(entry["rva"]), 16): entry
        for entry in complete_object_locators
    }
    candidate_sections = _candidate_rtti_sections(pe_sections)
    vtables: dict[int, dict[str, object]] = {}

    for section in candidate_sections:
        start = int(section.get("raw_offset", 0))
        size = int(section.get("raw_size", 0))
        end = min(start + size, len(data))
        for cursor in range(start, max(start, end - pointer_size), pointer_size):
            locator_pointer = _read_pointer(data, cursor, pointer_size)
            locator = col_by_va.get(locator_pointer)
            if locator is None:
                continue
            vtable_offset = cursor + pointer_size
            vtable_rva = pe_offset_to_rva(vtable_offset, pe_sections)
            if vtable_rva is None or vtable_rva in vtables:
                continue

            methods: list[dict[str, object]] = []
            for slot in range(256):
                entry_offset = vtable_offset + (slot * pointer_size)
                if entry_offset + pointer_size > len(data):
                    break
                method_pointer = _read_pointer(data, entry_offset, pointer_size)
                method_rva = method_pointer - image_base
                if not _is_executable_rva(method_rva, pe_sections):
                    break
                methods.append(
                    {
                        "slot": slot,
                        "address": f"0x{method_pointer:x}",
                        "rva": f"0x{method_rva:x}",
                    }
                )

            if not methods:
                continue

            vtables[vtable_rva] = {
                "class_name": locator["class_name"],
                "mangled_name": locator["mangled_name"],
                "complete_object_locator_rva": locator["rva"],
                "address": f"0x{image_base + vtable_rva:x}",
                "rva": f"0x{vtable_rva:x}",
                "method_count": len(methods),
                "methods": methods,
            }

    return sorted(vtables.values(), key=lambda item: (item["class_name"], item["rva"]))


def _build_class_entries(
    type_descriptors: dict[int, dict[str, object]],
    complete_object_locators: list[dict[str, object]],
    vtables: list[dict[str, object]],
    machine: str,
) -> list[dict[str, object]]:
    classes: dict[str, dict[str, object]] = {}
    for descriptor in type_descriptors.values():
        name = str(descriptor["demangled_name"])
        classes.setdefault(
            name,
            {
                "name": name,
                "mangled_name": descriptor["mangled_name"],
                "kind": descriptor["kind"],
                "type_descriptor_rva": descriptor["rva"],
                "base_classes": [],
                "complete_object_locator_rvas": [],
                "vtables": [],
                "methods": [],
                "machine": machine,
            },
        )

    for entry in complete_object_locators:
        class_entry = classes.setdefault(
            str(entry["class_name"]),
            {
                "name": entry["class_name"],
                "mangled_name": entry["mangled_name"],
                "kind": "class",
                "type_descriptor_rva": entry["type_descriptor_rva"],
                "base_classes": [],
                "complete_object_locator_rvas": [],
                "vtables": [],
                "methods": [],
                "machine": machine,
            },
        )
        for base_name in entry.get("base_classes", []):
            if base_name != class_entry["name"] and base_name not in class_entry["base_classes"]:
                class_entry["base_classes"].append(base_name)
        if entry["rva"] not in class_entry["complete_object_locator_rvas"]:
            class_entry["complete_object_locator_rvas"].append(entry["rva"])

    for vtable in vtables:
        class_entry = classes.setdefault(
            str(vtable["class_name"]),
            {
                "name": vtable["class_name"],
                "mangled_name": vtable["mangled_name"],
                "kind": "class",
                "type_descriptor_rva": "",
                "base_classes": [],
                "complete_object_locator_rvas": [],
                "vtables": [],
                "methods": [],
                "machine": machine,
            },
        )
        class_entry["vtables"].append(
            {
                "address": vtable["address"],
                "rva": vtable["rva"],
                "method_count": vtable["method_count"],
                "complete_object_locator_rva": vtable["complete_object_locator_rva"],
            }
        )
        known_methods = {
            (
                str(method.get("vtable_rva") or ""),
                int(method.get("slot", -1)),
                str(method.get("address") or ""),
            )
            for method in class_entry["methods"]
        }
        for method in vtable.get("methods", []):
            method_key = (
                str(vtable["rva"]),
                int(method.get("slot", -1)),
                str(method.get("address") or ""),
            )
            if method_key in known_methods:
                continue
            class_entry["methods"].append(
                {
                    "name": f"vf_{str(method['address']).replace('0x', '')}",
                    "slot": method["slot"],
                    "address": method["address"],
                    "rva": method["rva"],
                    "vtable_rva": vtable["rva"],
                }
            )
            known_methods.add(method_key)

    return sorted(
        classes.values(),
        key=lambda item: (-len(item["methods"]), -len(item["vtables"]), item["name"].lower()),
    )


def demangle_msvc_type_name(mangled_name: str) -> tuple[str, str]:
    if not mangled_name.startswith(".?A") or len(mangled_name) < 5:
        return "", "class"

    kind = "class"
    body = mangled_name[3:]
    if body.startswith("W4"):
        kind = "enum"
        body = body[2:]
    elif body.startswith("V"):
        kind = "class"
        body = body[1:]
    elif body.startswith("U"):
        kind = "struct"
        body = body[1:]
    elif body.startswith("T"):
        kind = "union"
        body = body[1:]
    else:
        body = body[1:]

    parts = [part for part in body.split("@") if part]
    if not parts:
        return "", kind
    normalized = [_normalize_msvc_fragment(part) for part in reversed(parts)]
    name = "::".join(fragment for fragment in normalized if fragment)
    return name, kind


def _normalize_msvc_fragment(fragment: str) -> str:
    value = fragment
    if value.startswith("?$"):
        value = value[2:]
    return value.replace("`anonymous namespace'", "anonymous_namespace")


def _candidate_rtti_sections(pe_sections: list[dict[str, object]]) -> list[dict[str, object]]:
    candidates = []
    for section in pe_sections:
        name = str(section.get("name", "")).lower()
        flags = {str(flag) for flag in section.get("flag_names", [])}
        if "EXECUTE" in flags:
            continue
        if name in {".rdata", ".data", ".pdata"} or ("READ" in flags and int(section.get("raw_size", 0)) > 0):
            candidates.append(section)
    return candidates


def _is_executable_rva(rva: int, pe_sections: list[dict[str, object]]) -> bool:
    if rva < 0:
        return False
    for section in pe_sections:
        virtual_address = int(section.get("virtual_address", 0))
        span = max(int(section.get("virtual_size", 0)), int(section.get("raw_size", 0)))
        if not (virtual_address <= rva < virtual_address + span):
            continue
        flags = {str(flag) for flag in section.get("flag_names", [])}
        if "EXECUTE" in flags:
            return True
        name = str(section.get("name", "")).lower()
        return name in {".text", "text", "code"}
    return False


def _read_pointer(data: bytes, offset: int, pointer_size: int) -> int:
    if pointer_size == 8:
        return struct.unpack_from("<Q", data, offset)[0]
    return struct.unpack_from("<I", data, offset)[0]
