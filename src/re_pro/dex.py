from __future__ import annotations

import struct
from pathlib import Path

DEX_MAGIC_PREFIX = b"dex\n"


def is_dex_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == DEX_MAGIC_PREFIX
    except OSError:
        return False


def parse_dex_metadata(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 112 or not data.startswith(DEX_MAGIC_PREFIX):
        return None

    version = data[4:7].decode("ascii", errors="ignore")
    endian_tag = struct.unpack_from("<I", data, 40)[0]
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 64)
    proto_ids_size, proto_ids_off = struct.unpack_from("<II", data, 72)
    field_ids_size, field_ids_off = struct.unpack_from("<II", data, 80)
    method_ids_size, method_ids_off = struct.unpack_from("<II", data, 88)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 96)

    strings = _parse_dex_strings(data, string_ids_size, string_ids_off)
    type_descriptors = _parse_type_descriptors(data, strings, type_ids_size, type_ids_off)
    class_descriptors = _parse_class_descriptors(data, type_descriptors, class_defs_size, class_defs_off)
    package_names = sorted(
        {
            descriptor[1 : descriptor.rfind("/")].replace("/", ".")
            for descriptor in class_descriptors
            if descriptor.startswith("L") and "/" in descriptor
        }
    )

    return {
        "version": version,
        "endian_tag": hex(endian_tag),
        "string_count": string_ids_size,
        "type_count": type_ids_size,
        "proto_count": proto_ids_size,
        "field_count": field_ids_size,
        "method_count": method_ids_size,
        "class_count": class_defs_size,
        "strings": strings[:200],
        "type_descriptors": type_descriptors[:200],
        "class_descriptors": class_descriptors[:200],
        "package_names": package_names[:100],
    }


def _parse_dex_strings(data: bytes, string_ids_size: int, string_ids_off: int) -> list[str]:
    results: list[str] = []
    for index in range(string_ids_size):
        entry_offset = string_ids_off + (index * 4)
        if entry_offset + 4 > len(data):
            break
        string_data_off = struct.unpack_from("<I", data, entry_offset)[0]
        try:
            _, cursor = _read_uleb128(data, string_data_off)
            value, _ = _read_mutf8(data, cursor)
        except ValueError:
            continue
        results.append(value)
    return results


def _parse_type_descriptors(data: bytes, strings: list[str], type_ids_size: int, type_ids_off: int) -> list[str]:
    results: list[str] = []
    for index in range(type_ids_size):
        entry_offset = type_ids_off + (index * 4)
        if entry_offset + 4 > len(data):
            break
        descriptor_idx = struct.unpack_from("<I", data, entry_offset)[0]
        if 0 <= descriptor_idx < len(strings):
            results.append(strings[descriptor_idx])
    return results


def _parse_class_descriptors(data: bytes, type_descriptors: list[str], class_defs_size: int, class_defs_off: int) -> list[str]:
    results: list[str] = []
    for index in range(class_defs_size):
        entry_offset = class_defs_off + (index * 32)
        if entry_offset + 4 > len(data):
            break
        class_idx = struct.unpack_from("<I", data, entry_offset)[0]
        if 0 <= class_idx < len(type_descriptors):
            results.append(type_descriptors[class_idx])
    return results


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Unexpected end of ULEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift > 35:
            raise ValueError("ULEB128 too large")


def _read_mutf8(data: bytes, offset: int) -> tuple[str, int]:
    buffer = bytearray()
    while True:
        if offset >= len(data):
            raise ValueError("Unexpected end of MUTF-8")
        byte = data[offset]
        offset += 1
        if byte == 0:
            return buffer.decode("utf-8", errors="ignore"), offset
        buffer.append(byte)
