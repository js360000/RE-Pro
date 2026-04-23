from __future__ import annotations

import struct
from pathlib import Path

from .utils import sanitize_text


RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200


def parse_resources_arsc(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return parse_resources_arsc_bytes(data)


def parse_resources_arsc_bytes(data: bytes) -> dict[str, object] | None:
    if len(data) < 12:
        return None

    chunk_type, header_size, total_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_TABLE_TYPE or header_size < 12 or total_size > len(data):
        return None

    package_count = struct.unpack_from("<I", data, 8)[0]
    packages: list[dict[str, object]] = []
    package_names: list[str] = []

    cursor = header_size
    chunk_count = 1
    while cursor + 8 <= min(total_size, len(data)):
        child_type, child_header_size, child_size = struct.unpack_from("<HHI", data, cursor)
        if child_header_size < 8 or child_size < child_header_size or cursor + child_size > len(data):
            break
        chunk_count += 1
        if child_type == RES_TABLE_PACKAGE_TYPE and child_header_size >= 0x120 and cursor + 0x120 <= len(data):
            package_id = struct.unpack_from("<I", data, cursor + 8)[0]
            raw_name = data[cursor + 12 : cursor + 12 + 256]
            package_name = _decode_utf16le_name(raw_name)
            package_info = {
                "id": package_id,
                "name": package_name,
            }
            packages.append(package_info)
            if package_name:
                package_names.append(package_name)
        cursor += child_size

    return {
        "package_count": package_count,
        "chunk_count": chunk_count,
        "package_names": package_names,
        "packages": packages,
    }


def _decode_utf16le_name(raw_name: bytes) -> str:
    try:
        decoded = raw_name.decode("utf-16le", errors="ignore")
    except UnicodeDecodeError:
        return ""
    return sanitize_text(decoded.split("\x00", 1)[0])
