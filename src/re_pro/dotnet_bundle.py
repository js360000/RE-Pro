from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

from .utils import ensure_dir, safe_output_path


BUNDLE_SIGNATURE = bytes.fromhex(
    "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae"
)
FILE_TYPE_NAMES = {
    0: "Unknown",
    1: "Assembly",
    2: "NativeBinary",
    3: "DepsJson",
    4: "RuntimeConfigJson",
    5: "Symbols",
}
HEADER_FLAG_NAMES = {
    1: "NetcoreApp3CompatMode",
}


def parse_dotnet_single_file_bundle(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None

    position = data.rfind(BUNDLE_SIGNATURE)
    if position < 8:
        return None

    header_offset = struct.unpack_from("<q", data, position - 8)[0]
    if header_offset <= 0 or header_offset >= len(data):
        return None

    cursor = header_offset
    try:
        major_version, minor_version = struct.unpack_from("<II", data, cursor)
        cursor += 8
        file_count = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        bundle_id, cursor = _read_binary_writer_string(data, cursor)
        deps_offset = deps_size = runtime_offset = runtime_size = 0
        flags = 0
        if major_version >= 2:
            deps_offset, deps_size, runtime_offset, runtime_size, flags = struct.unpack_from("<qqqqQ", data, cursor)
            cursor += 40
        entries: list[dict[str, object]] = []
        for _ in range(file_count):
            entry_offset, size = struct.unpack_from("<qq", data, cursor)
            cursor += 16
            compressed_size = 0
            if major_version >= 6:
                compressed_size = struct.unpack_from("<q", data, cursor)[0]
                cursor += 8
            file_type = data[cursor]
            cursor += 1
            relative_path, cursor = _read_binary_writer_string(data, cursor)
            entries.append(
                {
                    "relative_path": relative_path,
                    "offset": entry_offset,
                    "size": size,
                    "compressed_size": compressed_size,
                    "file_type": file_type,
                    "file_type_name": FILE_TYPE_NAMES.get(file_type, f"Unknown({file_type})"),
                }
            )
    except (IndexError, struct.error, UnicodeDecodeError, ValueError):
        return None

    return {
        "major_version": major_version,
        "minor_version": minor_version,
        "bundle_id": bundle_id,
        "header_offset": header_offset,
        "file_count": file_count,
        "deps_offset": deps_offset,
        "deps_size": deps_size,
        "runtime_config_offset": runtime_offset,
        "runtime_config_size": runtime_size,
        "flags": [name for bit, name in HEADER_FLAG_NAMES.items() if flags & bit],
        "flag_mask": hex(flags),
        "entries": entries,
    }


def extract_dotnet_single_file_bundle(path: Path, destination_root: Path) -> dict[str, object] | None:
    manifest = parse_dotnet_single_file_bundle(path)
    if manifest is None:
        return None

    try:
        data = path.read_bytes()
    except OSError:
        return None

    output_dir = ensure_dir(destination_root)
    files_dir = ensure_dir(output_dir / "files")
    manifest_path = output_dir / "bundle_manifest.json"

    extracted_entries: list[dict[str, object]] = []
    for entry in manifest["entries"]:
        relative_path = str(entry["relative_path"])
        destination = safe_output_path(files_dir, relative_path)
        ensure_dir(destination.parent)
        start = int(entry["offset"])
        stored_size = int(entry["compressed_size"] or entry["size"])
        blob = data[start : start + stored_size]
        if entry["compressed_size"]:
            try:
                payload = _decompress_entry(blob)
            except Exception as exc:
                extracted_entries.append({**entry, "destination": str(destination), "error": str(exc)})
                continue
        else:
            payload = blob
        destination.write_bytes(payload)
        extracted_entries.append({**entry, "destination": str(destination)})

    result = {
        **manifest,
        "extracted_entries": extracted_entries,
        "files_dir": str(files_dir),
        "manifest_path": str(manifest_path),
    }
    manifest_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _read_binary_writer_string(data: bytes, offset: int) -> tuple[str, int]:
    length, cursor = _read_7bit_encoded_int(data, offset)
    end = cursor + length
    if end > len(data):
        raise ValueError("String exceeds bundle bounds")
    return data[cursor:end].decode("utf-8"), end


def _read_7bit_encoded_int(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    cursor = offset
    while True:
        if cursor >= len(data):
            raise ValueError("Unexpected end of bundle while reading 7-bit integer")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7
        if shift >= 35:
            raise ValueError("Invalid 7-bit encoded integer in bundle")


def _decompress_entry(blob: bytes) -> bytes:
    attempts = [
        lambda: zlib.decompress(blob),
        lambda: zlib.decompress(blob, -zlib.MAX_WBITS),
        lambda: zlib.decompress(blob, zlib.MAX_WBITS | 32),
    ]
    errors: list[str] = []
    for attempt in attempts:
        try:
            return attempt()
        except zlib.error as exc:
            errors.append(str(exc))
    raise ValueError("; ".join(errors) if errors else "Unknown deflate decompression failure")
