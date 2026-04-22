from __future__ import annotations

import ctypes
import json
from dataclasses import dataclass
from pathlib import Path

from .utils import ensure_dir, sanitize_text, safe_slug

LOAD_LIBRARY_AS_DATAFILE = 0x00000002
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
_kernel32.LoadLibraryExW.restype = ctypes.c_void_p
_kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
_kernel32.FreeLibrary.restype = ctypes.c_bool
_kernel32.EnumResourceTypesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
_kernel32.EnumResourceTypesW.restype = ctypes.c_bool
_kernel32.EnumResourceNamesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
_kernel32.EnumResourceNamesW.restype = ctypes.c_bool
_kernel32.EnumResourceLanguagesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
_kernel32.EnumResourceLanguagesW.restype = ctypes.c_bool
_kernel32.FindResourceExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ushort]
_kernel32.FindResourceExW.restype = ctypes.c_void_p
_kernel32.SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_kernel32.SizeofResource.restype = ctypes.c_uint32
_kernel32.LoadResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_kernel32.LoadResource.restype = ctypes.c_void_p
_kernel32.LockResource.argtypes = [ctypes.c_void_p]
_kernel32.LockResource.restype = ctypes.c_void_p

RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    23: "HTML",
    24: "MANIFEST",
}


@dataclass
class PEResourceEntry:
    type_name: str
    type_id: int | None
    name: str
    language: int
    size: int
    path: str


@dataclass
class _RawResourceEntry:
    type_name: str
    type_id: int | None
    name: str
    language: int
    data: bytes
    path: str


def extract_pe_resources(target: Path, destination_root: Path) -> tuple[list[PEResourceEntry], Path]:
    handle = _kernel32.LoadLibraryExW(str(target), None, LOAD_LIBRARY_AS_DATAFILE)
    if not handle:
        return [], destination_root / "pe_resources.json"

    resources_root = ensure_dir(destination_root / "pe_resources")
    manifest_entries: list[PEResourceEntry] = []
    raw_entries: list[_RawResourceEntry] = []

    try:
        def enum_types_callback(module_handle, type_ptr, _lparam):
            resource_type = _resource_type_identifier(type_ptr)

            def enum_names_callback(module_handle2, type_ptr2, name_ptr, _lparam2):
                resource_name = _resource_name_identifier(name_ptr)

                def enum_languages_callback(module_handle3, type_ptr3, name_ptr2, language, _lparam3):
                    data = _load_resource_bytes(module_handle3, type_ptr3, name_ptr2, language)
                    if not data:
                        return True
                    entry = _write_resource(
                        resources_root,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        language=int(language),
                        data=data,
                    )
                    manifest_entries.append(entry)
                    raw_entries.append(
                        _RawResourceEntry(
                            type_name=entry.type_name,
                            type_id=entry.type_id,
                            name=entry.name,
                            language=entry.language,
                            data=data,
                            path=entry.path,
                        )
                    )
                    return True

                callback = _enum_language_callback(enum_languages_callback)
                _kernel32.EnumResourceLanguagesW(module_handle2, type_ptr2, name_ptr, callback, 0)
                return True

            callback = _enum_name_callback(enum_names_callback)
            _kernel32.EnumResourceNamesW(module_handle, type_ptr, callback, 0)
            return True

        callback = _enum_type_callback(enum_types_callback)
        _kernel32.EnumResourceTypesW(handle, callback, 0)
    finally:
        _kernel32.FreeLibrary(handle)

    manifest_path = destination_root / "pe_resources.json"
    payload = [
        {
            "type_name": entry.type_name,
            "type_id": entry.type_id,
            "name": entry.name,
            "language": entry.language,
            "size": entry.size,
            "path": entry.path,
        }
        for entry in manifest_entries
    ]

    icon_entries = _reconstruct_group_icons(resources_root, raw_entries)
    manifest_entries.extend(icon_entries)
    payload.extend(
        {
            "type_name": entry.type_name,
            "type_id": entry.type_id,
            "name": entry.name,
            "language": entry.language,
            "size": entry.size,
            "path": entry.path,
        }
        for entry in icon_entries
    )
    manifest_path.write_text(sanitize_text(json.dumps(payload, indent=2, ensure_ascii=False)), encoding="utf-8")
    return manifest_entries, manifest_path


def _resource_type_identifier(pointer) -> tuple[int | None, str]:
    value = ctypes.cast(pointer, ctypes.c_void_p).value or 0
    if value <= 0xFFFF:
        resource_id = int(value)
        return resource_id, RESOURCE_TYPE_NAMES.get(resource_id, f"ID_{resource_id}")
    return None, sanitize_text(ctypes.wstring_at(pointer))


def _resource_name_identifier(pointer) -> tuple[int | None, str]:
    value = ctypes.cast(pointer, ctypes.c_void_p).value or 0
    if value <= 0xFFFF:
        resource_id = int(value)
        return resource_id, f"ID_{resource_id}"
    return None, sanitize_text(ctypes.wstring_at(pointer))


def _load_resource_bytes(module_handle, type_ptr, name_ptr, language: int) -> bytes:
    resource_handle = _kernel32.FindResourceExW(module_handle, type_ptr, name_ptr, language)
    if not resource_handle:
        return b""
    size = _kernel32.SizeofResource(module_handle, resource_handle)
    if not size:
        return b""
    loaded = _kernel32.LoadResource(module_handle, resource_handle)
    if not loaded:
        return b""
    locked = _kernel32.LockResource(loaded)
    if not locked:
        return b""
    return ctypes.string_at(locked, size)


def _write_resource(
    destination_root: Path,
    *,
    resource_type: tuple[int | None, str],
    resource_name: tuple[int | None, str],
    language: int,
    data: bytes,
) -> PEResourceEntry:
    type_id, type_name = resource_type
    _, name_string = resource_name
    type_dir = ensure_dir(destination_root / safe_slug(type_name))
    extension = _resource_extension(type_name, data)
    filename = f"{safe_slug(name_string)}_lang{language}{extension}"
    path = type_dir / filename
    if extension in {".xml", ".html", ".txt"}:
        path.write_text(_decode_resource_text(data), encoding="utf-8")
    else:
        path.write_bytes(data)
    return PEResourceEntry(
        type_name=type_name,
        type_id=type_id,
        name=name_string,
        language=language,
        size=len(data),
        path=str(path),
    )


def _resource_extension(type_name: str, data: bytes) -> str:
    if type_name == "MANIFEST":
        return ".xml"
    if type_name == "HTML":
        return ".html"
    if type_name == "VERSION":
        return ".bin"
    if type_name in {"STRING", "RCDATA", "MESSAGETABLE"} and _looks_textual(data):
        return ".txt"
    if type_name == "BITMAP":
        return ".bmp.bin"
    if type_name in {"ICON", "GROUP_ICON", "CURSOR", "GROUP_CURSOR"}:
        return ".bin"
    return ".bin"


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[: min(512, len(data))]
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126)
    return printable / len(sample) > 0.85


def _decode_resource_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            return sanitize_text(data.decode(encoding))
        except UnicodeDecodeError:
            continue
    return sanitize_text(data.decode("utf-8", errors="replace"))


def _reconstruct_group_icons(destination_root: Path, entries: list[_RawResourceEntry]) -> list[PEResourceEntry]:
    icon_entries = [entry for entry in entries if entry.type_name == "ICON"]
    group_entries = [entry for entry in entries if entry.type_name == "GROUP_ICON"]
    icon_map = {(entry.name, entry.language): entry.data for entry in icon_entries}
    fallback_icon_map = {entry.name: entry.data for entry in icon_entries}
    output: list[PEResourceEntry] = []
    ico_dir = ensure_dir(destination_root / "ICO")

    for entry in group_entries:
        ico_data = _build_ico_from_group(entry.data, entry.language, icon_map, fallback_icon_map)
        if not ico_data:
            continue
        ico_path = ico_dir / f"{safe_slug(entry.name)}_lang{entry.language}.ico"
        ico_path.write_bytes(ico_data)
        output.append(
            PEResourceEntry(
                type_name="ICO",
                type_id=None,
                name=entry.name,
                language=entry.language,
                size=len(ico_data),
                path=str(ico_path),
            )
        )
    return output


def _build_ico_from_group(
    group_data: bytes,
    language: int,
    icon_map: dict[tuple[str, int], bytes],
    fallback_icon_map: dict[str, bytes],
) -> bytes | None:
    if len(group_data) < 6:
        return None
    reserved, resource_type, count = ctypes.c_ushort.from_buffer_copy(group_data[:2]).value, ctypes.c_ushort.from_buffer_copy(group_data[2:4]).value, ctypes.c_ushort.from_buffer_copy(group_data[4:6]).value
    if reserved != 0 or resource_type != 1 or count <= 0:
        return None
    if len(group_data) < 6 + (count * 14):
        return None

    header = bytearray(group_data[:6])
    directory = bytearray()
    images: list[bytes] = []
    image_offset = 6 + (count * 16)

    for index in range(count):
        offset = 6 + (index * 14)
        width = group_data[offset]
        height = group_data[offset + 1]
        color_count = group_data[offset + 2]
        reserved_byte = group_data[offset + 3]
        planes = int.from_bytes(group_data[offset + 4 : offset + 6], "little")
        bit_count = int.from_bytes(group_data[offset + 6 : offset + 8], "little")
        bytes_in_res = int.from_bytes(group_data[offset + 8 : offset + 12], "little")
        icon_id = int.from_bytes(group_data[offset + 12 : offset + 14], "little")
        icon_name = f"ID_{icon_id}"
        image = icon_map.get((icon_name, language)) or fallback_icon_map.get(icon_name)
        if image is None:
            return None
        images.append(image)
        directory.extend(bytes([width, height, color_count, reserved_byte]))
        directory.extend(planes.to_bytes(2, "little"))
        directory.extend(bit_count.to_bytes(2, "little"))
        directory.extend(bytes_in_res.to_bytes(4, "little"))
        directory.extend(image_offset.to_bytes(4, "little"))
        image_offset += len(image)

    return bytes(header + directory + b"".join(images))


def _enum_type_callback(function):
    return ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long)(function)


def _enum_name_callback(function):
    return ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long)(function)


def _enum_language_callback(function):
    return ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_long)(function)
