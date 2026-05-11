from __future__ import annotations

import ctypes
import plistlib
import re
import struct
from pathlib import Path


def sanitize_text(value: str) -> str:
    normalized = value.encode("utf-8", errors="replace").decode("utf-8")
    return "".join(ch if ch in "\r\n\t" or ord(ch) >= 32 else " " for ch in normalized).strip()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._") or "output"


def read_binary_head(path: Path, size: int = 2_000_000) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def is_probable_binary(path: Path, data: bytes) -> bool:
    binary_suffixes = {".exe", ".dll", ".sys", ".drv", ".bin", ".com", ".scr", ".ocx"}
    if path.suffix.lower() in binary_suffixes:
        return True
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    text_bytes = sum(1 for byte in data[:4096] if byte in (9, 10, 13) or 32 <= byte <= 126)
    ratio = text_bytes / min(len(data), 4096)
    return ratio < 0.85


def extract_ascii_strings(data: bytes, minimum: int = 6, limit: int = 8000) -> list[str]:
    pattern = rb"[\x20-\x7E]{%d,}" % minimum
    strings = [match.decode("utf-8", errors="ignore") for match in re.findall(pattern, data)]
    return strings[:limit]


def parse_pe_metadata(path: Path) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(0x1000)
    except OSError:
        return None

    if len(header) < 0x40 or header[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset + 24 > len(header):
        return None
    if header[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    machine, number_of_sections, timestamp, _, _, optional_header_size, characteristics = struct.unpack_from(
        "<HHIIIHH", header, pe_offset + 4
    )
    optional_header_offset = pe_offset + 24
    if optional_header_offset + 2 > len(header):
        return None
    optional_magic = struct.unpack_from("<H", header, optional_header_offset)[0]
    address_of_entry_point = 0
    image_base = 0
    if optional_magic == 0x20B and optional_header_offset + 32 <= len(header):
        address_of_entry_point = struct.unpack_from("<I", header, optional_header_offset + 16)[0]
        image_base = struct.unpack_from("<Q", header, optional_header_offset + 24)[0]
    elif optional_magic == 0x10B and optional_header_offset + 32 <= len(header):
        address_of_entry_point = struct.unpack_from("<I", header, optional_header_offset + 16)[0]
        image_base = struct.unpack_from("<I", header, optional_header_offset + 28)[0]
    section_table_offset = optional_header_offset + optional_header_size
    sections: list[str] = []
    for index in range(number_of_sections):
        section_offset = section_table_offset + (40 * index)
        if section_offset + 8 > len(header):
            break
        raw_name = header[section_offset : section_offset + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        if name:
            sections.append(name)

    machine_map = {
        0x014C: "x86",
        0x8664: "x64",
        0x01C4: "ARM",
        0xAA64: "ARM64",
    }
    optional_magic_map = {
        0x10B: "PE32",
        0x20B: "PE32+",
    }
    return {
        "machine": machine_map.get(machine, hex(machine)),
        "timestamp": timestamp,
        "characteristics": hex(characteristics),
        "optional_magic": optional_magic_map.get(optional_magic, hex(optional_magic)),
        "entry_point": address_of_entry_point,
        "image_base": image_base,
        "sections": sections,
        "number_of_sections": number_of_sections,
    }


def parse_pe_sections(path: Path) -> list[dict[str, int | str]]:
    try:
        with path.open("rb") as handle:
            header = handle.read(0x4000)
    except OSError:
        return []

    if len(header) < 0x40 or header[:2] != b"MZ":
        return []

    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset + 24 > len(header):
        return []
    if header[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return []

    number_of_sections = struct.unpack_from("<H", header, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", header, pe_offset + 20)[0]
    section_table_offset = pe_offset + 24 + optional_header_size
    sections: list[dict[str, int | str]] = []
    for index in range(number_of_sections):
        section_offset = section_table_offset + (40 * index)
        if section_offset + 40 > len(header):
            break
        raw_name = header[section_offset : section_offset + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", header, section_offset + 8)
        characteristics = struct.unpack_from("<I", header, section_offset + 36)[0]
        flags = []
        if characteristics & 0x20000000:
            flags.append("EXECUTE")
        if characteristics & 0x40000000:
            flags.append("READ")
        if characteristics & 0x80000000:
            flags.append("WRITE")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
                "flag_names": flags,
            }
        )
    return sections


def pe_rva_to_offset(rva: int, sections: list[dict[str, int | str]]) -> int | None:
    for section in sections:
        virtual_address = int(section["virtual_address"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        raw_offset = int(section["raw_offset"])
        if virtual_address <= rva < virtual_address + span:
            return raw_offset + (rva - virtual_address)
    return None


def pe_offset_to_rva(offset: int, sections: list[dict[str, int | str]]) -> int | None:
    for section in sections:
        raw_offset = int(section["raw_offset"])
        raw_size = int(section["raw_size"])
        virtual_address = int(section["virtual_address"])
        if raw_offset <= offset < raw_offset + raw_size:
            return virtual_address + (offset - raw_offset)
    return None


def _rva_to_offset(rva: int, sections: list[dict[str, int | str]]) -> int | None:
    return pe_rva_to_offset(rva, sections)


def parse_pe_imports(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 0x200 or data[:2] != b"MZ":
        return []

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 0x100 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return []

    optional_header_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    if optional_magic == 0x20B:
        data_directory_offset = optional_header_offset + 112
    elif optional_magic == 0x10B:
        data_directory_offset = optional_header_offset + 96
    else:
        return []
    if data_directory_offset + 16 > len(data):
        return []

    import_rva, import_size = struct.unpack_from("<II", data, data_directory_offset + 8)
    if import_rva == 0 or import_size == 0:
        return []

    sections = parse_pe_sections(path)
    import_offset = _rva_to_offset(import_rva, sections)
    if import_offset is None:
        return []

    imports: list[str] = []
    seen: set[str] = set()
    for index in range(2048):
        descriptor_offset = import_offset + (index * 20)
        if descriptor_offset + 20 > len(data):
            break
        original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor_offset)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        name_offset = _rva_to_offset(name_rva, sections)
        if name_offset is None or name_offset >= len(data):
            continue
        end = data.find(b"\x00", name_offset)
        if end == -1:
            continue
        name = data[name_offset:end].decode("ascii", errors="ignore")
        if name and name.lower() not in seen:
            imports.append(name)
            seen.add(name.lower())
    return imports


def parse_pe_codeview_records(path: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 0x200 or data[:2] != b"MZ":
        return []

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 0x100 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return []

    optional_header_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    if optional_magic == 0x20B:
        data_directory_offset = optional_header_offset + 112
    elif optional_magic == 0x10B:
        data_directory_offset = optional_header_offset + 96
    else:
        return []
    if data_directory_offset + (8 * 7) > len(data):
        return []

    debug_rva, debug_size = struct.unpack_from("<II", data, data_directory_offset + (8 * 6))
    if debug_rva == 0 or debug_size == 0:
        return []

    sections = parse_pe_sections(path)
    debug_offset = _rva_to_offset(debug_rva, sections)
    if debug_offset is None:
        return []

    records: list[dict[str, object]] = []
    for index in range(max(debug_size // 28, 1)):
        entry_offset = debug_offset + (index * 28)
        if entry_offset + 28 > len(data):
            break
        _, _, _, _, entry_type, size_of_data, address_of_raw_data, pointer_to_raw_data = struct.unpack_from(
            "<IIHHIIII", data, entry_offset
        )
        if entry_type == 0 and size_of_data == 0 and address_of_raw_data == 0 and pointer_to_raw_data == 0:
            continue
        payload_offset = pointer_to_raw_data
        if payload_offset == 0 and address_of_raw_data:
            payload_offset = _rva_to_offset(address_of_raw_data, sections) or 0
        if payload_offset <= 0 or payload_offset + size_of_data > len(data):
            continue
        payload = data[payload_offset : payload_offset + size_of_data]
        if entry_type == 2 and payload[:4] == b"RSDS" and len(payload) >= 24:
            guid = _format_pe_pdb_guid(payload[4:20])
            age = struct.unpack_from("<I", payload, 20)[0]
            end = payload.find(b"\x00", 24)
            if end == -1:
                end = len(payload)
            pdb_path = payload[24:end].decode("utf-8", errors="ignore")
            records.append(
                {
                    "format": "RSDS",
                    "guid": guid,
                    "age": age,
                    "pdb_path": sanitize_text(pdb_path),
                }
            )
        elif entry_type == 2 and payload[:4] == b"NB10" and len(payload) >= 16:
            age = struct.unpack_from("<I", payload, 12)[0]
            end = payload.find(b"\x00", 16)
            if end == -1:
                end = len(payload)
            pdb_path = payload[16:end].decode("utf-8", errors="ignore")
            records.append(
                {
                    "format": "NB10",
                    "age": age,
                    "pdb_path": sanitize_text(pdb_path),
                }
            )
    return records


def parse_pe_cli_metadata(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 0x200 or data[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 0x100 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    optional_header_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    if optional_magic == 0x20B:
        data_directory_offset = optional_header_offset + 112
    elif optional_magic == 0x10B:
        data_directory_offset = optional_header_offset + 96
    else:
        return None
    if data_directory_offset + (8 * 15) > len(data):
        return None

    cli_rva, cli_size = struct.unpack_from("<II", data, data_directory_offset + (8 * 14))
    if cli_rva == 0 or cli_size == 0:
        return None

    sections = parse_pe_sections(path)
    cli_offset = _rva_to_offset(cli_rva, sections)
    if cli_offset is None or cli_offset + 24 > len(data):
        return None

    (
        cb,
        major_runtime,
        minor_runtime,
        metadata_rva,
        metadata_size,
        flags,
        entry_point_token,
        resources_rva,
        resources_size,
        strong_name_rva,
        strong_name_size,
        code_manager_table_rva,
        code_manager_table_size,
        vtable_fixups_rva,
        vtable_fixups_size,
        export_address_table_jumps_rva,
        export_address_table_jumps_size,
        managed_native_header_rva,
        managed_native_header_size,
    ) = struct.unpack_from("<IHHIIIIIIIIIIIIIIII", data, cli_offset)

    metadata_offset = _rva_to_offset(metadata_rva, sections)
    metadata_version = ""
    stream_names: list[str] = []
    if metadata_offset is not None and metadata_offset + 16 <= len(data) and data[metadata_offset : metadata_offset + 4] == b"BSJB":
        version_length = struct.unpack_from("<I", data, metadata_offset + 12)[0]
        version_offset = metadata_offset + 16
        version_end = min(version_offset + version_length, len(data))
        metadata_version = sanitize_text(data[version_offset:version_end].rstrip(b"\x00").decode("utf-8", errors="ignore"))
        stream_header_offset = version_offset + version_length
        stream_header_offset = (stream_header_offset + 3) & ~3
        if stream_header_offset + 4 <= len(data):
            _, streams = struct.unpack_from("<HH", data, stream_header_offset)
            cursor = stream_header_offset + 4
            for _ in range(streams):
                if cursor + 8 > len(data):
                    break
                _, _ = struct.unpack_from("<II", data, cursor)
                cursor += 8
                name_end = data.find(b"\x00", cursor)
                if name_end == -1:
                    break
                name = data[cursor:name_end].decode("ascii", errors="ignore")
                if name:
                    stream_names.append(name)
                cursor = (name_end + 4) & ~3

    managed_native_header: dict[str, object] | None = None
    if managed_native_header_rva and managed_native_header_size:
        managed_native_offset = _rva_to_offset(managed_native_header_rva, sections)
        if managed_native_offset is not None and managed_native_offset + 16 <= len(data):
            signature, major_version, minor_version, native_flags, section_count = struct.unpack_from(
                "<IHHII",
                data,
                managed_native_offset,
            )
            managed_native_header = {
                "rva": managed_native_header_rva,
                "size": managed_native_header_size,
                "signature": hex(signature),
                "signature_text": sanitize_text(data[managed_native_offset : managed_native_offset + 4].decode("ascii", errors="ignore")),
                "major_version": major_version,
                "minor_version": minor_version,
                "flags": hex(native_flags),
                "section_count": section_count,
                "is_readytorun": signature == 0x00525452,
            }

    return {
        "cli_header_size": cb,
        "runtime_version": f"{major_runtime}.{minor_runtime}",
        "metadata_rva": metadata_rva,
        "metadata_size": metadata_size,
        "metadata_version": metadata_version,
        "flags": _describe_cli_flags(flags),
        "flag_mask": hex(flags),
        "entry_point_token": hex(entry_point_token),
        "resources_rva": resources_rva,
        "resources_size": resources_size,
        "strong_name_rva": strong_name_rva,
        "strong_name_size": strong_name_size,
        "code_manager_table_rva": code_manager_table_rva,
        "code_manager_table_size": code_manager_table_size,
        "vtable_fixups_rva": vtable_fixups_rva,
        "vtable_fixups_size": vtable_fixups_size,
        "export_address_table_jumps_rva": export_address_table_jumps_rva,
        "export_address_table_jumps_size": export_address_table_jumps_size,
        "managed_native_header_rva": managed_native_header_rva,
        "managed_native_header_size": managed_native_header_size,
        "managed_native_header": managed_native_header,
        "metadata_streams": stream_names,
    }


def read_pe_version_info(path: Path) -> dict[str, str]:
    if path.suffix.lower() not in {".exe", ".dll", ".mui", ".ocx", ".sys"}:
        return {}

    size = ctypes.windll.version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return {}

    buffer = ctypes.create_string_buffer(size)
    ok = ctypes.windll.version.GetFileVersionInfoW(str(path), 0, size, buffer)
    if not ok:
        return {}

    block = ctypes.c_void_p()
    block_len = ctypes.c_uint()
    if not ctypes.windll.version.VerQueryValueW(buffer, "\\VarFileInfo\\Translation", ctypes.byref(block), ctypes.byref(block_len)):
        return {}

    translations = ctypes.string_at(block.value, block_len.value)
    if len(translations) < 4:
        return {}
    language, codepage = struct.unpack_from("<HH", translations, 0)
    prefix = f"\\StringFileInfo\\{language:04x}{codepage:04x}\\"

    keys = [
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
    ]
    result: dict[str, str] = {}
    for key in keys:
        if ctypes.windll.version.VerQueryValueW(
            buffer,
            prefix + key,
            ctypes.byref(block),
            ctypes.byref(block_len),
        ):
            value = ctypes.wstring_at(block.value, block_len.value)
            if value:
                result[key] = sanitize_text(value.rstrip("\x00"))
    return result


def sanitize_relative_source_path(raw_path: str) -> str:
    normalized = raw_path.replace("\\", "/").strip()
    normalized = normalized.removeprefix("webpack://")
    normalized = normalized.removeprefix("file://")
    normalized = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*:(//)?", "", normalized)
    normalized = normalized.lstrip("/")
    parts: list[str] = []
    for part in normalized.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            continue
        safe_part = re.sub(r'[<>:"|?*]', "_", part).rstrip(" .")
        if safe_part:
            parts.append(safe_part)
    return "/".join(parts) or "unknown.js"


def safe_output_path(base_dir: Path, relative_path: str) -> Path:
    safe_relative = sanitize_relative_source_path(relative_path)
    destination = (base_dir / safe_relative).resolve()
    base_resolved = base_dir.resolve()
    if not str(destination).startswith(str(base_resolved)):
        raise ValueError(f"Unsafe output path derived from {relative_path!r}")
    return destination


def parse_macho_metadata(path: Path) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(0x1000)
    except OSError:
        return None

    if len(header) < 4:
        return None

    magic = header[:4]
    thin_layouts = {
        b"\xfe\xed\xfa\xce": (">", False),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xcf\xfa\xed\xfe": ("<", True),
    }
    fat_layouts = {
        b"\xca\xfe\xba\xbe": ">",
        b"\xbe\xba\xfe\xca": "<",
        b"\xca\xfe\xba\xbf": ">",
        b"\xbf\xba\xfe\xca": "<",
    }
    if magic in thin_layouts:
        endian, is_64 = thin_layouts[magic]
        minimum = 32 if is_64 else 28
        if len(header) < minimum:
            return None
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(f"{endian}iiIIII", header, 4)
        return {
            "format": "mach-o",
            "endianness": "little" if endian == "<" else "big",
            "bits": 64 if is_64 else 32,
            "cpu_type": _macho_cpu_name(cputype),
            "cpu_subtype": cpusubtype,
            "file_type": _macho_file_type_name(filetype),
            "load_commands": ncmds,
            "load_commands_size": sizeofcmds,
            "flags": hex(flags),
        }
    if magic in fat_layouts:
        endian = fat_layouts[magic]
        if len(header) < 8:
            return None
        arch_count = struct.unpack_from(f"{endian}I", header, 4)[0]
        return {
            "format": "mach-o-fat",
            "endianness": "little" if endian == "<" else "big",
            "architectures": arch_count,
        }
    return None


def parse_plist(path: Path) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _macho_cpu_name(cpu_type: int) -> str:
    cpu_map = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        18: "ppc",
        0x01000012: "ppc64",
    }
    return cpu_map.get(cpu_type, hex(cpu_type))


def _macho_file_type_name(file_type: int) -> str:
    file_type_map = {
        0x1: "object",
        0x2: "executable",
        0x3: "fixed-vm-library",
        0x4: "core",
        0x5: "preloaded-executable",
        0x6: "dynamic-library",
        0x7: "dynamic-linker",
        0x8: "bundle",
        0x9: "dynamic-library-stub",
    }
    return file_type_map.get(file_type, hex(file_type))


def _format_pe_pdb_guid(raw_guid: bytes) -> str:
    data1, data2, data3 = struct.unpack_from("<IHH", raw_guid, 0)
    data4 = raw_guid[8:]
    return (
        f"{data1:08X}-{data2:04X}-{data3:04X}-"
        f"{data4[0]:02X}{data4[1]:02X}-"
        f"{data4[2]:02X}{data4[3]:02X}{data4[4]:02X}{data4[5]:02X}{data4[6]:02X}{data4[7]:02X}"
    )


def _describe_cli_flags(flags: int) -> list[str]:
    mapping = {
        0x00000001: "ILONLY",
        0x00000002: "32BITREQUIRED",
        0x00000004: "IL_LIBRARY",
        0x00000008: "STRONGNAMESIGNED",
        0x00000010: "NATIVE_ENTRYPOINT",
        0x00010000: "TRACKDEBUGDATA",
        0x00020000: "32BITPREFERRED",
    }
    return [name for mask, name in mapping.items() if flags & mask]
