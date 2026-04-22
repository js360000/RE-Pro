from __future__ import annotations

import struct
from pathlib import Path


ELF_MAGIC = b"\x7fELF"

ELF_MACHINE_NAMES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86_64",
    0xB7: "ARM64",
    0xF3: "RISC-V",
}

ELF_TYPE_NAMES = {
    0x00: "none",
    0x01: "relocatable",
    0x02: "executable",
    0x03: "shared-object",
    0x04: "core",
}

ELF_PROGRAM_TYPE_NAMES = {
    0x00: "NULL",
    0x01: "LOAD",
    0x02: "DYNAMIC",
    0x03: "INTERP",
    0x04: "NOTE",
    0x05: "SHLIB",
    0x06: "PHDR",
    0x07: "TLS",
}

ELF_PROGRAM_FLAG_NAMES = {
    0x1: "EXECUTE",
    0x2: "WRITE",
    0x4: "READ",
}

ELF_SECTION_TYPE_NAMES = {
    0x00: "NULL",
    0x01: "PROGBITS",
    0x02: "SYMTAB",
    0x03: "STRTAB",
    0x04: "RELA",
    0x05: "HASH",
    0x06: "DYNAMIC",
    0x07: "NOTE",
    0x08: "NOBITS",
    0x09: "REL",
    0x0B: "DYNSYM",
    0x0E: "INIT_ARRAY",
    0x0F: "FINI_ARRAY",
    0x11: "GROUP",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFF: "VERSYM",
}

ELF_SECTION_FLAG_NAMES = {
    0x1: "WRITE",
    0x2: "ALLOC",
    0x4: "EXECINSTR",
    0x10: "MERGE",
    0x20: "STRINGS",
    0x40: "INFO_LINK",
    0x80: "LINK_ORDER",
    0x100: "OS_NONCONFORMING",
    0x200: "GROUP",
    0x400: "TLS",
}

ELF_SYMBOL_BINDINGS = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
}

ELF_SYMBOL_TYPES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
}

EF_MIPS_NOREORDER = 0x00000001
EF_MIPS_PIC = 0x00000002
EF_MIPS_CPIC = 0x00000004
EF_MIPS_ABI2 = 0x00000020
EF_MIPS_32BITMODE = 0x00000100
EF_MIPS_FP64 = 0x00000200
EF_MIPS_NAN2008 = 0x00000400

EF_MIPS_ABI = 0x0000F000
EF_MIPS_ABI_NAMES = {
    0x00001000: "O32",
    0x00002000: "O64",
    0x00003000: "EABI32",
    0x00004000: "EABI64",
}

EF_MIPS_MACH = 0x00FF0000
EF_MIPS_MACH_NAMES = {
    0x00000000: "generic",
    0x00810000: "R3900",
    0x00820000: "R4010",
    0x00830000: "R4100",
    0x00850000: "R4650",
    0x00860000: "R5400",
    0x00870000: "R5500",
    0x00880000: "R9000",
    0x00910000: "VR5400",
    0x00920000: "R5900",
}

EF_MIPS_ARCH = 0xF0000000
EF_MIPS_ARCH_NAMES = {
    0x00000000: "MIPS I",
    0x10000000: "MIPS II",
    0x20000000: "MIPS III",
    0x30000000: "MIPS IV",
    0x40000000: "MIPS V",
    0x50000000: "MIPS32",
    0x60000000: "MIPS64",
    0x70000000: "MIPS32R2",
    0x80000000: "MIPS64R2",
    0x90000000: "MIPS32R6",
    0xA0000000: "MIPS64R6",
}


def parse_elf_metadata(path: Path) -> dict[str, object] | None:
    parsed = _parse_elf(path)
    if parsed is None:
        return None
    header = parsed["header"]
    sections = parsed["sections"]
    return {
        "format": "elf",
        "bits": header["bits"],
        "endianness": header["endianness"],
        "type": header["type_name"],
        "machine": header["machine_name"],
        "entry_point": header["entry_point"],
        "flags": header["flags"],
        "mips_flags": header.get("mips_flags"),
        "program_header_offset": header["program_header_offset"],
        "section_header_offset": header["section_header_offset"],
        "program_header_count": header["program_header_count"],
        "section_header_count": header["section_header_count"],
        "section_string_index": header["section_string_index"],
        "sections": [str(section.get("name", "")) for section in sections if section.get("name")],
    }


def parse_elf_program_headers(path: Path) -> list[dict[str, object]]:
    parsed = _parse_elf(path)
    if parsed is None:
        return []
    return parsed["program_headers"]


def parse_elf_sections(path: Path) -> list[dict[str, object]]:
    parsed = _parse_elf(path)
    if parsed is None:
        return []
    return parsed["sections"]


def parse_elf_symbols(path: Path, *, limit: int = 2048) -> list[dict[str, object]]:
    parsed = _parse_elf(path)
    if parsed is None:
        return []
    data = parsed["data"]
    header = parsed["header"]
    sections = parsed["sections"]
    endian = header["endian_char"]
    is_64 = header["bits"] == 64
    symbols: list[dict[str, object]] = []

    for section in sections:
        if section["type"] not in (0x02, 0x0B):
            continue
        string_table_index = int(section.get("link", 0))
        if not (0 <= string_table_index < len(sections)):
            continue
        string_table = sections[string_table_index]
        string_data = _slice_section_bytes(data, string_table)
        if not string_data:
            continue
        entry_size = int(section.get("entry_size", 0))
        if entry_size <= 0:
            entry_size = 24 if is_64 else 16
        entries = _slice_section_bytes(data, section)
        if not entries:
            continue

        for offset in range(0, len(entries) - entry_size + 1, entry_size):
            chunk = entries[offset : offset + entry_size]
            if is_64:
                if len(chunk) < 24:
                    continue
                name_offset, info, other, section_index, value, size = struct.unpack_from(f"{endian}IBBHQQ", chunk, 0)
            else:
                if len(chunk) < 16:
                    continue
                name_offset, value, size, info, other, section_index = struct.unpack_from(f"{endian}IIIBBH", chunk, 0)
            name = _read_c_string(string_data, name_offset)
            if not name:
                continue
            section_name = ""
            if 0 <= section_index < len(sections):
                section_name = str(sections[section_index].get("name", ""))
            symbols.append(
                {
                    "name": name,
                    "value": value,
                    "size": size,
                    "binding": ELF_SYMBOL_BINDINGS.get(info >> 4, hex(info >> 4)),
                    "type": ELF_SYMBOL_TYPES.get(info & 0x0F, hex(info & 0x0F)),
                    "visibility": hex(other),
                    "section_index": section_index,
                    "section_name": section_name,
                    "table": section.get("name") or ELF_SECTION_TYPE_NAMES.get(int(section["type"]), hex(int(section["type"]))),
                }
            )
            if len(symbols) >= limit:
                return symbols
    return symbols


def parse_elf_needed_libraries(path: Path) -> list[str]:
    parsed = _parse_elf(path)
    if parsed is None:
        return []
    data = parsed["data"]
    header = parsed["header"]
    sections = parsed["sections"]
    endian = header["endian_char"]
    is_64 = header["bits"] == 64
    libraries: list[str] = []
    seen: set[str] = set()

    for section in sections:
        if section["type"] != 0x06:
            continue
        string_table_index = int(section.get("link", 0))
        if not (0 <= string_table_index < len(sections)):
            continue
        string_table = sections[string_table_index]
        string_data = _slice_section_bytes(data, string_table)
        entries = _slice_section_bytes(data, section)
        if not string_data or not entries:
            continue
        entry_size = 16 if is_64 else 8
        for offset in range(0, len(entries) - entry_size + 1, entry_size):
            chunk = entries[offset : offset + entry_size]
            if is_64:
                tag, value = struct.unpack_from(f"{endian}QQ", chunk, 0)
            else:
                tag, value = struct.unpack_from(f"{endian}II", chunk, 0)
            if tag == 0:
                break
            if tag != 1:
                continue
            name = _read_c_string(string_data, value)
            if name and name.lower() not in seen:
                libraries.append(name)
                seen.add(name.lower())
    return libraries


def parse_elf_interpreter(path: Path) -> str | None:
    parsed = _parse_elf(path)
    if parsed is None:
        return None
    for section in parsed["sections"]:
        if section.get("name") == ".interp":
            data = _slice_section_bytes(parsed["data"], section)
            if not data:
                return None
            return _read_c_string(data, 0) or None
    return None


def elf_virtual_address_to_offset(
    address: int,
    sections: list[dict[str, object]],
    program_headers: list[dict[str, object]] | None = None,
) -> int | None:
    for section in sections:
        section_address = int(section.get("address", 0))
        section_size = max(int(section.get("size", 0)), int(section.get("entry_size", 0)))
        if section_address <= address < section_address + section_size:
            return int(section.get("offset", 0)) + (address - section_address)
    for program_header in program_headers or []:
        virtual_address = int(program_header.get("virtual_address", 0))
        file_size = int(program_header.get("file_size", 0))
        if virtual_address <= address < virtual_address + file_size:
            return int(program_header.get("offset", 0)) + (address - virtual_address)
    return None


def _parse_elf(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return None

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None

    endian = "<" if ei_data == 1 else ">"
    bits = 64 if ei_class == 2 else 32
    if bits == 64:
        header_format = f"{endian}HHIQQQIHHHHHH"
    else:
        header_format = f"{endian}HHIIIIIHHHHHH"
    header_size = struct.calcsize(header_format)
    if len(data) < 16 + header_size:
        return None
    header_values = struct.unpack_from(header_format, data, 16)
    (
        elf_type,
        machine,
        _version,
        entry_point,
        program_header_offset,
        section_header_offset,
        flags,
        _ehsize,
        program_header_size,
        program_header_count,
        section_header_size,
        section_header_count,
        section_string_index,
    ) = header_values

    header = {
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "endian_char": endian,
        "type": elf_type,
        "type_name": ELF_TYPE_NAMES.get(elf_type, hex(elf_type)),
        "machine": machine,
        "machine_name": ELF_MACHINE_NAMES.get(machine, hex(machine)),
        "entry_point": entry_point,
        "program_header_offset": program_header_offset,
        "program_header_size": program_header_size,
        "program_header_count": program_header_count,
        "section_header_offset": section_header_offset,
        "section_header_size": section_header_size,
        "section_header_count": section_header_count,
        "section_string_index": section_string_index,
        "flags": hex(flags),
    }
    if machine == 0x08:
        header["mips_flags"] = _decode_mips_flags(flags)
    program_headers = _parse_elf_program_headers(data, header)
    sections = _parse_elf_sections(data, header)
    return {
        "data": data,
        "header": header,
        "program_headers": program_headers,
        "sections": sections,
    }


def _parse_elf_program_headers(data: bytes, header: dict[str, object]) -> list[dict[str, object]]:
    program_header_offset = int(header["program_header_offset"])
    program_header_size = int(header["program_header_size"])
    program_header_count = int(header["program_header_count"])
    bits = int(header["bits"])
    endian = str(header["endian_char"])
    if program_header_offset <= 0 or program_header_size <= 0 or program_header_count <= 0:
        return []

    headers: list[dict[str, object]] = []
    header_format = f"{endian}IIQQQQQQ" if bits == 64 else f"{endian}IIIIIIII"
    minimum_size = struct.calcsize(header_format)
    if program_header_size < minimum_size:
        return []

    for index in range(program_header_count):
        offset = program_header_offset + (index * program_header_size)
        if offset + minimum_size > len(data):
            break
        values = struct.unpack_from(header_format, data, offset)
        if bits == 64:
            program_type, flags, file_offset, virtual_address, physical_address, file_size, memory_size, align = values
        else:
            program_type, file_offset, virtual_address, physical_address, file_size, memory_size, flags, align = values
        headers.append(
            {
                "index": index,
                "type": program_type,
                "type_name": ELF_PROGRAM_TYPE_NAMES.get(program_type, hex(program_type)),
                "offset": file_offset,
                "virtual_address": virtual_address,
                "physical_address": physical_address,
                "file_size": file_size,
                "memory_size": memory_size,
                "flags": flags,
                "flag_names": [name for mask, name in ELF_PROGRAM_FLAG_NAMES.items() if flags & mask],
                "align": align,
            }
        )
    return headers


def _parse_elf_sections(data: bytes, header: dict[str, object]) -> list[dict[str, object]]:
    section_header_offset = int(header["section_header_offset"])
    section_header_size = int(header["section_header_size"])
    section_header_count = int(header["section_header_count"])
    bits = int(header["bits"])
    endian = str(header["endian_char"])
    if section_header_offset <= 0 or section_header_size <= 0 or section_header_count <= 0:
        return []

    sections: list[dict[str, object]] = []
    section_format = f"{endian}IIQQQQIIQQ" if bits == 64 else f"{endian}IIIIIIIIII"
    minimum_size = struct.calcsize(section_format)
    if section_header_size < minimum_size:
        return []

    for index in range(section_header_count):
        offset = section_header_offset + (index * section_header_size)
        if offset + minimum_size > len(data):
            break
        values = struct.unpack_from(section_format, data, offset)
        if bits == 64:
            name_offset, section_type, flags, address, file_offset, size, link, info, address_align, entry_size = values
        else:
            name_offset, section_type, flags, address, file_offset, size, link, info, address_align, entry_size = values
        sections.append(
            {
                "index": index,
                "name_offset": name_offset,
                "type": section_type,
                "type_name": ELF_SECTION_TYPE_NAMES.get(section_type, hex(section_type)),
                "flags": flags,
                "flag_names": [name for mask, name in ELF_SECTION_FLAG_NAMES.items() if flags & mask],
                "address": address,
                "offset": file_offset,
                "size": size,
                "link": link,
                "info": info,
                "address_align": address_align,
                "entry_size": entry_size,
            }
        )

    section_string_index = int(header["section_string_index"])
    string_table = b""
    if 0 <= section_string_index < len(sections):
        shstr = sections[section_string_index]
        string_table = _slice_section_bytes(data, shstr)
    for section in sections:
        section["name"] = _read_c_string(string_table, int(section.get("name_offset", 0))) if string_table else ""
    return sections


def _slice_section_bytes(data: bytes, section: dict[str, object]) -> bytes:
    offset = int(section.get("offset", 0))
    size = int(section.get("size", 0))
    if offset < 0 or size <= 0 or offset + size > len(data):
        return b""
    return data[offset : offset + size]


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="ignore")


def _decode_mips_flags(flags: int) -> dict[str, object]:
    decoded_flags: list[str] = []
    for mask, name in (
        (EF_MIPS_NOREORDER, "noreorder"),
        (EF_MIPS_PIC, "pic"),
        (EF_MIPS_CPIC, "cpic"),
        (EF_MIPS_ABI2, "abi2"),
        (EF_MIPS_32BITMODE, "32bitmode"),
        (EF_MIPS_FP64, "fp64"),
        (EF_MIPS_NAN2008, "nan2008"),
    ):
        if flags & mask:
            decoded_flags.append(name)

    abi_value = flags & EF_MIPS_ABI
    mach_value = flags & EF_MIPS_MACH
    arch_value = flags & EF_MIPS_ARCH
    return {
        "raw": hex(flags),
        "abi": EF_MIPS_ABI_NAMES.get(abi_value, None if abi_value == 0 else hex(abi_value)),
        "machine_variant": EF_MIPS_MACH_NAMES.get(mach_value, None if mach_value == 0 else hex(mach_value)),
        "arch": EF_MIPS_ARCH_NAMES.get(arch_value, None if arch_value == 0 else hex(arch_value)),
        "flags": decoded_flags,
    }
