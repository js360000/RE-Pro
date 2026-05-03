from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .psp import PARAM_SFO_MAGIC
from .psp import PBP_SECTION_FILENAMES
from .psp import PBP_SECTION_NAMES
from .psp import parse_data_psar
from .psp import parse_data_psp
from .psp import parse_param_sfo


MAX_HEADER_BYTES = 4 * 1024 * 1024


def detect_console_formats(path: Path, head: bytes | None = None, elf_metadata: dict[str, object] | None = None) -> list[dict[str, Any]]:
    data = head if head is not None else _read_head(path)
    file_size = _safe_size(path, len(data))
    suffix = path.suffix.lower()
    detections: list[dict[str, Any]] = []
    parsers = (
        _parse_psx_exe,
        _parse_sce_self,
        _parse_sce_pkg,
        _parse_psp_param_sfo,
        _parse_psp_data_psp,
        _parse_psarc,
        _parse_psp_data_psar,
        _parse_psp_pbp,
        _parse_gamecube_wii_dol,
        _parse_gamecube_wii_disc,
        _parse_nds_rom,
        _parse_gba_rom,
        _parse_n64_rom,
        _parse_u8_archive,
        _parse_rarc_archive,
        _parse_sarc_archive,
        _parse_yaz0_stream,
        _parse_cri_cpk,
        _parse_cri_afs,
        _parse_xbox_xbe,
        _parse_xbox_xex,
    )
    for parser in parsers:
        parsed = parser(data, file_size, suffix)
        if parsed is not None:
            detections.append(parsed)

    elf_detection = _classify_console_elf(elf_metadata, suffix)
    if elf_detection is not None:
        detections.append(elf_detection)

    return _dedupe_detections(detections)


def _read_head(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_HEADER_BYTES)
    except OSError:
        return b""


def _safe_size(path: Path, fallback: int) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return fallback


def _parse_psx_exe(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x800 or not data.startswith(b"PS-X EXE"):
        return None
    region = _clean_ascii(data[0x4C:0x80])
    text_size = _u32le(data, 0x1C)
    return _detection(
        "sony-psx-exe",
        "Sony PlayStation PS-X EXE",
        "Sony PlayStation",
        "executable",
        "console-executable",
        "MIPS R3000A",
        {
            "entry_point": _hex(_u32le(data, 0x10)),
            "initial_gp": _hex(_u32le(data, 0x14)),
            "text_load_address": _hex(_u32le(data, 0x18)),
            "text_size": text_size,
            "initial_sp": _hex(_u32le(data, 0x30)),
            "region_string": region,
            "payload_offset": 0x800,
        },
    )


def _parse_sce_self(data: bytes, _file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or data[:4] != b"SCE\x00":
        return None
    words = [_u32be(data, offset) for offset in range(0, min(len(data), 0x30), 4)]
    platform = "Sony PlayStation 3 / Vita"
    if suffix == ".sprx":
        display = "Sony SELF/SPRX relocatable executable"
    else:
        display = "Sony SELF executable"
    return _detection(
        "sony-sce-self",
        display,
        platform,
        "executable",
        "console-executable",
        "PowerPC PPU / ARM depending on target generation",
        {
            "magic": "SCE\\0",
            "extension": suffix,
            "header_words_be": [_hex(value) for value in words],
            "likely_encrypted_or_signed": True,
            "notes": "SELF/SPRX wraps an ELF payload behind an SCE certified-file header.",
        },
    )


def _parse_sce_pkg(data: bytes, file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x80 or data[:4] != b"\x7fPKG":
        return None
    revision = _u16be(data, 0x04)
    pkg_type = _u16be(data, 0x06)
    platform = {1: "Sony PlayStation 3", 2: "Sony PSP / PlayStation Vita"}.get(pkg_type, "Sony PlayStation")
    content_id = _clean_ascii(data[0x30:0x60])
    return _detection(
        "sony-pkg",
        "Sony PlayStation PKG package",
        platform,
        "archive",
        "console-archive",
        "",
        {
            "revision": _hex(revision, 4),
            "revision_kind": "debug" if revision == 0 else "finalized" if revision == 0x8000 else "unknown",
            "debug_package": revision == 0,
            "pkg_type": _hex(pkg_type, 4),
            "metadata_offset": _u32be(data, 0x08),
            "metadata_count": _u32be(data, 0x0C),
            "metadata_size": _u32be(data, 0x10),
            "item_count_or_flags": _u32be(data, 0x14),
            "total_size": _u64be(data, 0x18),
            "data_offset": _u64be(data, 0x20),
            "data_size": _u64be(data, 0x28),
            "content_id": content_id,
            "observed_file_size": file_size,
            "encrypted_payload_likely": True,
        },
    )


def _parse_psarc(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or data[:4] != b"PSAR":
        return None
    compression = _clean_ascii(data[0x08:0x0C])
    compression_raw = data[0x08:0x0C].rstrip(b"\x00")
    if compression_raw not in {b"zlib", b"lzma", b""}:
        return None
    toc_size = _u32be(data, 0x0C)
    toc_entry_size = _u32be(data, 0x10)
    toc_entry_count = _u32be(data, 0x14)
    if toc_size < 0x20 or toc_entry_size < 0x1E or toc_entry_count == 0:
        return None
    archive_flags = _u32be(data, 0x1C)
    return _detection(
        "sony-psarc",
        "Sony PlayStation Archive (PSARC)",
        "Sony PlayStation 3 / Vita",
        "archive",
        "console-archive",
        "",
        {
            "version": _clean_ascii(data[0x04:0x08]),
            "compression": compression,
            "toc_size": toc_size,
            "toc_entry_size": toc_entry_size,
            "toc_entry_count": toc_entry_count,
            "block_size": _u32be(data, 0x18),
            "archive_flags": _hex(archive_flags),
            "toc_encrypted": bool(archive_flags & 0x04),
        },
    )


def _parse_psp_param_sfo(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x14 or data[:4] != PARAM_SFO_MAGIC:
        return None
    try:
        manifest = parse_param_sfo(data)
    except Exception:
        manifest = {}
    values = manifest.get("values") if isinstance(manifest, dict) else {}
    return _detection(
        "sony-psp-param-sfo",
        "Sony PSP PARAM.SFO metadata",
        "Sony PSP",
        "metadata",
        "console-metadata",
        "",
        {
            "version": _hex(_u32le(data, 0x04)),
            "key_table_offset": _u32le(data, 0x08),
            "data_table_offset": _u32le(data, 0x0C),
            "entry_count": _u32le(data, 0x10),
            "title": values.get("TITLE", "") if isinstance(values, dict) else "",
            "category": values.get("CATEGORY", "") if isinstance(values, dict) else "",
            "disc_id": values.get("DISC_ID", "") if isinstance(values, dict) else "",
            "updater_version": values.get("UPDATER_VER", "") if isinstance(values, dict) else "",
        },
    )


def _parse_psp_data_psp(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 4 or (data[:4] != b"~PSP" and not (data[:4] == b"\x7fELF" and _suffix == ".psp")):
        return None
    metadata = parse_data_psp(data)
    return _detection(
        "sony-psp-data-psp",
        "Sony PSP DATA.PSP executable payload",
        "Sony PSP",
        "executable",
        "console-executable",
        "MIPS Allegrex",
        metadata,
    )


def _parse_psp_data_psar(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 8 or data[:4] != b"PSAR":
        return None
    metadata = parse_data_psar(data)
    return _detection(
        "sony-psp-data-psar",
        "Sony PSP DATA.PSAR firmware payload",
        "Sony PSP",
        "archive",
        "console-archive",
        "MIPS Allegrex",
        metadata,
    )


def _parse_psp_pbp(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x28 or data[:4] != b"\x00PBP":
        return None
    offsets = [_u32le(data, 0x08 + index * 4) for index in range(8)]
    if any(offset < 0x28 or offset > _file_size for offset in offsets) or offsets != sorted(offsets):
        return None
    sections = []
    for index, (name, filename, offset) in enumerate(zip(PBP_SECTION_NAMES, PBP_SECTION_FILENAMES, offsets, strict=False)):
        next_offset = offsets[index + 1] if index + 1 < len(offsets) else _file_size
        size = max(0, next_offset - offset)
        signature = data[offset : offset + min(16, size)] if offset < len(data) else b""
        sections.append(
            {
                "name": name,
                "filename": filename,
                "offset": offset,
                "offset_hex": _hex(offset),
                "size": size,
                "signature_hex": signature.hex(" "),
                "empty": size == 0,
            }
        )
    return _detection(
        "sony-psp-pbp",
        "Sony PSP PBP package",
        "Sony PSP",
        "archive",
        "console-archive",
        "MIPS Allegrex",
        {
            "version": _hex(_u32le(data, 0x04)),
            "sections": sections,
        },
    )


def _parse_gamecube_wii_dol(data: bytes, file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x100:
        return None
    if suffix != ".dol" and not _looks_like_dol(data, file_size):
        return None
    if suffix == ".dol" and not _looks_like_dol(data, file_size):
        return None
    text_offsets = [_u32be(data, 0x00 + index * 4) for index in range(7)]
    data_offsets = [_u32be(data, 0x1C + index * 4) for index in range(11)]
    text_addresses = [_u32be(data, 0x48 + index * 4) for index in range(7)]
    data_addresses = [_u32be(data, 0x64 + index * 4) for index in range(11)]
    text_sizes = [_u32be(data, 0x90 + index * 4) for index in range(7)]
    data_sizes = [_u32be(data, 0xAC + index * 4) for index in range(11)]
    sections = _dol_sections("text", text_offsets, text_addresses, text_sizes)
    sections.extend(_dol_sections("data", data_offsets, data_addresses, data_sizes))
    return _detection(
        "nintendo-dol",
        "Nintendo GameCube/Wii DOL executable",
        "Nintendo GameCube / Wii",
        "executable",
        "console-executable",
        "PowerPC 750",
        {
            "entry_point": _hex(_u32be(data, 0xE0)),
            "bss_address": _hex(_u32be(data, 0xD8)),
            "bss_size": _u32be(data, 0xDC),
            "sections": sections,
            "section_count": len(sections),
        },
    )


def _parse_gamecube_wii_disc(data: bytes, _file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x440:
        return None
    gc_magic = _u32be(data, 0x1C)
    wii_magic = _u32be(data, 0x18)
    if gc_magic != 0xC2339F3D and wii_magic != 0x5D1C9EA3 and suffix not in {".gcm", ".iso"}:
        return None
    if gc_magic != 0xC2339F3D and wii_magic != 0x5D1C9EA3:
        return None
    platform = "Nintendo Wii" if wii_magic == 0x5D1C9EA3 else "Nintendo GameCube"
    return _detection(
        "nintendo-gc-wii-disc",
        f"{platform} disc image",
        platform,
        "disc-image",
        "console-disc-image",
        "PowerPC 750",
        {
            "game_code": _clean_ascii(data[0x00:0x04]),
            "maker_code": _clean_ascii(data[0x04:0x06]),
            "disc_number": data[0x06],
            "version": data[0x07],
            "game_name": _clean_ascii(data[0x20:0x60]),
            "dol_offset": _u32be(data, 0x420),
            "fst_offset": _u32be(data, 0x424),
            "fst_size": _u32be(data, 0x428),
            "fst_max_size": _u32be(data, 0x42C),
            "user_position": _u32be(data, 0x434),
            "user_length": _u32be(data, 0x438),
        },
    )


def _parse_nds_rom(data: bytes, file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x160:
        return None
    logo_prefix = data[0xC0:0xC4] == b"\x24\xFF\xAE\x51"
    header_size = _u32le(data, 0x84)
    if suffix != ".nds" and not logo_prefix:
        return None
    if header_size not in {0, 0x4000} and header_size > file_size:
        return None
    return _detection(
        "nintendo-nds-rom",
        "Nintendo DS ROM image",
        "Nintendo DS",
        "rom-image",
        "console-rom",
        "ARM9 / ARM7",
        {
            "title": _clean_ascii(data[0x00:0x0C]),
            "game_code": _clean_ascii(data[0x0C:0x10]),
            "maker_code": _clean_ascii(data[0x10:0x12]),
            "unit_code": _hex(data[0x12], 2),
            "arm9_rom_offset": _u32le(data, 0x20),
            "arm9_entry_address": _hex(_u32le(data, 0x24)),
            "arm9_ram_address": _hex(_u32le(data, 0x28)),
            "arm9_size": _u32le(data, 0x2C),
            "arm7_rom_offset": _u32le(data, 0x30),
            "arm7_entry_address": _hex(_u32le(data, 0x34)),
            "arm7_ram_address": _hex(_u32le(data, 0x38)),
            "arm7_size": _u32le(data, 0x3C),
            "filename_table_offset": _u32le(data, 0x40),
            "filename_table_size": _u32le(data, 0x44),
            "file_allocation_table_offset": _u32le(data, 0x48),
            "file_allocation_table_size": _u32le(data, 0x4C),
            "banner_offset": _u32le(data, 0x68),
            "header_size": header_size,
        },
    )


def _parse_gba_rom(data: bytes, _file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0xC0:
        return None
    if data[0xB2] != 0x96 and suffix != ".gba":
        return None
    if suffix == ".gba" and data[0xB2] != 0x96:
        return None
    return _detection(
        "nintendo-gba-rom",
        "Nintendo Game Boy Advance ROM image",
        "Nintendo Game Boy Advance",
        "rom-image",
        "console-rom",
        "ARM7TDMI",
        {
            "entry_branch": data[0x00:0x04].hex(),
            "title": _clean_ascii(data[0xA0:0xAC]),
            "game_code": _clean_ascii(data[0xAC:0xB0]),
            "maker_code": _clean_ascii(data[0xB0:0xB2]),
            "fixed_value": _hex(data[0xB2], 2),
            "main_unit_code": _hex(data[0xB3], 2),
            "software_version": data[0xBC],
            "header_checksum": _hex(data[0xBD], 2),
        },
    )


def _parse_n64_rom(data: bytes, _file_size: int, suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x40:
        return None
    magic = data[:4]
    byte_order = {
        b"\x80\x37\x12\x40": "big-endian .z64",
        b"\x37\x80\x40\x12": "byte-swapped .v64",
        b"\x40\x12\x37\x80": "little-endian .n64",
    }.get(magic)
    if byte_order is None and suffix not in {".z64", ".v64", ".n64"}:
        return None
    if byte_order is None:
        return None
    title_data = data[0x20:0x34]
    if byte_order == "byte-swapped .v64":
        title_data = _swap16(title_data)
    elif byte_order == "little-endian .n64":
        title_data = _swap32(title_data)
    return _detection(
        "nintendo-n64-rom",
        "Nintendo 64 ROM image",
        "Nintendo 64",
        "rom-image",
        "console-rom",
        "MIPS VR4300",
        {
            "byte_order": byte_order,
            "clock_rate": _hex(_u32be(data, 0x04)),
            "program_counter": _hex(_u32be(data, 0x08)),
            "release_address": _hex(_u32be(data, 0x0C)),
            "crc1": _hex(_u32be(data, 0x10)),
            "crc2": _hex(_u32be(data, 0x14)),
            "title": _clean_ascii(title_data),
            "media_format": _clean_ascii(data[0x3B:0x3C]),
            "cartridge_id": _clean_ascii(data[0x3C:0x3E]),
            "country_code": _clean_ascii(data[0x3E:0x3F]),
        },
    )


def _parse_u8_archive(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or _u32be(data, 0) != 0x55AA382D:
        return None
    return _detection(
        "nintendo-u8",
        "Nintendo U8 archive",
        "Nintendo GameCube / Wii",
        "archive",
        "console-archive",
        "",
        {
            "root_node_offset": _u32be(data, 0x04),
            "header_size": _u32be(data, 0x08),
            "data_offset": _u32be(data, 0x0C),
        },
    )


def _parse_rarc_archive(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or data[:4] != b"RARC":
        return None
    return _detection(
        "nintendo-rarc",
        "Nintendo RARC archive",
        "Nintendo GameCube / Wii",
        "archive",
        "console-archive",
        "",
        {
            "file_size": _u32be(data, 0x04),
            "file_data_offset": _u32be(data, 0x0C) + 0x20,
            "file_data_length": _u32be(data, 0x10),
        },
    )


def _parse_sarc_archive(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or data[:4] != b"SARC":
        return None
    endian = ">" if data[0x06:0x08] == b"\xFE\xFF" else "<" if data[0x06:0x08] == b"\xFF\xFE" else ">"
    header_len = _unpack_u16(data, 0x04, endian)
    node_count = None
    hash_multiplier = None
    if len(data) >= header_len + 0x0C and data[header_len:header_len + 4] == b"SFAT":
        node_count = _unpack_u16(data, header_len + 0x06, endian)
        hash_multiplier = _unpack_u32(data, header_len + 0x08, endian)
    return _detection(
        "nintendo-sarc",
        "Nintendo SARC archive",
        "Nintendo 3DS / Wii U / Switch",
        "archive",
        "console-archive",
        "",
        {
            "endianness": "big" if endian == ">" else "little",
            "header_length": header_len,
            "file_length": _unpack_u32(data, 0x08, endian),
            "data_offset": _unpack_u32(data, 0x0C, endian),
            "node_count": node_count,
            "hash_multiplier": hash_multiplier,
        },
    )


def _parse_yaz0_stream(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x10 or data[:4] != b"Yaz0":
        return None
    return _detection(
        "nintendo-yaz0",
        "Nintendo Yaz0 compressed stream",
        "Nintendo GameCube / Wii / Wii U / Switch",
        "compressed",
        "console-compressed",
        "",
        {
            "decompressed_size": _u32be(data, 0x04),
            "required_alignment": _u32be(data, 0x08),
            "payload_offset": 0x10,
        },
    )


def _parse_cri_cpk(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x20 or data[:4] != b"CPK ":
        return None
    return _detection(
        "cri-cpk",
        "CRI Middleware CPK archive",
        "Multi-console middleware",
        "archive",
        "console-archive",
        "",
        {
            "magic": "CPK ",
            "utf_table_hint": _clean_ascii(data[0x10:0x14]),
            "notes": "CPK is common in PS3, PSP, Vita, Wii, Wii U, 3DS, Switch, and PC game assets.",
        },
    )


def _parse_cri_afs(data: bytes, file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x10 or data[:4] not in {b"AFS\x00", b"AFS "}:
        return None
    file_count = _u32le(data, 0x04)
    if file_count > 100000:
        return None
    entries = []
    table_end = 0x08 + min(file_count, 16) * 8
    if table_end <= len(data):
        for index in range(min(file_count, 16)):
            offset = _u32le(data, 0x08 + index * 8)
            size = _u32le(data, 0x0C + index * 8)
            if offset or size:
                entries.append({"index": index, "offset": offset, "size": size})
    return _detection(
        "cri-afs",
        "CRI Middleware AFS archive",
        "Dreamcast / PlayStation 2 / multi-console middleware",
        "archive",
        "console-archive",
        "",
        {
            "file_count": file_count,
            "sample_entries": entries,
            "observed_file_size": file_size,
        },
    )


def _parse_xbox_xbe(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x110 or data[:4] != b"XBEH":
        return None
    return _detection(
        "xbox-xbe",
        "Microsoft Xbox XBE executable",
        "Microsoft Xbox",
        "executable",
        "console-executable",
        "x86",
        {
            "base_address": _hex(_u32le(data, 0x104)),
            "header_size": _u32le(data, 0x108),
            "image_size": _u32le(data, 0x10C),
        },
    )


def _parse_xbox_xex(data: bytes, _file_size: int, _suffix: str) -> dict[str, Any] | None:
    if len(data) < 0x18 or data[:4] != b"XEX2":
        return None
    return _detection(
        "xbox360-xex",
        "Microsoft Xbox 360 XEX executable",
        "Microsoft Xbox 360",
        "executable",
        "console-executable",
        "PowerPC",
        {
            "module_flags": _hex(_u32be(data, 0x04)),
            "data_offset": _u32be(data, 0x08),
            "header_count": _u32be(data, 0x0C),
        },
    )


def _classify_console_elf(elf_metadata: dict[str, object] | None, suffix: str) -> dict[str, Any] | None:
    if not elf_metadata:
        return None
    machine = str(elf_metadata.get("machine", ""))
    bits = int(elf_metadata.get("bits", 0) or 0)
    mips_flags = elf_metadata.get("mips_flags")
    if machine == "MIPS":
        variant = ""
        if isinstance(mips_flags, dict):
            variant = str(mips_flags.get("machine_variant", ""))
        platform = "Sony PlayStation 2" if variant == "R5900" or suffix == ".elf" else "Sony PSP / PlayStation 2"
        return _detection(
            "sony-mips-elf",
            f"{platform} ELF executable",
            platform,
            "executable",
            "console-executable",
            "MIPS R5900 / Allegrex",
            {"elf": elf_metadata},
        )
    if machine == "PowerPC":
        platform = "Sony PlayStation 3 PPU" if bits == 64 else "Nintendo GameCube / Wii"
        return _detection(
            "powerpc-console-elf",
            f"{platform} ELF executable",
            platform,
            "executable",
            "console-executable",
            "PowerPC",
            {"elf": elf_metadata},
        )
    if machine == "ARM" and suffix in {".elf", ".axf"}:
        return _detection(
            "arm-console-elf",
            "ARM console ELF executable",
            "Nintendo DS / Game Boy Advance / PSP support tooling",
            "executable",
            "console-executable",
            "ARM",
            {"elf": elf_metadata},
        )
    return None


def _looks_like_dol(data: bytes, file_size: int) -> bool:
    sections = 0
    entry = _u32be(data, 0xE0)
    if not 0x80000000 <= entry <= 0x81800000:
        return False
    for offset_base, size_base in ((0x00, 0x90), (0x1C, 0xAC)):
        count = 7 if offset_base == 0x00 else 11
        for index in range(count):
            offset = _u32be(data, offset_base + index * 4)
            size = _u32be(data, size_base + index * 4)
            if not offset and not size:
                continue
            if offset < 0x100 or offset >= file_size + 0x100 or size > file_size:
                return False
            sections += 1
    return sections > 0


def _dol_sections(kind: str, offsets: list[int], addresses: list[int], sizes: list[int]) -> list[dict[str, Any]]:
    sections = []
    for index, (offset, address, size) in enumerate(zip(offsets, addresses, sizes, strict=False)):
        if not offset and not size:
            continue
        sections.append(
            {
                "name": f".{kind}{index}",
                "file_offset": offset,
                "load_address": _hex(address),
                "size": size,
                "kind": kind,
            }
        )
    return sections


def _dedupe_detections(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for detection in detections:
        key = detection["format_id"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(detection)
    return unique


def _detection(
    format_id: str,
    display_name: str,
    platform: str,
    family: str,
    target_type: str,
    architecture: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format_id": format_id,
        "display_name": display_name,
        "platform": platform,
        "family": family,
        "target_type": target_type,
        "architecture": architecture,
        "metadata": metadata,
    }


def _clean_ascii(data: bytes) -> str:
    if not data:
        return ""
    trimmed = data.split(b"\x00", 1)[0]
    return "".join(chr(byte) if 32 <= byte <= 126 else " " for byte in trimmed).strip()


def _swap16(data: bytes) -> bytes:
    out = bytearray()
    for index in range(0, len(data), 2):
        out.extend(data[index:index + 2][::-1])
    return bytes(out)


def _swap32(data: bytes) -> bytes:
    out = bytearray()
    for index in range(0, len(data), 4):
        out.extend(data[index:index + 4][::-1])
    return bytes(out)


def _hex(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}x}"


def _u16be(data: bytes, offset: int) -> int:
    return _unpack_u16(data, offset, ">")


def _u32be(data: bytes, offset: int) -> int:
    return _unpack_u32(data, offset, ">")


def _u64be(data: bytes, offset: int) -> int:
    if offset + 8 > len(data):
        return 0
    return struct.unpack_from(">Q", data, offset)[0]


def _u32le(data: bytes, offset: int) -> int:
    return _unpack_u32(data, offset, "<")


def _unpack_u16(data: bytes, offset: int, endian: str) -> int:
    if offset + 2 > len(data):
        return 0
    return struct.unpack_from(f"{endian}H", data, offset)[0]


def _unpack_u32(data: bytes, offset: int, endian: str) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from(f"{endian}I", data, offset)[0]
