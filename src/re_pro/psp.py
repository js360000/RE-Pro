from __future__ import annotations

from dataclasses import dataclass
import json
import struct
from pathlib import Path
from typing import Any

from .utils import ensure_dir, sanitize_relative_source_path


PBP_MAGIC = b"\x00PBP"
PARAM_SFO_MAGIC = b"\x00PSF"
PBP_HEADER_SIZE = 0x28
PBP_METADATA_NAME = "pbp_manifest.json"
PARAM_SFO_JSON_NAME = "PARAM.SFO.json"
PSP_SECTION_METADATA_NAMES = {
    PBP_METADATA_NAME,
    "DATA.PSP.manifest.json",
    "DATA.PSAR.manifest.json",
}

PBP_SECTION_FILENAMES = (
    "PARAM.SFO",
    "ICON0.PNG",
    "ICON1.PMF",
    "PIC0.PNG",
    "PIC1.PNG",
    "SND0.AT3",
    "DATA.PSP",
    "DATA.PSAR",
)
PBP_SECTION_NAMES = tuple(name.lower().replace(".", "_") for name in PBP_SECTION_FILENAMES)

SFO_FORMAT_UTF8_SPECIAL = 0x0004
SFO_FORMAT_UTF8 = 0x0204
SFO_FORMAT_UINT32 = 0x0404


class PspFormatError(ValueError):
    """Raised when a PSP PBP/SFO payload is malformed."""


@dataclass
class PbpSection:
    index: int
    name: str
    filename: str
    offset: int
    size: int
    data: bytes

    def to_manifest(self, *, include_data: bool = False) -> dict[str, Any]:
        payload = {
            "index": self.index,
            "name": self.name,
            "filename": self.filename,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "size": self.size,
            "signature_hex": self.data[:16].hex(" "),
            "empty": self.size == 0,
        }
        if include_data:
            payload["data_hex"] = self.data.hex()
        return payload


@dataclass
class PbpArchive:
    path: Path
    version: int
    sections: list[PbpSection]

    def to_manifest(self) -> dict[str, Any]:
        return {
            "format": "sony-psp-pbp",
            "path": str(self.path),
            "version": self.version,
            "version_hex": f"0x{self.version:08x}",
            "section_count": len(self.sections),
            "sections": [section.to_manifest() for section in self.sections],
        }

    def section(self, filename: str) -> PbpSection | None:
        normalized = filename.upper()
        for section in self.sections:
            if section.filename.upper() == normalized:
                return section
        return None


def is_pbp(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == PBP_MAGIC
    except OSError:
        return False


def is_param_sfo(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == PARAM_SFO_MAGIC
    except OSError:
        return False


def parse_pbp(path: str | Path) -> PbpArchive:
    pbp_path = Path(path).resolve()
    data = pbp_path.read_bytes()
    if len(data) < PBP_HEADER_SIZE or data[:4] != PBP_MAGIC:
        raise PspFormatError(f"Not a PSP PBP file: {pbp_path}")
    version = _u32le(data, 0x04)
    offsets = [_u32le(data, 0x08 + index * 4) for index in range(len(PBP_SECTION_FILENAMES))]
    if any(offset < PBP_HEADER_SIZE or offset > len(data) for offset in offsets):
        raise PspFormatError(f"PBP section offset outside file bounds: {pbp_path}")
    if offsets != sorted(offsets):
        raise PspFormatError(f"PBP section offsets are not monotonic: {pbp_path}")

    sections: list[PbpSection] = []
    for index, (name, filename, offset) in enumerate(zip(PBP_SECTION_NAMES, PBP_SECTION_FILENAMES, offsets, strict=False)):
        next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        size = max(0, next_offset - offset)
        sections.append(
            PbpSection(
                index=index,
                name=name,
                filename=filename,
                offset=offset,
                size=size,
                data=data[offset : offset + size],
            )
        )
    return PbpArchive(path=pbp_path, version=version, sections=sections)


def extract_pbp(
    archive_path: str | Path,
    destination_root: str | Path,
    *,
    max_section_bytes: int = 256 * 1024 * 1024,
) -> dict[str, Any]:
    archive = parse_pbp(archive_path)
    output_dir = ensure_dir(Path(destination_root))
    warnings: list[str] = []
    extracted: list[dict[str, Any]] = []

    for section in archive.sections:
        if section.size > max_section_bytes:
            warnings.append(f"Skipped {section.filename}; section size {section.size} exceeds cap {max_section_bytes}.")
            continue
        section_path = output_dir / section.filename
        section_path.write_bytes(section.data)
        extracted.append({"section": section.name, "filename": section.filename, "path": str(section_path), "size": section.size})
        if section.filename == "PARAM.SFO" and section.data:
            try:
                manifest = parse_param_sfo(section.data)
                (output_dir / PARAM_SFO_JSON_NAME).write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
            except PspFormatError as exc:
                warnings.append(f"PARAM.SFO parse failed: {exc}")
        elif section.filename == "DATA.PSP" and section.data:
            manifest = parse_data_psp(section.data)
            (output_dir / "DATA.PSP.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        elif section.filename == "DATA.PSAR" and section.data:
            manifest = parse_data_psar(section.data)
            (output_dir / "DATA.PSAR.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    manifest_path = output_dir / PBP_METADATA_NAME
    manifest_path.write_text(json.dumps(archive.to_manifest(), indent=2), encoding="utf-8")
    return {
        "ok": True,
        "format": "sony-psp-pbp",
        "archive_path": str(archive.path),
        "output_dir": str(output_dir),
        "manifest_path": str(manifest_path),
        "extracted_file_count": len(extracted),
        "files": extracted,
        "warnings": warnings,
    }


def rebuild_pbp_with_overlay(base_archive: str | Path, overlay_root: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    base = Path(base_archive).resolve()
    overlay = Path(overlay_root).resolve()
    archive = parse_pbp(base)
    output = Path(output_path).resolve() if output_path else base.with_suffix(".rebuilt.PBP")
    ensure_dir(output.parent)

    payloads: list[bytes] = []
    replaced: list[str] = []
    for section in archive.sections:
        section_path = overlay / sanitize_relative_source_path(section.filename)
        data = section.data
        if section.filename == "PARAM.SFO":
            json_path = overlay / PARAM_SFO_JSON_NAME
            use_json = json_path.exists() and (
                not section_path.exists() or json_path.stat().st_mtime >= section_path.stat().st_mtime
            )
            if use_json:
                data = build_param_sfo_from_json(json_path)
                section_path.write_bytes(data)
                replaced.append(PARAM_SFO_JSON_NAME)
            elif section_path.exists() and section_path.is_file():
                data = section_path.read_bytes()
                replaced.append(section.filename)
        elif section_path.exists() and section_path.is_file():
            data = section_path.read_bytes()
            replaced.append(section.filename)
        payloads.append(data)

    _write_pbp(output, archive.version, payloads)
    return {
        "ok": True,
        "kind": "pbp_rebuild",
        "base_archive": str(base),
        "overlay_root": str(overlay),
        "rebuilt_artifact": str(output),
        "replaced_entries": sorted(set(replaced)),
        "section_count": len(payloads),
        "size": output.stat().st_size,
    }


def _write_pbp(path: Path, version: int, section_payloads: list[bytes]) -> None:
    if len(section_payloads) != len(PBP_SECTION_FILENAMES):
        raise PspFormatError(f"PBP requires exactly {len(PBP_SECTION_FILENAMES)} sections.")
    offsets: list[int] = []
    cursor = PBP_HEADER_SIZE
    for payload in section_payloads:
        offsets.append(cursor)
        cursor += len(payload)
    with path.open("wb") as handle:
        handle.write(PBP_MAGIC)
        handle.write(struct.pack("<I", version))
        for offset in offsets:
            handle.write(struct.pack("<I", offset))
        for payload in section_payloads:
            handle.write(payload)


def parse_param_sfo_file(path: str | Path) -> dict[str, Any]:
    return parse_param_sfo(Path(path).read_bytes(), source_path=str(Path(path).resolve()))


def parse_param_sfo(data: bytes, *, source_path: str = "") -> dict[str, Any]:
    if len(data) < 0x14 or data[:4] != PARAM_SFO_MAGIC:
        raise PspFormatError("Not a PARAM.SFO payload.")
    version = _u32le(data, 0x04)
    key_table_offset = _u32le(data, 0x08)
    data_table_offset = _u32le(data, 0x0C)
    count = _u32le(data, 0x10)
    if count > 4096:
        raise PspFormatError(f"Unreasonable PARAM.SFO entry count: {count}")
    index_end = 0x14 + count * 0x10
    if index_end > len(data) or key_table_offset > len(data) or data_table_offset > len(data):
        raise PspFormatError("PARAM.SFO table offsets exceed payload size.")

    entries: list[dict[str, Any]] = []
    values: dict[str, Any] = {}
    for index in range(count):
        cursor = 0x14 + index * 0x10
        key_offset = _u16le(data, cursor)
        format_code = _u16le(data, cursor + 2)
        length = _u32le(data, cursor + 4)
        max_length = _u32le(data, cursor + 8)
        data_offset = _u32le(data, cursor + 12)
        key_start = key_table_offset + key_offset
        if key_start >= len(data):
            raise PspFormatError(f"PARAM.SFO key {index} starts outside payload.")
        key_end = data.find(b"\x00", key_start)
        if key_end < 0:
            raise PspFormatError(f"PARAM.SFO key {index} is not NUL terminated.")
        key = data[key_start:key_end].decode("ascii", errors="replace")
        value_start = data_table_offset + data_offset
        value_end = min(len(data), value_start + length)
        raw_value = data[value_start:value_end]
        entry: dict[str, Any] = {
            "index": index,
            "key": key,
            "format": _sfo_format_name(format_code),
            "format_code": f"0x{format_code:04x}",
            "length": length,
            "max_length": max_length,
            "key_offset": key_offset,
            "data_offset": data_offset,
        }
        if format_code in {SFO_FORMAT_UTF8_SPECIAL, SFO_FORMAT_UTF8}:
            value = raw_value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            entry["value"] = value
            values[key] = value
        elif format_code == SFO_FORMAT_UINT32:
            value = _u32le(raw_value.ljust(4, b"\x00"), 0)
            entry["value"] = value
            values[key] = value
        else:
            entry["value_hex"] = raw_value.hex()
            values[key] = {"hex": raw_value.hex()}
        entries.append(entry)

    return {
        "format": "param_sfo",
        "source_path": source_path,
        "version": version,
        "version_hex": f"0x{version:08x}",
        "key_table_offset": key_table_offset,
        "data_table_offset": data_table_offset,
        "entry_count": count,
        "entries": entries,
        "values": values,
    }


def build_param_sfo_from_json(path: str | Path) -> bytes:
    payload = json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(payload, dict):
        raise PspFormatError(f"Expected PARAM.SFO JSON object: {path}")
    return build_param_sfo(payload)


def build_param_sfo(payload: dict[str, Any]) -> bytes:
    entries_payload = payload.get("entries")
    values = payload.get("values") if isinstance(payload.get("values"), dict) else {}
    if not isinstance(entries_payload, list):
        entries_payload = [
            {"key": key, "value": value, "format_code": "0x0404" if isinstance(value, int) else "0x0204"}
            for key, value in values.items()
        ]
    version = _parse_int(payload.get("version_hex", payload.get("version", 0x101)), default=0x101)
    normalized: list[dict[str, Any]] = []
    for raw_entry in entries_payload:
        if not isinstance(raw_entry, dict):
            continue
        key = str(raw_entry.get("key", "")).strip()
        if not key:
            continue
        format_code = _parse_sfo_format_code(raw_entry)
        value = values.get(key, raw_entry.get("value"))
        max_length = _parse_int(raw_entry.get("max_length", raw_entry.get("length", 0)), default=0)
        raw_bytes, value_length, max_length = _encode_sfo_value(format_code, value, raw_entry, max_length)
        normalized.append(
            {
                "key": key,
                "format_code": format_code,
                "length": value_length,
                "max_length": max_length,
                "raw_bytes": raw_bytes,
            }
        )

    key_table = bytearray()
    for entry in normalized:
        entry["key_offset"] = len(key_table)
        key_table.extend(entry["key"].encode("ascii", errors="replace"))
        key_table.append(0)

    key_table_offset = 0x14 + len(normalized) * 0x10
    data_table_offset = _align4(key_table_offset + len(key_table))
    data_table = bytearray()
    for entry in normalized:
        while len(data_table) % 4:
            data_table.append(0)
        entry["data_offset"] = len(data_table)
        data_table.extend(entry["raw_bytes"])

    result = bytearray()
    result.extend(PARAM_SFO_MAGIC)
    result.extend(struct.pack("<IIII", version, key_table_offset, data_table_offset, len(normalized)))
    for entry in normalized:
        result.extend(
            struct.pack(
                "<HHIII",
                int(entry["key_offset"]),
                int(entry["format_code"]),
                int(entry["length"]),
                int(entry["max_length"]),
                int(entry["data_offset"]),
            )
        )
    result.extend(key_table)
    while len(result) < data_table_offset:
        result.append(0)
    result.extend(data_table)
    return bytes(result)


def parse_data_psp(data: bytes, *, source_path: str = "") -> dict[str, Any]:
    magic = data[:4]
    if magic == b"~PSP":
        module_name = _clean_ascii(data[0x0A:0x0A + 28])
        return {
            "format": "sony-psp-data-psp",
            "source_path": source_path,
            "size": len(data),
            "magic": "~PSP",
            "module_name": module_name,
            "header_hex": data[:128].hex(" "),
            "encrypted_or_signed_likely": True,
            "notes": "Signed PSP PRX/PBOOT-style executable payload; preserve exact bytes unless a legal PSP decryptor is configured.",
        }
    if magic == b"\x7fELF":
        return {
            "format": "sony-psp-data-psp",
            "source_path": source_path,
            "size": len(data),
            "magic": "ELF",
            "embedded_format": "ELF",
            "encrypted_or_signed_likely": False,
        }
    return {
        "format": "sony-psp-data-psp",
        "source_path": source_path,
        "size": len(data),
        "magic": magic.hex(" "),
        "header_hex": data[:128].hex(" "),
        "encrypted_or_signed_likely": True,
    }


def parse_data_psar(data: bytes, *, source_path: str = "") -> dict[str, Any]:
    markers = []
    for marker in (b"\x00PSF", b"~PSP", b"\x7fELF", b"SCE\x00"):
        start = 0
        while len(markers) < 64:
            found = data.find(marker, start)
            if found < 0:
                break
            markers.append({"marker": marker.hex(" "), "offset": found, "offset_hex": f"0x{found:x}"})
            start = found + 1
    return {
        "format": "sony-psp-data-psar",
        "source_path": source_path,
        "size": len(data),
        "magic": data[:4].decode("ascii", errors="replace") if data[:4] == b"PSAR" else data[:4].hex(" "),
        "version_or_flags_le": _u32le(data, 0x04) if len(data) >= 8 else 0,
        "version_or_flags_hex": f"0x{_u32le(data, 0x04):08x}" if len(data) >= 8 else "0x00000000",
        "header_hex": data[:128].hex(" "),
        "known_marker_hits": markers,
        "encrypted_or_packed_likely": True,
        "notes": "PSP firmware DATA.PSAR payload; this is distinct from PSARC and commonly needs PSP updater/PSAR-specific unpacking.",
    }


def _parse_sfo_format_code(entry: dict[str, Any]) -> int:
    value = entry.get("format_code", entry.get("format"))
    if isinstance(value, str):
        lowered = value.lower().strip()
        if lowered in {"utf8", "string", "str"}:
            return SFO_FORMAT_UTF8
        if lowered in {"utf8-special", "utf8_special"}:
            return SFO_FORMAT_UTF8_SPECIAL
        if lowered in {"uint32", "int", "integer"}:
            return SFO_FORMAT_UINT32
    return _parse_int(value, default=SFO_FORMAT_UTF8)


def _encode_sfo_value(format_code: int, value: Any, entry: dict[str, Any], max_length: int) -> tuple[bytes, int, int]:
    if format_code in {SFO_FORMAT_UTF8_SPECIAL, SFO_FORMAT_UTF8}:
        text = "" if value is None else str(value)
        encoded = text.encode("utf-8") + b"\x00"
        max_length = max(max_length, len(encoded))
        return encoded.ljust(max_length, b"\x00"), len(encoded), max_length
    if format_code == SFO_FORMAT_UINT32:
        number = _parse_int(value, default=0)
        max_length = max(max_length, 4)
        return struct.pack("<I", number).ljust(max_length, b"\x00"), 4, max_length
    raw_hex = entry.get("value_hex")
    if isinstance(value, dict) and "hex" in value:
        raw_hex = value.get("hex")
    if raw_hex is None:
        raw = b"" if value is None else str(value).encode("utf-8")
    else:
        raw = bytes.fromhex(str(raw_hex))
    max_length = max(max_length, len(raw))
    return raw.ljust(max_length, b"\x00"), len(raw), max_length


def _sfo_format_name(format_code: int) -> str:
    if format_code == SFO_FORMAT_UTF8_SPECIAL:
        return "utf8-special"
    if format_code == SFO_FORMAT_UTF8:
        return "utf8"
    if format_code == SFO_FORMAT_UINT32:
        return "uint32"
    return f"unknown-0x{format_code:04x}"


def _parse_int(value: Any, *, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def _clean_ascii(data: bytes) -> str:
    trimmed = data.split(b"\x00", 1)[0]
    return "".join(chr(byte) if 32 <= byte <= 126 else " " for byte in trimmed).strip()


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _u16le(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, offset)[0]


def _u32le(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, offset)[0]
