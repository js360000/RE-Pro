from __future__ import annotations

import hashlib
import json
import lzma
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .utils import ensure_dir, sanitize_relative_source_path

PSARC_MAGIC = b"PSAR"
PSARC_HEADER_SIZE = 0x20
PSARC_ENTRY_SIZE = 0x1E
PSARC_DEFAULT_BLOCK_SIZE = 0x10000
PSARC_MANIFEST_NAME = "__manifest__"
PSARC_METADATA_NAME = "psarc_manifest.json"
PSARC_TOC_ENCRYPTED_FLAG = 0x04
ROCKSMITH_PSARC_KEY = bytes(
    [
        0xC5,
        0x3D,
        0xB2,
        0x38,
        0x70,
        0xA1,
        0xA2,
        0xF7,
        0x1C,
        0xAE,
        0x64,
        0x06,
        0x1F,
        0xDD,
        0x0E,
        0x11,
        0x57,
        0x30,
        0x9D,
        0xC8,
        0x52,
        0x04,
        0xD4,
        0xC5,
        0xBF,
        0xDF,
        0x25,
        0x09,
        0x0D,
        0xF2,
        0x57,
        0x2C,
    ]
)


class PsarcFormatError(ValueError):
    """Raised when a file looks like PSARC but has invalid archive structure."""


@dataclass
class PsarcEntry:
    index: int
    name_digest: bytes
    block_index: int
    uncompressed_size: int
    data_offset: int
    path: str = ""
    block_sizes: list[int] = field(default_factory=list)
    block_compression: list[str] = field(default_factory=list)
    compression: str = "unknown"
    compression_level: int | None = None

    @property
    def is_manifest(self) -> bool:
        return self.index == 0

    @property
    def display_path(self) -> str:
        return self.path or (PSARC_MANIFEST_NAME if self.is_manifest else f"entry_{self.index:05d}.bin")


@dataclass
class PsarcArchive:
    path: Path
    version: bytes
    compression: str
    compression_field: bytes
    toc_size: int
    toc_entry_size: int
    entry_count: int
    block_size: int
    archive_flags: int
    block_size_table: list[int]
    entries: list[PsarcEntry]
    manifest_paths: list[str] = field(default_factory=list)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "format": "psarc",
            "path": str(self.path),
            "version": ".".join(str(part) for part in struct.unpack(">HH", self.version)),
            "compression": self.compression or "none",
            "toc_size": self.toc_size,
            "toc_entry_size": self.toc_entry_size,
            "entry_count": self.entry_count,
            "block_size": self.block_size,
            "archive_flags": self.archive_flags,
            "manifest_paths": self.manifest_paths,
            "entries": [
                {
                    "index": entry.index,
                    "path": entry.display_path,
                    "name_digest": entry.name_digest.hex(),
                    "block_index": entry.block_index,
                    "block_count": len(entry.block_sizes),
                    "uncompressed_size": entry.uncompressed_size,
                    "data_offset": entry.data_offset,
                    "block_sizes": entry.block_sizes,
                    "block_compression": entry.block_compression,
                    "compression": entry.compression,
                    "compression_level": entry.compression_level,
                }
                for entry in self.entries
            ],
        }


@dataclass
class _BuildEntry:
    index: int
    path: str
    name_digest: bytes
    uncompressed_size: int
    payload: bytes
    block_sizes: list[int]
    block_index: int = 0
    data_offset: int = 0
    compression: str = "unknown"
    compression_level: int | None = None
    source_index: int | None = None
    changed: bool = False
    added: bool = False


def is_psarc(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == PSARC_MAGIC
    except OSError:
        return False


def parse_psarc(path: str | Path, *, inspect_blocks: bool = False) -> PsarcArchive:
    archive_path = Path(path).resolve()
    with archive_path.open("rb") as handle:
        header = handle.read(PSARC_HEADER_SIZE)
        if len(header) < PSARC_HEADER_SIZE or header[:4] != PSARC_MAGIC:
            raise PsarcFormatError(f"Not a PSARC archive: {archive_path}")
        version = header[0x04:0x08]
        compression_field = header[0x08:0x0C]
        compression = _decode_compression(compression_field)
        toc_size = _u32be(header, 0x0C)
        toc_entry_size = _u32be(header, 0x10)
        entry_count = _u32be(header, 0x14)
        block_size = _u32be(header, 0x18) or PSARC_DEFAULT_BLOCK_SIZE
        archive_flags = _u32be(header, 0x1C)
        if toc_size < PSARC_HEADER_SIZE:
            raise PsarcFormatError(f"Invalid PSARC ToC size {toc_size} in {archive_path}")
        if toc_entry_size < PSARC_ENTRY_SIZE:
            raise PsarcFormatError(f"Invalid PSARC ToC entry size {toc_entry_size} in {archive_path}")
        if entry_count > 1_000_000:
            raise PsarcFormatError(f"Unreasonable PSARC entry count {entry_count} in {archive_path}")
        toc_payload = handle.read(toc_size - PSARC_HEADER_SIZE)
    if archive_flags & PSARC_TOC_ENCRYPTED_FLAG:
        toc_payload = _crypt_rocksmith_psarc_toc(toc_payload, decrypt=True)
    entry_table_size = entry_count * toc_entry_size
    if len(toc_payload) < entry_table_size:
        raise PsarcFormatError(f"Truncated PSARC ToC in {archive_path}")
    block_table_bytes = toc_payload[entry_table_size:]
    block_field_size = _block_table_field_size(block_size)
    block_size_table = [
        int.from_bytes(block_table_bytes[offset : offset + block_field_size], "big")
        for offset in range(0, len(block_table_bytes) - block_field_size + 1, block_field_size)
    ]
    entries: list[PsarcEntry] = []
    for index in range(entry_count):
        cursor = index * toc_entry_size
        name_digest = bytes(toc_payload[cursor : cursor + 16])
        block_index = _u32be(toc_payload, cursor + 16)
        uncompressed_size = _u40be(toc_payload, cursor + 20)
        data_offset = _u40be(toc_payload, cursor + 25)
        block_count = _block_count(uncompressed_size, block_size)
        entry_block_sizes = block_size_table[block_index : block_index + block_count]
        entry = PsarcEntry(
            index=index,
            name_digest=name_digest,
            block_index=block_index,
            uncompressed_size=uncompressed_size,
            data_offset=data_offset,
            block_sizes=list(entry_block_sizes),
        )
        _infer_entry_compression(archive_compression=compression, block_size=block_size, entry=entry)
        entries.append(entry)

    archive = PsarcArchive(
        path=archive_path,
        version=version,
        compression=compression,
        compression_field=compression_field,
        toc_size=toc_size,
        toc_entry_size=toc_entry_size,
        entry_count=entry_count,
        block_size=block_size,
        archive_flags=archive_flags,
        block_size_table=block_size_table,
        entries=entries,
    )
    if entries:
        _attach_manifest_paths(archive)
    if inspect_blocks:
        for entry in archive.entries:
            _entry_compression_profile(archive, entry)
    return archive


def read_entry_data(archive: PsarcArchive, entry: PsarcEntry, *, max_bytes: int | None = None) -> bytes:
    if max_bytes is not None and entry.uncompressed_size > max_bytes:
        raise PsarcFormatError(f"PSARC entry {entry.display_path} exceeds read cap ({entry.uncompressed_size} bytes)")
    output = bytearray()
    remaining = entry.uncompressed_size
    with archive.path.open("rb") as handle:
        handle.seek(entry.data_offset)
        for block_position, table_size in enumerate(entry.block_sizes):
            disk_size = _disk_block_size(table_size, archive.block_size)
            compressed = handle.read(disk_size)
            expected = min(archive.block_size, remaining)
            decoded, codec, level = _decode_block(archive.compression, compressed, expected)
            output.extend(decoded[:expected])
            if len(entry.block_compression) <= block_position:
                entry.block_compression.append(codec)
            else:
                entry.block_compression[block_position] = codec
            if level is not None and entry.compression_level is None:
                entry.compression_level = level
            remaining -= min(expected, len(decoded))
            if remaining <= 0:
                break
    return bytes(output[: entry.uncompressed_size])


def extract_psarc(
    archive_path: str | Path,
    output_dir: str | Path,
    *,
    max_members: int = 5000,
    max_member_bytes: int = 128 * 1024 * 1024,
) -> dict[str, Any]:
    archive = parse_psarc(archive_path)
    destination_root = ensure_dir(Path(output_dir).resolve())
    extracted: list[dict[str, Any]] = []
    warnings: list[str] = []
    for entry in archive.entries[1:]:
        if len(extracted) >= max_members:
            warnings.append(f"Skipped remaining PSARC entries after cap of {max_members}.")
            break
        if entry.uncompressed_size > max_member_bytes:
            warnings.append(f"Skipped {entry.display_path}; size {entry.uncompressed_size} exceeds cap.")
            continue
        relative = sanitize_relative_source_path(entry.display_path)
        destination = (destination_root / relative).resolve()
        if not _is_relative_to(destination, destination_root):
            warnings.append(f"Skipped unsafe PSARC path {entry.display_path}.")
            continue
        ensure_dir(destination.parent)
        destination.write_bytes(read_entry_data(archive, entry, max_bytes=max_member_bytes))
        extracted.append(
            {
                "index": entry.index,
                "path": entry.display_path,
                "extracted_path": str(destination),
                "uncompressed_size": entry.uncompressed_size,
                "compression": entry.compression,
                "compression_level": entry.compression_level,
            }
        )
    manifest = archive.to_manifest()
    manifest.update(
        {
            "output_dir": str(destination_root),
            "extracted_file_count": len(extracted),
            "extracted_files": extracted,
            "warnings": warnings,
        }
    )
    manifest_path = destination_root / PSARC_METADATA_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "archive": str(archive.path),
        "output_dir": str(destination_root),
        "manifest_path": str(manifest_path),
        "entry_count": archive.entry_count,
        "extracted_file_count": len(extracted),
        "warnings": warnings,
    }


def rebuild_psarc_with_overlay(base_archive: Path, overlay_root: Path, output_path: Path | None = None) -> dict[str, Any]:
    base_archive = base_archive.resolve()
    overlay_root = overlay_root.resolve()
    if not base_archive.exists() or not base_archive.is_file():
        return {"ok": False, "error": f"Base PSARC not found: {base_archive}"}
    if not overlay_root.exists() or not overlay_root.is_dir():
        return {"ok": False, "error": f"Overlay root not found: {overlay_root}"}
    archive = parse_psarc(base_archive)
    if output_path is None:
        output_path = base_archive.with_name(f"{base_archive.stem}.rebuilt{base_archive.suffix}")
    output_path = output_path.resolve()
    ensure_dir(output_path.parent)

    existing_entries = archive.entries[1:]
    existing_by_safe_path = {
        sanitize_relative_source_path(entry.display_path).lower(): entry
        for entry in existing_entries
    }
    additions = _overlay_additions(overlay_root, set(existing_by_safe_path))
    added_manifest_paths = [
        _new_manifest_path(relative, archive)
        for relative, _path in additions
    ]
    manifest_paths = [entry.display_path for entry in existing_entries] + added_manifest_paths

    build_entries: list[_BuildEntry] = []
    manifest_entry = archive.entries[0] if archive.entries else None
    if manifest_entry is not None and not additions:
        build_entries.append(_preserve_entry_payload(archive, manifest_entry, path=PSARC_MANIFEST_NAME))
    else:
        manifest_digest = manifest_entry.name_digest if manifest_entry is not None else bytes(16)
        manifest_codec, manifest_level = _entry_codec_for_replacement(archive, manifest_entry)
        manifest_data = _encode_manifest(manifest_paths)
        payload, block_sizes = _compress_data(manifest_data, manifest_codec, archive.block_size, manifest_level)
        build_entries.append(
            _BuildEntry(
                index=0,
                path=PSARC_MANIFEST_NAME,
                name_digest=manifest_digest,
                uncompressed_size=len(manifest_data),
                payload=payload,
                block_sizes=block_sizes,
                compression=manifest_codec,
                compression_level=manifest_level,
                source_index=0 if manifest_entry is not None else None,
                changed=True,
            )
        )

    replaced: list[str] = []
    preserved: list[str] = []
    for entry in existing_entries:
        relative = sanitize_relative_source_path(entry.display_path)
        overlay_file = overlay_root / relative
        if overlay_file.exists() and overlay_file.is_file():
            replacement = overlay_file.read_bytes()
            original = read_entry_data(archive, entry)
            if replacement != original:
                codec, level = _entry_codec_for_replacement(archive, entry)
                payload, block_sizes = _compress_data(replacement, codec, archive.block_size, level)
                build_entries.append(
                    _BuildEntry(
                        index=len(build_entries),
                        path=entry.display_path,
                        name_digest=entry.name_digest,
                        uncompressed_size=len(replacement),
                        payload=payload,
                        block_sizes=block_sizes,
                        compression=codec,
                        compression_level=level,
                        source_index=entry.index,
                        changed=True,
                    )
                )
                replaced.append(entry.display_path)
                continue
        build_entries.append(_preserve_entry_payload(archive, entry, path=entry.display_path))
        preserved.append(entry.display_path)

    added: list[str] = []
    default_codec, default_level = _default_codec_for_additions(archive)
    for manifest_path, (_relative, overlay_file) in zip(added_manifest_paths, additions, strict=False):
        data = overlay_file.read_bytes()
        payload, block_sizes = _compress_data(data, default_codec, archive.block_size, default_level)
        build_entries.append(
            _BuildEntry(
                index=len(build_entries),
                path=manifest_path,
                name_digest=hashlib.md5(manifest_path.encode("utf-8")).digest(),
                uncompressed_size=len(data),
                payload=payload,
                block_sizes=block_sizes,
                compression=default_codec,
                compression_level=default_level,
                changed=True,
                added=True,
            )
        )
        added.append(manifest_path)

    _write_psarc(output_path, archive, build_entries)
    return {
        "ok": True,
        "base_archive": str(base_archive),
        "overlay_root": str(overlay_root),
        "rebuilt_artifact": str(output_path),
        "compression": archive.compression or "none",
        "block_size": archive.block_size,
        "preserved_entry_order": True,
        "preserved_payload_count": len(preserved),
        "replaced_entries": replaced,
        "added_entries": added,
        "entry_count": len(build_entries),
    }


def pack_psarc_from_mapping(
    files: dict[str, bytes] | Iterable[tuple[str, bytes]],
    output_path: str | Path,
    *,
    compression: str = "zlib",
    compression_level: int = 9,
    block_size: int = PSARC_DEFAULT_BLOCK_SIZE,
    archive_flags: int = 0,
) -> dict[str, Any]:
    items = list(files.items() if isinstance(files, dict) else files)
    output = Path(output_path).resolve()
    ensure_dir(output.parent)
    compression = _normalize_codec(compression)
    metadata = PsarcArchive(
        path=output,
        version=b"\x00\x01\x00\x04",
        compression=compression,
        compression_field=_compression_field(compression),
        toc_size=0,
        toc_entry_size=PSARC_ENTRY_SIZE,
        entry_count=0,
        block_size=block_size,
        archive_flags=archive_flags,
        block_size_table=[],
        entries=[],
    )
    manifest_paths = [path.replace("\\", "/") for path, _data in items]
    manifest_data = _encode_manifest(manifest_paths)
    manifest_payload, manifest_blocks = _compress_data(manifest_data, compression, block_size, compression_level)
    build_entries = [
        _BuildEntry(
            index=0,
            path=PSARC_MANIFEST_NAME,
            name_digest=bytes(16),
            uncompressed_size=len(manifest_data),
            payload=manifest_payload,
            block_sizes=manifest_blocks,
            compression=compression,
            compression_level=compression_level,
            changed=True,
        )
    ]
    for path, data in items:
        manifest_path = path.replace("\\", "/")
        payload, block_sizes = _compress_data(data, compression, block_size, compression_level)
        build_entries.append(
            _BuildEntry(
                index=len(build_entries),
                path=manifest_path,
                name_digest=hashlib.md5(manifest_path.encode("utf-8")).digest(),
                uncompressed_size=len(data),
                payload=payload,
                block_sizes=block_sizes,
                compression=compression,
                compression_level=compression_level,
                changed=True,
            )
        )
    _write_psarc(output, metadata, build_entries)
    return {
        "ok": True,
        "rebuilt_artifact": str(output),
        "entry_count": len(build_entries),
        "compression": compression,
        "block_size": block_size,
    }


def pack_psarc_from_directory(
    source_root: str | Path,
    output_path: str | Path,
    *,
    compression: str = "zlib",
    compression_level: int = 9,
    block_size: int = PSARC_DEFAULT_BLOCK_SIZE,
    order_manifest: str | Path | None = None,
    archive_flags: int = 0,
) -> dict[str, Any]:
    root = Path(source_root).resolve()
    if not root.exists() or not root.is_dir():
        return {"ok": False, "error": f"PSARC source directory not found: {root}"}
    explicit_order = _read_order_manifest(order_manifest) if order_manifest else []
    files_by_relative = {
        path.relative_to(root).as_posix(): path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != PSARC_METADATA_NAME
    }
    ordered_relatives: list[str] = []
    seen: set[str] = set()
    for relative in explicit_order:
        safe = sanitize_relative_source_path(relative)
        if safe in files_by_relative and safe not in seen:
            ordered_relatives.append(safe)
            seen.add(safe)
    for relative in sorted(files_by_relative):
        if relative not in seen:
            ordered_relatives.append(relative)
            seen.add(relative)
    mapping = [(relative, files_by_relative[relative].read_bytes()) for relative in ordered_relatives]
    result = pack_psarc_from_mapping(
        mapping,
        output_path,
        compression=compression,
        compression_level=compression_level,
        block_size=block_size,
        archive_flags=archive_flags,
    )
    result.update(
        {
            "source_root": str(root),
            "file_count": len(mapping),
            "file_order": ordered_relatives,
            "order_manifest": str(Path(order_manifest).resolve()) if order_manifest else "",
        }
    )
    return result


def _attach_manifest_paths(archive: PsarcArchive) -> None:
    manifest_entry = archive.entries[0]
    try:
        manifest_data = read_entry_data(archive, manifest_entry)
    except (OSError, PsarcFormatError, zlib.error, lzma.LZMAError):
        manifest_data = b""
    paths = [
        line.decode("utf-8", errors="replace").strip()
        for line in manifest_data.replace(b"\r\n", b"\n").split(b"\n")
        if line.strip()
    ]
    archive.manifest_paths = paths
    manifest_entry.path = PSARC_MANIFEST_NAME
    for index, entry in enumerate(archive.entries[1:], start=0):
        if index < len(paths):
            entry.path = paths[index].replace("\\", "/")
        else:
            entry.path = f"entry_{entry.index:05d}.bin"


def _infer_entry_compression(*, archive_compression: str, block_size: int, entry: PsarcEntry) -> None:
    compression: list[str] = []
    for block_position, table_size in enumerate(entry.block_sizes):
        disk_size = _disk_block_size(table_size, block_size)
        expected = min(block_size, max(0, entry.uncompressed_size - (block_position * block_size)))
        compression.append("stored" if disk_size == expected else archive_compression or "stored")
    entry.block_compression = compression
    if not compression:
        entry.compression = "none"
    elif all(item == "stored" for item in compression):
        entry.compression = "none"
    elif archive_compression:
        entry.compression = archive_compression
    else:
        entry.compression = "unknown"


def _entry_compression_profile(archive: PsarcArchive, entry: PsarcEntry | None) -> tuple[str, int | None]:
    if entry is None:
        return _normalize_codec(archive.compression), 9 if archive.compression in {"zlib", "lzma"} else None
    if not entry.block_sizes:
        entry.compression = "none"
        return "none", None
    codecs: list[str] = []
    level: int | None = None
    remaining = entry.uncompressed_size
    with archive.path.open("rb") as handle:
        handle.seek(entry.data_offset)
        for table_size in entry.block_sizes:
            disk_size = _disk_block_size(table_size, archive.block_size)
            block = handle.read(disk_size)
            expected = min(archive.block_size, remaining)
            _decoded, codec, block_level = _decode_block(archive.compression, block, expected)
            codecs.append(codec)
            if block_level is not None and level is None:
                level = block_level
            remaining -= expected
            if remaining <= 0:
                break
    entry.block_compression = codecs
    if any(codec in {"zlib", "lzma"} for codec in codecs):
        entry.compression = archive.compression or "unknown"
    elif codecs:
        entry.compression = "none"
    if level is not None:
        entry.compression_level = level
    return entry.compression, entry.compression_level


def _entry_codec_for_replacement(archive: PsarcArchive, entry: PsarcEntry | None) -> tuple[str, int | None]:
    codec, level = _entry_compression_profile(archive, entry)
    if codec in {"unknown", "stored"}:
        codec = _normalize_codec(archive.compression)
    if codec == "none":
        return "none", None
    if codec == "zlib":
        return codec, level or 9
    if codec == "lzma":
        return codec, level or 9
    return "none", None


def _default_codec_for_additions(archive: PsarcArchive) -> tuple[str, int | None]:
    for entry in archive.entries[1:]:
        codec, level = _entry_compression_profile(archive, entry)
        if codec in {"zlib", "lzma"}:
            return codec, level or 9
    codec = _normalize_codec(archive.compression)
    return codec, 9 if codec in {"zlib", "lzma"} else None


def _preserve_entry_payload(archive: PsarcArchive, entry: PsarcEntry, *, path: str) -> _BuildEntry:
    payload = _read_entry_payload(archive, entry)
    codec, level = _entry_compression_profile(archive, entry)
    return _BuildEntry(
        index=entry.index,
        path=path,
        name_digest=entry.name_digest,
        uncompressed_size=entry.uncompressed_size,
        payload=payload,
        block_sizes=list(entry.block_sizes),
        compression=codec,
        compression_level=level,
        source_index=entry.index,
    )


def _read_entry_payload(archive: PsarcArchive, entry: PsarcEntry) -> bytes:
    size = sum(_disk_block_size(table_size, archive.block_size) for table_size in entry.block_sizes)
    with archive.path.open("rb") as handle:
        handle.seek(entry.data_offset)
        return handle.read(size)


def _compress_data(data: bytes, codec: str, block_size: int, level: int | None) -> tuple[bytes, list[int]]:
    codec = _normalize_codec(codec)
    payload = bytearray()
    block_sizes: list[int] = []
    max_table_size = (1 << (_block_table_field_size(block_size) * 8)) - 1
    if not data:
        return b"", []
    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        encoded = _compress_block(block, codec, level)
        if codec != "none" and 0 < len(encoded) < len(block) and len(encoded) <= max_table_size:
            payload.extend(encoded)
            block_sizes.append(len(encoded))
            continue
        payload.extend(block)
        table_size = 0 if len(block) == block_size else len(block)
        if table_size > max_table_size:
            raise PsarcFormatError(f"PSARC block table cannot represent block size {table_size}")
        block_sizes.append(table_size)
    return bytes(payload), block_sizes


def _compress_block(block: bytes, codec: str, level: int | None) -> bytes:
    if codec == "zlib":
        return zlib.compress(block, max(0, min(9, level or 9)))
    if codec == "lzma":
        return lzma.compress(block, format=lzma.FORMAT_ALONE, preset=max(0, min(9, level or 9)))
    return block


def _decode_block(codec: str, block: bytes, expected_size: int) -> tuple[bytes, str, int | None]:
    codec = _normalize_codec(codec)
    if codec == "zlib" and (_looks_like_zlib(block) or len(block) != expected_size):
        try:
            return zlib.decompress(block), "zlib", _zlib_level(block)
        except zlib.error:
            pass
    if codec == "lzma" and (_looks_like_lzma(block) or len(block) != expected_size):
        decoded = _try_lzma_decompress(block)
        if decoded is not None:
            return decoded, "lzma", 9
    return block, "stored", None


def _try_lzma_decompress(block: bytes) -> bytes | None:
    for fmt in (lzma.FORMAT_ALONE, lzma.FORMAT_XZ, lzma.FORMAT_AUTO):
        try:
            return lzma.decompress(block, format=fmt)
        except lzma.LZMAError:
            continue
    for dict_size in (1 << 20, 1 << 21, 1 << 23):
        try:
            return lzma.decompress(
                block,
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size}],
            )
        except lzma.LZMAError:
            continue
    return None


def _write_psarc(output_path: Path, template: PsarcArchive, entries: list[_BuildEntry]) -> None:
    block_table: list[int] = []
    for entry in entries:
        entry.block_index = len(block_table)
        block_table.extend(entry.block_sizes)
    toc_entry_size = template.toc_entry_size or PSARC_ENTRY_SIZE
    block_field_size = _block_table_field_size(template.block_size)
    toc_size = PSARC_HEADER_SIZE + (len(entries) * toc_entry_size) + (len(block_table) * block_field_size)
    data_offset = toc_size
    for entry in entries:
        entry.data_offset = data_offset
        data_offset += len(entry.payload)

    toc_payload = bytearray()
    for entry in entries:
        record = bytearray(toc_entry_size)
        record[0:16] = entry.name_digest[:16].ljust(16, b"\x00")
        struct.pack_into(">I", record, 16, entry.block_index)
        record[20:25] = _u40bytes(entry.uncompressed_size)
        record[25:30] = _u40bytes(entry.data_offset)
        toc_payload.extend(record)
    max_table_size = (1 << (block_field_size * 8)) - 1
    for table_size in block_table:
        if table_size < 0 or table_size > max_table_size:
            raise PsarcFormatError(f"PSARC block table value {table_size} exceeds {block_field_size}-byte field")
        toc_payload.extend(table_size.to_bytes(block_field_size, "big"))
    if template.archive_flags & PSARC_TOC_ENCRYPTED_FLAG:
        toc_payload = bytearray(_crypt_rocksmith_psarc_toc(bytes(toc_payload), decrypt=False))

    with output_path.open("wb") as handle:
        handle.write(PSARC_MAGIC)
        handle.write(template.version)
        handle.write(template.compression_field[:4].ljust(4, b"\x00"))
        handle.write(struct.pack(">I", toc_size))
        handle.write(struct.pack(">I", toc_entry_size))
        handle.write(struct.pack(">I", len(entries)))
        handle.write(struct.pack(">I", template.block_size))
        handle.write(struct.pack(">I", template.archive_flags))
        handle.write(toc_payload)
        for entry in entries:
            handle.write(entry.payload)


def _overlay_additions(overlay_root: Path, existing_paths: set[str]) -> list[tuple[str, Path]]:
    additions: list[tuple[str, Path]] = []
    for path in sorted(overlay_root.rglob("*")):
        if not path.is_file() or path.name == PSARC_METADATA_NAME:
            continue
        relative = path.relative_to(overlay_root).as_posix()
        if relative.lower() in existing_paths:
            continue
        additions.append((relative, path))
    return additions


def _read_order_manifest(order_manifest: str | Path | None) -> list[str]:
    if order_manifest is None:
        return []
    manifest_path = Path(order_manifest).resolve()
    if not manifest_path.exists() or not manifest_path.is_file():
        raise PsarcFormatError(f"PSARC order manifest not found: {manifest_path}")
    if manifest_path.suffix.lower() == ".json":
        payload = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, dict):
            values = payload.get("files") or payload.get("manifest_paths") or payload.get("file_order") or []
        elif isinstance(payload, list):
            values = payload
        else:
            values = []
        return [str(value).replace("\\", "/").strip() for value in values if str(value).strip()]
    return [
        line.strip().replace("\\", "/")
        for line in manifest_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _new_manifest_path(relative: str, archive: PsarcArchive) -> str:
    clean = sanitize_relative_source_path(relative)
    absolute_like = bool(archive.archive_flags & 0x02) or _mostly_absolute(archive.manifest_paths)
    return f"/{clean}" if absolute_like and not clean.startswith("/") else clean


def _mostly_absolute(paths: list[str]) -> bool:
    if not paths:
        return False
    absolute_count = sum(1 for path in paths if path.startswith("/"))
    return absolute_count > len(paths) // 2


def _encode_manifest(paths: list[str]) -> bytes:
    return ("\n".join(paths) + ("\n" if paths else "")).encode("utf-8")


def _block_count(size: int, block_size: int) -> int:
    if size <= 0:
        return 0
    return (size + block_size - 1) // block_size


def _disk_block_size(table_size: int, block_size: int) -> int:
    return block_size if table_size == 0 else table_size


def _block_table_field_size(block_size: int) -> int:
    if block_size <= 0x10000:
        return 2
    if block_size <= 0x1000000:
        return 3
    return 4


def _crypt_rocksmith_psarc_toc(payload: bytes, *, decrypt: bool) -> bytes:
    if not payload:
        return payload
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(ROCKSMITH_PSARC_KEY), modes.CFB(bytes(16)))
        cryptor = cipher.decryptor() if decrypt else cipher.encryptor()
        return cryptor.update(payload) + cryptor.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES

        cipher = AES.new(ROCKSMITH_PSARC_KEY, AES.MODE_CFB, iv=bytes(16), segment_size=128)
        return cipher.decrypt(payload) if decrypt else cipher.encrypt(payload)
    except ImportError as exc:
        raise PsarcFormatError(
            "Encrypted PSARC ToC support requires the 'cryptography' package or PyCryptodome."
        ) from exc


def _decode_compression(field: bytes) -> str:
    text = field.rstrip(b"\x00").decode("ascii", errors="ignore").strip().lower()
    return _normalize_codec(text)


def _normalize_codec(codec: str) -> str:
    codec = (codec or "").strip().lower()
    if codec in {"zlib", "lzma"}:
        return codec
    return "none"


def _compression_field(codec: str) -> bytes:
    codec = _normalize_codec(codec)
    if codec == "zlib":
        return b"zlib"
    if codec == "lzma":
        return b"lzma"
    return b"\x00\x00\x00\x00"


def _looks_like_zlib(block: bytes) -> bool:
    if len(block) < 2:
        return False
    cmf, flg = block[0], block[1]
    return (cmf & 0x0F) == 8 and ((cmf << 8) + flg) % 31 == 0


def _zlib_level(block: bytes) -> int | None:
    if len(block) < 2 or not _looks_like_zlib(block):
        return None
    return {0: 1, 1: 3, 2: 6, 3: 9}.get(block[1] >> 6)


def _looks_like_lzma(block: bytes) -> bool:
    if len(block) < 13:
        return False
    return block[0] in {0x5D, 0x6D, 0x7D, 0x8D, 0x9D} or block[:6] == b"\xfd7zXZ\x00"


def _u32be(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from(">I", data, offset)[0]


def _u40be(data: bytes, offset: int) -> int:
    if offset + 5 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 5], "big")


def _u40bytes(value: int) -> bytes:
    if value < 0 or value >= (1 << 40):
        raise PsarcFormatError(f"Value does not fit PSARC uint40: {value}")
    return int(value).to_bytes(5, "big")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
