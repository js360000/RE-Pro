from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

import brotli

from .sourcemap import restore_sources_from_map
from .utils import ensure_dir, safe_output_path


@dataclass
class TauriAssetEntry:
    key: str
    key_offset: int
    data_offset: int
    data_length: int


def extract_tauri_assets(
    target: Path,
    destination_root: Path,
    recovered_sources_root: Path,
) -> dict[str, object]:
    data = target.read_bytes()
    image_base, sections = _parse_pe_layout(data)
    entries = scan_tauri_asset_entries(data, image_base, sections)

    assets_dir = ensure_dir(destination_root / "assets")
    manifest: list[dict[str, object]] = []
    restored_sources: list[dict[str, str]] = []
    notes: list[str] = []

    for entry in entries:
        compressed = data[entry.data_offset : entry.data_offset + entry.data_length]
        try:
            raw = brotli.decompress(compressed)
        except brotli.error:
            continue

        output_path = safe_output_path(assets_dir, entry.key)
        ensure_dir(output_path.parent)
        output_path.write_bytes(raw)
        manifest.append(
            {
                "key": entry.key,
                "path": str(output_path),
                "compressed_size": entry.data_length,
                "raw_size": len(raw),
            }
        )

        if output_path.suffix.lower() == ".map":
            recovered, map_notes = restore_sources_from_map(output_path, recovered_sources_root)
            restored_sources.extend(
                {
                    "original_path": item.original_path,
                    "restored_path": item.restored_path,
                    "source_map": item.source_map,
                }
                for item in recovered
            )
            notes.extend(map_notes)

    manifest_path = destination_root / "extracted_assets_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "entries": entries,
        "manifest_path": manifest_path,
        "assets_dir": assets_dir,
        "extracted_count": len(manifest),
        "restored_sources": restored_sources,
        "notes": notes,
    }


def scan_tauri_asset_entries(
    data: bytes,
    image_base: int,
    sections: list[dict[str, int | str]],
) -> list[TauriAssetEntry]:
    candidates: dict[str, TauriAssetEntry] = {}
    scan_sections = [section for section in sections if section["name"] in {".rdata", ".data"}]
    for section in scan_sections:
        start = int(section["raw_offset"])
        end = start + int(section["raw_size"])
        for offset in range(start, max(start, end - 32), 8):
            key_va, key_len, data_va, data_len = struct.unpack_from("<QQQQ", data, offset)
            if not (1 <= key_len <= 260 and 1 <= data_len <= 25_000_000):
                continue

            key_offset = _va_to_offset(key_va, image_base, sections)
            data_offset = _va_to_offset(data_va, image_base, sections)
            if key_offset is None or data_offset is None:
                continue
            if key_offset + key_len > len(data) or data_offset + data_len > len(data):
                continue

            key_bytes = data[key_offset : key_offset + key_len]
            try:
                key = key_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not _looks_like_tauri_asset_key(key):
                continue

            current = candidates.get(key)
            if current is None or data_len > current.data_length:
                candidates[key] = TauriAssetEntry(
                    key=key,
                    key_offset=key_offset,
                    data_offset=data_offset,
                    data_length=data_len,
                )

    return sorted(candidates.values(), key=lambda entry: entry.key)


def _parse_pe_layout(data: bytes) -> tuple[int, list[dict[str, int | str]]]:
    if len(data) < 0x1000 or data[:2] != b"MZ":
        raise ValueError("Target is not a PE file")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Target does not contain a valid PE signature")

    number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    if optional_magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, pe_offset + 24 + 24)[0]
    elif optional_magic == 0x10B:
        image_base = struct.unpack_from("<I", data, pe_offset + 24 + 28)[0]
    else:
        raise ValueError("Unsupported PE optional header")

    section_table_offset = pe_offset + 24 + optional_header_size
    sections: list[dict[str, int | str]] = []
    for index in range(number_of_sections):
        offset = section_table_offset + (40 * index)
        name = data[offset : offset + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
            }
        )
    return image_base, sections


def _va_to_offset(va: int, image_base: int, sections: list[dict[str, int | str]]) -> int | None:
    rva = va - image_base
    for section in sections:
        virtual_address = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        raw_offset = int(section["raw_offset"])
        if virtual_address <= rva < virtual_address + raw_size:
            return raw_offset + (rva - virtual_address)
    return None


def _looks_like_tauri_asset_key(key: str) -> bool:
    normalized = key.split("?", 1)[0]
    if normalized in {"/index.html", "/manifest.json", "/robots.txt", "/sitemap.xml"}:
        return True
    if normalized.startswith("icons/") or normalized.startswith("sidecars/"):
        return True
    if normalized.startswith(("/favicon", "/apple-touch-icon", "/web-app-manifest")):
        return True
    if not normalized.startswith("/"):
        return False
    if "." not in normalized.rsplit("/", 1)[-1]:
        return False
    known_roots = (
        "/assets/",
        "/_next/",
        "/static/",
        "/images/",
        "/img/",
        "/fonts/",
        "/media/",
        "/scripts/",
        "/styles/",
        "/configure/",
    )
    if not normalized.startswith(known_roots):
        return False
    extension = normalized.rsplit(".", 1)[-1].lower()
    return extension in {
        "js",
        "mjs",
        "cjs",
        "css",
        "html",
        "json",
        "map",
        "svg",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "ico",
        "woff",
        "woff2",
        "ttf",
        "otf",
        "txt",
        "md",
        "xml",
    }
