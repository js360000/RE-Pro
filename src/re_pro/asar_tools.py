from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path

from .tooling import REPO_ROOT, resolve_command, run_command
from .utils import ensure_dir


def extract_asar_archive(asar_path: Path, destination_base: Path, *, cwd: Path | None = None, timeout: int = 300) -> tuple[Path | None, str]:
    command_templates = _asar_extract_command_templates()
    errors: list[str] = []
    for command_template in command_templates:
        destination = _fresh_destination(destination_base)
        command = [*command_template, str(asar_path), str(destination)]
        try:
            code, _stdout, stderr = run_command(command, cwd=cwd or asar_path.parent, timeout=timeout)
        except OSError as exc:
            errors.append(f"{Path(command[0]).name}: {exc}")
            continue
        if code == 0:
            return destination, ""
        errors.append(f"{Path(command[0]).name}: {(stderr or '').strip() or 'exit code %d' % code}")
    destination = _fresh_destination(destination_base)
    try:
        extract_asar_archive_native(asar_path, destination)
        return destination, ""
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"native-python-asar: {exc}")
    return None, "; ".join(error for error in errors if error)


def _asar_extract_command_templates() -> list[list[str]]:
    commands: list[list[str]] = []
    asar = resolve_command([["asar"]])
    if asar is not None:
        commands.append(asar + ["extract"])

    node_asar = REPO_ROOT / "tools" / "asar" / "node_modules" / "@electron" / "asar" / "bin" / "asar.mjs"
    node = resolve_command([["node"]])
    if node is not None and node_asar.exists():
        commands.append(node + [str(node_asar), "extract"])

    npx = resolve_command([["npx"]])
    if npx is not None:
        commands.append(npx + ["-y", "@electron/asar", "extract"])
    return _dedupe_commands(commands)


def extract_asar_archive_native(asar_path: Path, destination: Path) -> None:
    header, header_size = read_asar_header(asar_path)
    files = header.get("files")
    if not isinstance(files, dict):
        raise ValueError("ASAR header did not contain a files table")
    destination = ensure_dir(destination)
    with asar_path.open("rb") as archive:
        _extract_asar_entries(
            archive,
            asar_path,
            files,
            destination,
            data_offset=8 + header_size,
            relative_parts=[],
        )


def read_asar_header(asar_path: Path) -> tuple[dict[str, object], int]:
    with asar_path.open("rb") as handle:
        size_pickle = handle.read(8)
        if len(size_pickle) != 8:
            raise ValueError("Unable to read ASAR header-size pickle")
        header_size = _read_pickle_uint32(size_pickle)
        if header_size <= 0 or header_size > asar_path.stat().st_size:
            raise ValueError(f"Invalid ASAR header size: {header_size}")
        header_pickle = handle.read(header_size)
        if len(header_pickle) != header_size:
            raise ValueError("Unable to read ASAR header pickle")
    header_json = _read_pickle_string(header_pickle)
    payload = json.loads(header_json)
    if not isinstance(payload, dict):
        raise ValueError("ASAR header JSON was not an object")
    return payload, header_size


def _extract_asar_entries(
    archive,
    asar_path: Path,
    entries: dict[str, object],
    destination: Path,
    *,
    data_offset: int,
    relative_parts: list[str],
) -> None:
    for raw_name, raw_entry in entries.items():
        name = _safe_asar_component(raw_name)
        if not name or not isinstance(raw_entry, dict):
            continue
        entry = raw_entry
        parts = [*relative_parts, name]
        target = _safe_join(destination, parts)
        children = entry.get("files")
        if isinstance(children, dict):
            ensure_dir(target)
            _extract_asar_entries(
                archive,
                asar_path,
                children,
                destination,
                data_offset=data_offset,
                relative_parts=parts,
            )
            continue
        if "link" in entry:
            _write_link_placeholder(target, str(entry.get("link") or ""))
            continue
        size = int(entry.get("size") or 0)
        ensure_dir(target.parent)
        if entry.get("unpacked"):
            unpacked_source = asar_path.with_name(f"{asar_path.name}.unpacked").joinpath(*parts)
            if unpacked_source.exists() and unpacked_source.is_file():
                shutil.copy2(unpacked_source, target)
            else:
                target.write_bytes(b"")
            continue
        offset = int(str(entry.get("offset") or "0"))
        archive.seek(data_offset + offset)
        with target.open("wb") as output:
            remaining = size
            while remaining > 0:
                chunk = archive.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError(f"Unexpected EOF while extracting {'/'.join(parts)}")
                output.write(chunk)
                remaining -= len(chunk)


def _read_pickle_uint32(buffer: bytes) -> int:
    payload_size = struct.unpack_from("<I", buffer, 0)[0]
    header_size = len(buffer) - payload_size
    if header_size < 0 or header_size + 4 > len(buffer):
        raise ValueError("Invalid pickle uint32 payload")
    return struct.unpack_from("<I", buffer, header_size)[0]


def _read_pickle_string(buffer: bytes) -> str:
    payload_size = struct.unpack_from("<I", buffer, 0)[0]
    header_size = len(buffer) - payload_size
    if header_size < 0 or header_size + 4 > len(buffer):
        raise ValueError("Invalid pickle string payload")
    string_size = struct.unpack_from("<i", buffer, header_size)[0]
    start = header_size + 4
    end = start + string_size
    if string_size < 0 or end > len(buffer):
        raise ValueError("Invalid pickle string length")
    return buffer[start:end].decode("utf-8")


def _safe_asar_component(value: object) -> str:
    text = str(value or "").replace("\\", "/").split("/")[-1]
    if text in {"", ".", ".."}:
        return ""
    return text


def _safe_join(root: Path, relative_parts: list[str]) -> Path:
    candidate = root.joinpath(*relative_parts).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ValueError(f"Unsafe ASAR path: {'/'.join(relative_parts)}")
    return candidate


def _write_link_placeholder(target: Path, link_target: str) -> None:
    ensure_dir(target.parent)
    target.write_text(f"ASAR symlink placeholder -> {link_target}\n", encoding="utf-8")


def _fresh_destination(destination_base: Path) -> Path:
    destination_base = destination_base.resolve()
    if not destination_base.exists() or not any(destination_base.iterdir()):
        return ensure_dir(destination_base)
    for index in range(1, 100):
        candidate = destination_base.with_name(f"{destination_base.name}_{index}")
        if not candidate.exists() or not any(candidate.iterdir()):
            return ensure_dir(candidate)
    return ensure_dir(destination_base.with_name(f"{destination_base.name}_latest"))


def _dedupe_commands(commands: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    result: list[list[str]] = []
    for command in commands:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        result.append(command)
    return result
