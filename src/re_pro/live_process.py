from __future__ import annotations

import csv
import ctypes
from ctypes import wintypes
from dataclasses import asdict
import io
import json
import platform
import re
from pathlib import Path
from typing import Any

from .models import LiveProcessSettings
from .tooling import run_command
from .utils import ensure_dir, extract_ascii_strings, safe_slug


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

PAYLOAD_SIGNATURES: list[tuple[str, bytes, str]] = [
    ("portable_executable", b"MZ", ".exe"),
    ("elf", b"\x7fELF", ".elf"),
    ("wasm", b"\x00asm", ".wasm"),
    ("zip", b"PK\x03\x04", ".zip"),
    ("gzip", b"\x1f\x8b\x08", ".gz"),
    ("7z", b"7z\xbc\xaf\x27\x1c", ".7z"),
    ("rar", b"Rar!\x1a\x07", ".rar"),
    ("psx_exe", b"PS-X EXE", ".psx.exe"),
    ("sce_self", b"SCE\x00", ".self"),
    ("psarc", b"PSAR", ".psarc"),
]

TEXT_MARKERS = [
    b"function ",
    b"const ",
    b"import ",
    b"export ",
    b"class ",
    b"using namespace",
    b"#include",
    b"package ",
    b"syntax =",
]


def list_live_processes(query: str = "", *, limit: int = 200) -> list[dict[str, Any]]:
    processes = _query_process_list()
    lowered = query.strip().lower()
    if lowered:
        processes = [
            process
            for process in processes
            if lowered in str(process.get("name", "")).lower()
            or lowered in str(process.get("executable_path", "")).lower()
            or lowered in str(process.get("command_line", "")).lower()
        ]
    return processes[: max(1, min(limit, 1000))]


def resolve_live_process(*, pid: int = 0, process_name: str = "") -> dict[str, Any]:
    if pid:
        process = _query_process_info(pid)
        if process is None:
            raise ProcessLookupError(f"PID not found or inaccessible: {pid}")
        return process
    name = process_name.strip().lower()
    if not name:
        raise ValueError("Either pid or process_name is required.")
    matches = [
        process
        for process in _query_process_list()
        if str(process.get("name", "")).lower() == name
        or str(process.get("name", "")).lower() == f"{name}.exe"
        or name in str(process.get("executable_path", "")).lower()
    ]
    if not matches:
        raise ProcessLookupError(f"No running process matched {process_name!r}")
    matches.sort(key=lambda item: int(item.get("pid", 0) or 0), reverse=True)
    return matches[0]


def capture_live_process(
    *,
    output_dir: str | Path,
    settings: LiveProcessSettings,
    logger=None,
) -> dict[str, Any]:
    output = ensure_dir(Path(output_dir).resolve())
    process = resolve_live_process(pid=settings.pid, process_name=settings.process_name)
    pid = int(process.get("pid", 0) or 0)
    if logger:
        logger(f"Live attach selected PID {pid} ({process.get('name')})")

    modules = _query_modules_for_pid(pid)
    regions = _enumerate_memory_regions(pid) if settings.dump_memory else []
    dumps_dir = ensure_dir(output / "memory_dumps")
    carved_dir = ensure_dir(output / "carved_payloads")
    strings_dir = ensure_dir(output / "strings")
    dumped_regions: list[dict[str, Any]] = []
    carved_payloads: list[dict[str, Any]] = []
    strings: list[str] = []
    total_dumped = 0
    errors: list[str] = []

    for region in regions:
        if total_dumped >= settings.max_total_bytes:
            break
        if not _should_dump_region(region, settings):
            continue
        max_bytes = min(
            int(region.get("region_size", 0) or 0),
            max(4096, int(settings.max_region_bytes)),
            max(0, int(settings.max_total_bytes) - total_dumped),
        )
        if max_bytes <= 0:
            continue
        try:
            data = _read_memory_region(pid, int(region.get("base_address", 0) or 0), max_bytes)
        except OSError as exc:
            errors.append(f"{region.get('base_address_hex')}: {exc}")
            continue
        if not data:
            continue
        interesting = _is_interesting_region(data, region, settings)
        if not interesting:
            continue
        dump_path = dumps_dir / f"region_{int(region.get('base_address', 0)):016x}_{len(data):x}.bin"
        dump_path.write_bytes(data)
        total_dumped += len(data)
        strings.extend(extract_ascii_strings(data, minimum=6, limit=400))
        dump_record = {
            **region,
            "path": str(dump_path),
            "dumped_bytes": len(data),
            "interesting_reasons": interesting,
        }
        dumped_regions.append(dump_record)
        carved_payloads.extend(_carve_payloads(data, region=region, output_dir=carved_dir, source_path=dump_path))

    strings_path = strings_dir / "live_strings.txt"
    unique_strings = sorted(set(strings))[:20000]
    strings_path.write_text("\n".join(unique_strings), encoding="utf-8", errors="ignore")
    process_path = output / "process.json"
    modules_path = output / "modules.json"
    regions_path = output / "memory_regions.json"
    process_path.write_text(json.dumps(process, indent=2), encoding="utf-8")
    modules_path.write_text(json.dumps(modules, indent=2), encoding="utf-8")
    regions_path.write_text(json.dumps(regions, indent=2), encoding="utf-8")

    manifest = {
        "ok": True,
        "method": "live_process_attach",
        "platform": platform.platform(),
        "settings": settings.to_dict(),
        "process": process,
        "modules": modules,
        "memory_region_count": len(regions),
        "dumped_regions": dumped_regions,
        "carved_payloads": carved_payloads,
        "artifacts": {
            "process": str(process_path),
            "modules": str(modules_path),
            "regions": str(regions_path),
            "strings": str(strings_path),
        },
        "summary": {
            "dumped_region_count": len(dumped_regions),
            "dumped_bytes": total_dumped,
            "carved_payload_count": len(carved_payloads),
            "unique_string_count": len(unique_strings),
            "module_count": len(modules),
            "errors": len(errors),
        },
        "errors": errors[:200],
    }
    manifest_path = output / "live_process_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _query_process_list() -> list[dict[str, Any]]:
    code, stdout, _ = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-CimInstance Win32_Process | "
                "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
            ),
        ],
        timeout=30,
    )
    if code != 0 or not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "pid": int(item.get("ProcessId", 0) or 0),
                "parent_pid": int(item.get("ParentProcessId", 0) or 0),
                "name": str(item.get("Name", "")),
                "executable_path": str(item.get("ExecutablePath", "") or ""),
                "command_line": str(item.get("CommandLine", "") or ""),
            }
        )
    return [item for item in result if item["pid"]]


def _query_process_info(pid: int) -> dict[str, Any] | None:
    for process in _query_process_list():
        if int(process.get("pid", 0) or 0) == int(pid):
            return process
    return None


def _query_modules_for_pid(pid: int) -> list[dict[str, Any]]:
    modules = _query_modules_with_powershell(pid)
    if modules:
        return modules
    return _query_modules_with_tasklist(pid)


def _query_modules_with_powershell(pid: int) -> list[dict[str, Any]]:
    code, stdout, _ = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                f"$p=Get-Process -Id {int(pid)} -ErrorAction Stop; "
                "$p.Modules | Select-Object ModuleName,FileName,BaseAddress,ModuleMemorySize | ConvertTo-Json -Compress"
            ),
        ],
        timeout=30,
    )
    if code != 0 or not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "name": str(item.get("ModuleName", "")),
                "path": str(item.get("FileName", "") or ""),
                "base_address": int(item.get("BaseAddress", 0) or 0),
                "base_address_hex": f"0x{int(item.get('BaseAddress', 0) or 0):x}",
                "size": int(item.get("ModuleMemorySize", 0) or 0),
            }
        )
    return result


def _query_modules_with_tasklist(pid: int) -> list[dict[str, Any]]:
    code, stdout, _ = run_command(["tasklist", "/FI", f"PID eq {int(pid)}", "/M", "/FO", "CSV", "/NH"], timeout=20)
    if code != 0 or not stdout.strip():
        return []
    reader = csv.reader(io.StringIO(stdout))
    result: list[dict[str, Any]] = []
    for row in reader:
        if len(row) < 3 or row[0].startswith("INFO:"):
            continue
        for module_name in [value.strip() for value in row[2].split(",") if value.strip()]:
            result.append({"name": module_name, "path": "", "base_address": 0, "base_address_hex": "", "size": 0})
    return result


def _enumerate_memory_regions(pid: int) -> list[dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for PID {pid}")
    try:
        max_address = _maximum_application_address(kernel32)
        address = 0
        regions: list[dict[str, Any]] = []
        mbi = MEMORY_BASIC_INFORMATION()
        while address < max_address:
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not result:
                address += 0x10000
                continue
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            if size <= 0:
                address += 0x10000
                continue
            protect = int(mbi.Protect)
            region = {
                "base_address": base,
                "base_address_hex": f"0x{base:x}",
                "region_size": size,
                "region_size_hex": f"0x{size:x}",
                "state": int(mbi.State),
                "protect": protect,
                "type": int(mbi.Type),
                "committed": int(mbi.State) == MEM_COMMIT,
                "readable": _is_readable_protection(protect),
                "executable": _is_executable_protection(protect),
                "mapped_image": int(mbi.Type) == MEM_IMAGE,
            }
            regions.append(region)
            address = base + size
        return regions
    finally:
        kernel32.CloseHandle(handle)


def _read_memory_region(pid: int, base_address: int, size: int) -> bytes:
    if platform.system().lower() != "windows":
        return b""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for PID {pid}")
    try:
        remaining = int(size)
        cursor = int(base_address)
        chunks: list[bytes] = []
        while remaining > 0:
            chunk_size = min(remaining, 1024 * 1024)
            buffer = ctypes.create_string_buffer(chunk_size)
            read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(cursor),
                buffer,
                chunk_size,
                ctypes.byref(read),
            )
            if not ok or read.value == 0:
                if not chunks:
                    raise OSError(ctypes.get_last_error(), f"ReadProcessMemory failed at 0x{cursor:x}")
                break
            chunks.append(buffer.raw[: read.value])
            cursor += read.value
            remaining -= read.value
        return b"".join(chunks)
    finally:
        kernel32.CloseHandle(handle)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


def _maximum_application_address(kernel32) -> int:
    info = SYSTEM_INFO()
    kernel32.GetNativeSystemInfo(ctypes.byref(info))
    return int(info.lpMaximumApplicationAddress or 0x7FFFFFFF)


def _is_readable_protection(protect: int) -> bool:
    if protect & PAGE_GUARD or protect & PAGE_NOACCESS:
        return False
    return True


def _is_executable_protection(protect: int) -> bool:
    return bool(protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))


def _should_dump_region(region: dict[str, Any], settings: LiveProcessSettings) -> bool:
    if not region.get("committed") or not region.get("readable"):
        return False
    if region.get("mapped_image") and not settings.include_mapped_images:
        return False
    if settings.include_all_readable:
        return True
    if region.get("executable"):
        return True
    size = int(region.get("region_size", 0) or 0)
    return size <= int(settings.max_region_bytes)


def _is_interesting_region(data: bytes, region: dict[str, Any], settings: LiveProcessSettings) -> list[str]:
    reasons: list[str] = []
    if region.get("executable"):
        reasons.append("executable")
    for name, signature, _suffix in PAYLOAD_SIGNATURES:
        if data.find(signature) != -1:
            reasons.append(f"signature:{name}")
    if any(marker in data for marker in TEXT_MARKERS):
        reasons.append("source_text_markers")
    if settings.include_all_readable:
        reasons.append("include_all_readable")
    return reasons


def _carve_payloads(data: bytes, *, region: dict[str, Any], output_dir: Path, source_path: Path) -> list[dict[str, Any]]:
    carved: list[dict[str, Any]] = []
    seen_offsets: set[tuple[str, int]] = set()
    for name, signature, suffix in PAYLOAD_SIGNATURES:
        cursor = 0
        while True:
            offset = data.find(signature, cursor)
            if offset == -1:
                break
            cursor = offset + max(1, len(signature))
            key = (name, offset)
            if key in seen_offsets:
                continue
            seen_offsets.add(key)
            if name == "portable_executable" and b"PE\x00\x00" not in data[offset : offset + 0x1000]:
                continue
            window = data[offset : min(len(data), offset + _carve_window_size(name))]
            if not window:
                continue
            base = int(region.get("base_address", 0) or 0)
            output_path = output_dir / f"{name}_{base + offset:016x}{suffix}"
            output_path.write_bytes(window)
            carved.append(
                {
                    "kind": name,
                    "path": str(output_path),
                    "source_region_path": str(source_path),
                    "region_base": region.get("base_address_hex"),
                    "region_offset": offset,
                    "virtual_address": f"0x{base + offset:x}",
                    "size": len(window),
                }
            )
    text_fragment = _extract_source_text_fragment(data)
    if text_fragment:
        base = int(region.get("base_address", 0) or 0)
        path = output_dir / f"text_fragment_{base:016x}.txt"
        path.write_text(text_fragment, encoding="utf-8", errors="ignore")
        carved.append(
            {
                "kind": "source_text_fragment",
                "path": str(path),
                "source_region_path": str(source_path),
                "region_base": region.get("base_address_hex"),
                "region_offset": 0,
                "virtual_address": f"0x{base:x}",
                "size": len(text_fragment.encode("utf-8", errors="ignore")),
            }
        )
    return carved


def _carve_window_size(kind: str) -> int:
    if kind in {"zip", "7z", "rar", "psarc"}:
        return 32 * 1024 * 1024
    if kind in {"portable_executable", "elf", "sce_self"}:
        return 16 * 1024 * 1024
    if kind == "wasm":
        return 8 * 1024 * 1024
    return 4 * 1024 * 1024


def _extract_source_text_fragment(data: bytes) -> str:
    if not any(marker in data for marker in TEXT_MARKERS):
        return ""
    strings = extract_ascii_strings(data, minimum=4, limit=4000)
    text = "\n".join(strings) if strings else data.decode("utf-8", errors="ignore")
    lines = [line.rstrip() for line in text.splitlines()]
    selected = [
        line
        for line in lines
        if 4 <= len(line) <= 500
        and any(marker.decode("ascii", errors="ignore").strip() in line for marker in TEXT_MARKERS)
    ]
    if not selected:
        return ""
    return "\n".join(selected[:1000]) + "\n"
