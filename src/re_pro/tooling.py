from __future__ import annotations

import glob
import os
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path
from queue import Empty, Queue
from typing import Iterable


COMMON_WINDOWS_PATTERNS: dict[str, list[str]] = {
    "7z": [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ],
    "analyzeHeadless": [
        r"C:\Program Files\Ghidra*\support\analyzeHeadless.bat",
        r"C:\Program Files (x86)\Ghidra*\support\analyzeHeadless.bat",
    ],
    "ghidraRun": [
        r"C:\Program Files\Ghidra*\ghidraRun.bat",
        r"C:\Program Files (x86)\Ghidra*\ghidraRun.bat",
    ],
    "rizin": [
        r"C:\Program Files\Rizin\bin\rizin.exe",
        r"C:\Program Files (x86)\Rizin\bin\rizin.exe",
    ],
    "rz-bin": [
        r"C:\Program Files\Rizin\bin\rz-bin.exe",
        r"C:\Program Files (x86)\Rizin\bin\rz-bin.exe",
    ],
    "radare2": [
        r"C:\Program Files\radare2\bin\radare2.exe",
        r"C:\Program Files (x86)\radare2\bin\radare2.exe",
    ],
    "r2": [
        r"C:\Program Files\radare2\bin\radare2.exe",
        r"C:\Program Files (x86)\radare2\bin\radare2.exe",
    ],
    "rabin2": [
        r"C:\Program Files\radare2\bin\rabin2.exe",
        r"C:\Program Files (x86)\radare2\bin\rabin2.exe",
    ],
    "java": [
        r"C:\Program Files\Eclipse Adoptium\jdk-*\bin\java.exe",
        r"C:\Program Files\Java\jdk-*\bin\java.exe",
        r"C:\Program Files\Microsoft\jdk-*\bin\java.exe",
    ],
    "dotnet": [
        r"C:\Program Files\dotnet\dotnet.exe",
        r"C:\Program Files (x86)\dotnet\dotnet.exe",
    ],
    "ilspycmd": [
        str(Path.home() / ".dotnet" / "tools" / "ilspycmd.exe"),
    ],
    "jadx": [
        r"C:\Program Files\jadx\bin\jadx.bat",
        r"C:\Program Files (x86)\jadx\bin\jadx.bat",
    ],
    "llvm-objdump": [
        r"C:\Program Files\LLVM\bin\llvm-objdump.exe",
    ],
    "llvm-nm": [
        r"C:\Program Files\LLVM\bin\llvm-nm.exe",
    ],
    "llvm-pdbutil": [
        r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe",
    ],
    "clang++": [
        r"C:\Program Files\LLVM\bin\clang++.exe",
        r"C:\msys64\mingw64\bin\clang++.exe",
        r"C:\msys64\ucrt64\bin\clang++.exe",
        r"C:\msys64\clang64\bin\clang++.exe",
    ],
    "g++": [
        r"C:\msys64\mingw64\bin\g++.exe",
        r"C:\msys64\ucrt64\bin\g++.exe",
        r"C:\msys64\clang64\bin\g++.exe",
        r"C:\mingw64\bin\g++.exe",
    ],
    "cl": [
        r"C:\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
    ],
    "dotnet-symbol": [
        str(Path.home() / ".dotnet" / "tools" / "dotnet-symbol.exe"),
    ],
    "asar": [
        str(Path.home() / "AppData" / "Roaming" / "npm" / "asar.cmd"),
        str(Path.home() / "AppData" / "Roaming" / "npm" / "asar.ps1"),
    ],
    "unfself": [
        r"C:\Program Files\ps3tools\unfself.exe",
        r"C:\Program Files (x86)\ps3tools\unfself.exe",
    ],
    "scetool": [
        r"C:\Program Files\ps3tools\scetool.exe",
        r"C:\Program Files (x86)\ps3tools\scetool.exe",
    ],
    "pkg2zip": [
        r"C:\Program Files\pkg2zip\pkg2zip.exe",
        r"C:\Program Files (x86)\pkg2zip\pkg2zip.exe",
    ],
    "pkg_dec": [
        r"C:\Program Files\ps3tools\pkg_dec.exe",
        r"C:\Program Files (x86)\ps3tools\pkg_dec.exe",
    ],
    "pkgrip": [
        r"C:\Program Files\ps3tools\pkgrip.exe",
        r"C:\Program Files (x86)\ps3tools\pkgrip.exe",
    ],
    "pspdecrypt": [
        r"C:\Program Files\pspdecrypt\pspdecrypt.exe",
        r"C:\Program Files (x86)\pspdecrypt\pspdecrypt.exe",
    ],
    "psp-packer": [
        r"C:\Program Files\psp-packer\psp-packer.exe",
        r"C:\Program Files (x86)\psp-packer\psp-packer.exe",
    ],
}

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL_TOOL_ROOTS = [
    REPO_ROOT / "tools",
    Path.home() / ".re-pro" / "tools",
]
LOCAL_TOOL_GLOBS: dict[str, list[str]] = {
    "analyzeHeadless": [
        "Ghidra*/support/analyzeHeadless.bat",
        "ghidra*/support/analyzeHeadless.bat",
    ],
    "analyzeHeadless.bat": [
        "Ghidra*/support/analyzeHeadless.bat",
        "ghidra*/support/analyzeHeadless.bat",
    ],
    "ghidraRun": [
        "Ghidra*/ghidraRun.bat",
        "ghidra*/ghidraRun.bat",
    ],
    "rizin": [
        "rizin*/bin/rizin.exe",
    ],
    "rz-bin": [
        "rizin*/bin/rz-bin.exe",
    ],
    "radare2": [
        "radare2*/bin/radare2.exe",
        "r2blob*/radare2.exe",
    ],
    "r2": [
        "radare2*/bin/radare2.exe",
        "r2blob*/radare2.exe",
    ],
    "rabin2": [
        "radare2*/bin/rabin2.exe",
        "r2blob*/rabin2.exe",
    ],
    "java": [
        "jdk*/bin/java.exe",
        "OpenJDK*/bin/java.exe",
    ],
    "dotnet": [
        "dotnet/dotnet.exe",
        "dotnet*/dotnet.exe",
    ],
    "ilspycmd": [
        "ilspycmd/ilspycmd.exe",
        "ilspycmd*/ilspycmd.exe",
    ],
    "ilspycmd.exe": [
        "ilspycmd/ilspycmd.exe",
        "ilspycmd*/ilspycmd.exe",
    ],
    "jadx": [
        "bin/jadx.bat",
        "bin/jadx.exe",
        "jadx*/bin/jadx.bat",
        "jadx*/bin/jadx.exe",
    ],
    "jadx.bat": [
        "bin/jadx.bat",
        "jadx*/bin/jadx.bat",
    ],
    "apktool": [
        "apktool/apktool.bat",
        "apktool*/apktool.bat",
    ],
    "apktool.bat": [
        "apktool/apktool.bat",
        "apktool*/apktool.bat",
    ],
    "apktool.jar": [
        "apktool/apktool*.jar",
        "apktool*/apktool*.jar",
        "apktool*.jar",
    ],
    "llvm-objdump": [
        "LLVM*/bin/llvm-objdump.exe",
    ],
    "llvm-nm": [
        "LLVM*/bin/llvm-nm.exe",
    ],
    "llvm-pdbutil": [
        "LLVM*/bin/llvm-pdbutil.exe",
    ],
    "dotnet-symbol": [
        "dotnet-symbol/dotnet-symbol.exe",
        "dotnet-symbol*/dotnet-symbol.exe",
    ],
    "dotnet-symbol.exe": [
        "dotnet-symbol/dotnet-symbol.exe",
        "dotnet-symbol*/dotnet-symbol.exe",
    ],
    "asar": [
        "asar/node_modules/.bin/asar.cmd",
        "asar/node_modules/.bin/asar.ps1",
        "asar/node_modules/@electron/asar/bin/asar.js",
        "node_modules/.bin/asar.cmd",
        "node_modules/.bin/asar.ps1",
    ],
    "asar.cmd": [
        "asar/node_modules/.bin/asar.cmd",
        "node_modules/.bin/asar.cmd",
    ],
    "asar.ps1": [
        "asar/node_modules/.bin/asar.ps1",
        "node_modules/.bin/asar.ps1",
    ],
    "python-arm64": [
        "python-arm64/python.exe",
        "python-arm64*/python.exe",
    ],
    "unfself": [
        "ps3tools*/unfself.exe",
        "ps3tools*/bin/unfself.exe",
        "unfself*/unfself.exe",
        "unfself.exe",
        "unfself",
    ],
    "scetool": [
        "ps3tools*/scetool.exe",
        "ps3tools*/bin/scetool.exe",
        "scetool*/scetool.exe",
        "scetool.exe",
        "scetool",
    ],
    "pkg2zip": [
        "pkg2zip*/pkg2zip.exe",
        "pkg2zip*/bin/pkg2zip.exe",
        "pkg2zip.exe",
        "pkg2zip",
    ],
    "pkg_dec": [
        "ps3tools*/pkg_dec.exe",
        "ps3tools*/bin/pkg_dec.exe",
        "pkg_dec*/pkg_dec.exe",
        "pkg_dec.exe",
        "pkg_dec",
    ],
    "pkgrip": [
        "pkgrip*/pkgrip.exe",
        "pkgrip*/bin/pkgrip.exe",
        "pkgrip.exe",
        "pkgrip",
    ],
    "pspdecrypt": [
        "pspdecrypt*/pspdecrypt.exe",
        "pspdecrypt*/bin/pspdecrypt.exe",
        "pspdecrypt.exe",
        "pspdecrypt",
    ],
    "psp-packer": [
        "psp-packer/bin/psp-packer.exe",
        "psp-packer*/bin/psp-packer.exe",
        "psp-packer*/psp-packer.exe",
        "psp-packer.exe",
        "psp-packer",
    ],
}


def _resolve_executable(executable: str) -> str | None:
    if os.path.isabs(executable) and Path(executable).exists():
        return executable

    if any(separator in executable for separator in ("\\", "/")):
        candidate = Path(executable)
        if candidate.exists():
            return str(candidate)

    found = shutil.which(executable)
    if found:
        return found

    for match in _iter_local_tool_matches(executable):
        return match

    for pattern in COMMON_WINDOWS_PATTERNS.get(executable, []):
        matches = sorted(glob.glob(pattern), reverse=True)
        if matches:
            return matches[0]
    return None


def _iter_local_tool_matches(executable: str) -> Iterable[str]:
    for root in LOCAL_TOOL_ROOTS:
        if not root.exists():
            continue
        for pattern in LOCAL_TOOL_GLOBS.get(executable, []):
            matches = sorted((str(path) for path in root.glob(pattern) if path.exists()), reverse=True)
            for match in matches:
                yield match


def resolve_tool_path(executable: str, extra_patterns: list[str] | None = None) -> str | None:
    resolved = _resolve_executable(executable)
    if resolved:
        return resolved
    if not extra_patterns:
        return None
    for root in LOCAL_TOOL_ROOTS:
        if not root.exists():
            continue
        for pattern in extra_patterns:
            matches = sorted((str(path) for path in root.glob(pattern) if path.exists()), reverse=True)
            if matches:
                return matches[0]
    return None


def resolve_command(candidates: list[list[str]]) -> list[str] | None:
    for candidate in candidates:
        executable = candidate[0]
        resolved = _resolve_executable(executable)
        if resolved:
            return [resolved, *candidate[1:]]
    return None


@lru_cache(maxsize=1)
def get_ghidra_install_root() -> Path | None:
    command = resolve_command([["analyzeHeadless"], ["analyzeHeadless.bat"], ["ghidraRun"], ["ghidraRun.bat"]])
    if command is None:
        return None
    candidate = Path(command[0]).resolve()
    if candidate.parent.name.lower() == "support":
        return candidate.parent.parent
    return candidate.parent


@lru_cache(maxsize=1)
def list_ghidra_languages() -> list[dict[str, object]]:
    ghidra_root = get_ghidra_install_root()
    if ghidra_root is None:
        return []
    processors_root = ghidra_root / "Ghidra" / "Processors"
    if not processors_root.exists():
        return []

    languages: list[dict[str, object]] = []
    for ldefs_path in processors_root.rglob("*.ldefs"):
        try:
            root = ET.parse(ldefs_path).getroot()
        except ET.ParseError:
            continue
        for language in root.findall("language"):
            compiler_ids = [compiler.get("id", "") for compiler in language.findall("compiler") if compiler.get("id")]
            external_names = [
                {
                    "tool": external_name.get("tool", ""),
                    "name": external_name.get("name", ""),
                }
                for external_name in language.findall("external_name")
                if external_name.get("name")
            ]
            languages.append(
                {
                    "id": language.get("id", ""),
                    "processor": language.get("processor", ""),
                    "endian": language.get("endian", ""),
                    "size": language.get("size", ""),
                    "variant": language.get("variant", ""),
                    "description": (language.findtext("description") or "").strip(),
                    "compiler_ids": compiler_ids,
                    "external_names": external_names,
                    "source": str(ldefs_path),
                }
            )
    return languages


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    path_entries = [entry for entry in env.get("PATH", "").split(os.pathsep) if entry]
    java_executable = _resolve_executable("java")
    if java_executable:
        java_bin = str(Path(java_executable).parent)
        if java_bin not in path_entries:
            path_entries.insert(0, java_bin)
        env.setdefault("JAVA_HOME", str(Path(java_executable).parent.parent))
    dotnet_executable = _resolve_executable("dotnet")
    if dotnet_executable:
        dotnet_bin = str(Path(dotnet_executable).parent)
        if dotnet_bin not in path_entries:
            path_entries.insert(0, dotnet_bin)
        dotnet_root = str(Path(dotnet_executable).parent)
        env.setdefault("DOTNET_ROOT", dotnet_root)
        env.setdefault("DOTNET_ROOT_ARM64", dotnet_root)
    for executable in ("g++", "clang++", "cl"):
        resolved = _resolve_executable(executable)
        if not resolved:
            continue
        tool_bin = str(Path(resolved).parent)
        if tool_bin not in path_entries:
            path_entries.insert(0, tool_bin)
    env["PATH"] = os.pathsep.join(path_entries)
    return env


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
) -> tuple[int, str, str]:
    process = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
        capture_output=True,
        text=True,
        errors="ignore",
        check=False,
        env=_build_env(),
    )
    return process.returncode, process.stdout, process.stderr


def run_command_logged(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    logger=None,
    label: str | None = None,
    heartbeat_seconds: int = 15,
) -> tuple[int, str, str]:
    command_label = label or Path(command[0]).stem
    if logger:
        logger(f"[{command_label}] starting: {' '.join(command)}")
    process = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        bufsize=1,
        env=_build_env(),
    )

    events: Queue[tuple[str, str | None]] = Queue()
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []

    def _pump(stream, bucket: list[str], stream_name: str) -> None:
        try:
            assert stream is not None
            for line in iter(stream.readline, ""):
                bucket.append(line)
                events.put((stream_name, line.rstrip()))
        finally:
            if stream is not None:
                stream.close()
            events.put((stream_name, None))

    stdout_thread = threading.Thread(target=_pump, args=(process.stdout, stdout_parts, "stdout"), daemon=True)
    stderr_thread = threading.Thread(target=_pump, args=(process.stderr, stderr_parts, "stderr"), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    start = time.monotonic()
    next_heartbeat = start + heartbeat_seconds
    closed_streams = set()
    timed_out = False

    while True:
        now = time.monotonic()
        if timeout and now - start > timeout:
            timed_out = True
            process.kill()
            if logger:
                logger(f"[{command_label}] timed out after {int(now - start)}s")
            stderr_parts.append(f"Timed out after {timeout} seconds.\n")
            break

        while True:
            try:
                stream_name, line = events.get_nowait()
            except Empty:
                break
            if line is None:
                closed_streams.add(stream_name)
                continue
            if logger and line:
                logger(f"[{command_label}] {stream_name}: {line}")

        if process.poll() is not None and closed_streams >= {"stdout", "stderr"}:
            break

        if logger and now >= next_heartbeat:
            logger(f"[{command_label}] still running ({int(now - start)}s elapsed)")
            next_heartbeat = now + heartbeat_seconds
        time.sleep(0.2)

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    returncode = process.wait()
    elapsed = time.monotonic() - start
    if logger:
        state = "timed out" if timed_out else f"completed with exit code {returncode}"
        logger(f"[{command_label}] {state} in {elapsed:.1f}s")
    return returncode, "".join(stdout_parts), "".join(stderr_parts)
