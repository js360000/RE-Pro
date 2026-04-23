from __future__ import annotations

import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .tooling import resolve_command, run_command
from .utils import ensure_dir


DEFAULT_SYMBOL_SERVERS = [
    "https://msdl.microsoft.com/download/symbols/",
]


def get_configured_symbol_servers() -> list[str]:
    configured = os.environ.get("RE_PRO_SYMBOL_SERVERS", "").strip()
    if not configured:
        return DEFAULT_SYMBOL_SERVERS[:]
    servers = [value.strip() for value in configured.split(";") if value.strip()]
    return servers or DEFAULT_SYMBOL_SERVERS[:]


def acquire_pdbs_from_symbol_servers(
    codeview_records: list[dict[str, object]],
    destination_dir: Path,
    *,
    logger=None,
    timeout: int = 30,
    symbol_servers: list[str] | None = None,
) -> list[dict[str, str]]:
    ensure_dir(destination_dir)
    servers = symbol_servers or get_configured_symbol_servers()
    downloads: list[dict[str, str]] = []
    seen_paths: set[Path] = set()
    for record in codeview_records:
        pdb_path = str(record.get("pdb_path", "")).strip()
        guid = str(record.get("guid", "")).strip()
        age_value = record.get("age")
        if not pdb_path or not guid or age_value in (None, ""):
            continue
        pdb_name = Path(pdb_path).name
        try:
            age = int(age_value)
        except (TypeError, ValueError):
            continue
        for server in servers:
            for key in _build_symbol_store_keys(guid, age):
                direct_url = urljoin(_ensure_trailing_slash(server), f"{pdb_name}/{key}/{pdb_name}")
                target_path = destination_dir / pdb_name
                if target_path in seen_paths and target_path.exists():
                    downloads.append(
                        {
                            "path": str(target_path),
                            "server": server,
                            "url": direct_url,
                            "key": key,
                            "method": "cached",
                        }
                    )
                    break
                downloaded = _download_symbol_payload(direct_url, target_path, timeout=timeout, logger=logger, expect_pdb=True)
                if downloaded is not None:
                    seen_paths.add(downloaded)
                    downloads.append(
                        {
                            "path": str(downloaded),
                            "server": server,
                            "url": direct_url,
                            "key": key,
                            "method": "http",
                        }
                    )
                    break

                compressed_name = _compressed_pdb_name(pdb_name)
                compressed_url = urljoin(_ensure_trailing_slash(server), f"{pdb_name}/{key}/{compressed_name}")
                compressed_path = destination_dir / compressed_name
                downloaded_compressed = _download_symbol_payload(
                    compressed_url,
                    compressed_path,
                    timeout=timeout,
                    logger=logger,
                    expect_pdb=False,
                )
                if downloaded_compressed is None:
                    continue
                expanded = _expand_compressed_pdb(downloaded_compressed, target_path, logger=logger)
                final_path = expanded or downloaded_compressed
                seen_paths.add(final_path)
                downloads.append(
                    {
                        "path": str(final_path),
                        "server": server,
                        "url": compressed_url,
                        "key": key,
                        "method": "http-expand" if expanded else "http-compressed",
                    }
                )
                break
            else:
                continue
            break
    return downloads


def download_with_dotnet_symbol(
    target: Path,
    destination_dir: Path,
    *,
    logger=None,
    timeout: int = 1800,
    symbol_servers: list[str] | None = None,
) -> dict[str, object] | None:
    command = resolve_command([["dotnet-symbol"], ["dotnet-symbol.exe"]])
    if command is None:
        return None
    ensure_dir(destination_dir)
    servers = symbol_servers or get_configured_symbol_servers()
    invocation = command + ["--symbols", "--modules", "-o", str(destination_dir)]
    for server in servers:
        if server.rstrip("/").lower() == "https://msdl.microsoft.com/download/symbols".rstrip("/").lower():
            invocation.append("--microsoft-symbol-server")
        else:
            invocation.extend(["--server-path", server])
    invocation.append(str(target))
    code, stdout, stderr = run_command(invocation, cwd=target.parent, timeout=timeout)
    return {
        "ok": code == 0,
        "command": invocation,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
        "output_dir": str(destination_dir),
    }


def _build_symbol_store_keys(guid: str, age: int) -> list[str]:
    normalized_guid = guid.replace("-", "").strip().upper()
    decimal_age = str(age)
    hex_age = format(age, "X")
    keys = [f"{normalized_guid}{decimal_age}"]
    if hex_age != decimal_age:
        keys.append(f"{normalized_guid}{hex_age}")
    return keys


def _ensure_trailing_slash(value: str) -> str:
    return value if value.endswith("/") else value + "/"


def _compressed_pdb_name(pdb_name: str) -> str:
    if len(pdb_name) < 2:
        return pdb_name + "_"
    return pdb_name[:-1] + "_"


def _download_symbol_payload(url: str, destination: Path, *, timeout: int, logger=None, expect_pdb: bool) -> Path | None:
    if logger:
        logger(f"Attempting symbol download: {url}")
    request = Request(url, headers={"User-Agent": "RE-Pro"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        if logger:
            logger(f"Symbol download miss: {url} ({exc})")
        return None
    if expect_pdb and not _looks_like_pdb_payload(payload):
        if logger:
            logger(f"Symbol download rejected as non-PDB payload: {url}")
        return None
    destination.write_bytes(payload)
    return destination


def _expand_compressed_pdb(source: Path, destination: Path, *, logger=None) -> Path | None:
    command = resolve_command([["expand"]])
    if command is None:
        if logger:
            logger("Compressed symbol payload downloaded, but expand.exe is unavailable.")
        return None
    code, stdout, stderr = run_command(command + [str(source), str(destination)], cwd=source.parent, timeout=120)
    if code != 0 or not destination.exists():
        if logger:
            message = stderr.strip() or stdout.strip() or f"expand.exe exited with {code}"
            logger(f"Failed to expand compressed symbol payload {source.name}: {message}")
        return None
    return destination


def _looks_like_pdb_payload(payload: bytes) -> bool:
    if not payload:
        return False
    if payload.startswith(b"Microsoft C/C++ MSF 7.00\r\n"):
        return True
    if payload.startswith(b"BSJB"):
        return True
    return False
