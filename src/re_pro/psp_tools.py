from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any, Callable

from .tooling import resolve_command, run_command_logged
from .utils import ensure_dir, safe_slug

COMMAND_ENV = {
    "decrypt": "RE_PRO_PSP_DECRYPT_CMD",
    "psar_extract": "RE_PRO_PSP_PSAR_EXTRACT_CMD",
    "encrypt": "RE_PRO_PSP_ENCRYPT_CMD",
    "psar_pack": "RE_PRO_PSP_PSAR_PACK_CMD",
}
PSP_PACKER_TAG_ENV = "RE_PRO_PSP_PACKER_TAGS"


def psp_tool_status() -> dict[str, Any]:
    decrypt = _resolve_pspdecrypt()
    packer = _resolve_psp_packer()
    return {
        "pspdecrypt": _tool_info(decrypt),
        "psp_packer": _tool_info(packer),
        "environment_overrides": {
            name: os.environ.get(env_name, "")
            for name, env_name in COMMAND_ENV.items()
            if os.environ.get(env_name, "").strip()
        },
    }


def attempt_psp_tooling(
    target: Path,
    output_dir: Path,
    detections: list[dict[str, Any]],
    *,
    run_external_tools: bool = False,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    target = Path(target).resolve()
    output_dir = Path(output_dir).resolve()
    format_ids = {str(item.get("format_id", "")) for item in detections}
    result: dict[str, Any] = {
        "target": str(target),
        "run_external_tools": run_external_tools,
        "tool_status": psp_tool_status(),
        "results": [],
    }
    if not run_external_tools:
        result["results"].append(
            {
                "kind": "psp_tooling",
                "ok": False,
                "method": "skipped",
                "message": "External tools are disabled. Re-run with --external-tools to decrypt DATA.PSP or extract DATA.PSAR.",
            }
        )
        result["ok"] = False
        return result
    if "sony-psp-pbp" in format_ids:
        result["results"].append(decrypt_data_psp(target, output_dir / "data_psp", pbp_mode=True, logger=logger))
        result["results"].append(extract_data_psar(target, output_dir / "data_psar", pbp_mode=True, logger=logger))
    if "sony-psp-data-psp" in format_ids:
        result["results"].append(decrypt_data_psp(target, output_dir / "data_psp", pbp_mode=False, logger=logger))
    if "sony-psp-data-psar" in format_ids:
        result["results"].append(extract_data_psar(target, output_dir / "data_psar", pbp_mode=False, logger=logger))
    result["ok"] = any(bool(item.get("ok")) for item in result["results"])
    return result


def write_psp_tool_manifest(path: Path, result: dict[str, Any]) -> Path:
    ensure_dir(path.parent)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path


def materialize_pbp_tool_outputs(
    pbp_path: Path,
    output_root: Path,
    *,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create optional decrypted DATA.PSP and extracted DATA.PSAR browser views."""

    pbp_path = Path(pbp_path).resolve()
    output_root = ensure_dir(Path(output_root).resolve())
    results = [
        decrypt_data_psp(pbp_path, output_root / "_tools" / "DATA.PSP", pbp_mode=True, logger=logger),
        extract_data_psar(pbp_path, output_root / "_tools" / "DATA.PSAR", pbp_mode=True, logger=logger),
    ]
    result = {
        "ok": any(bool(item.get("ok")) for item in results),
        "target": str(pbp_path),
        "output_root": str(output_root),
        "tool_status": psp_tool_status(),
        "results": results,
    }
    write_psp_tool_manifest(output_root / "_tools" / "psp_tool_outputs.json", result)
    return result


def decrypt_data_psp(
    target: Path,
    output_dir: Path,
    *,
    pbp_mode: bool = False,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    target = Path(target).resolve()
    output_dir = ensure_dir(Path(output_dir).resolve())
    output_file = (output_dir / ("DATA.PSP.decrypted.bin" if pbp_mode else f"{safe_slug(target.stem)}.decrypted.bin")).resolve()
    command = _resolve_decrypt_command(target, output_file, output_dir, pbp_mode=pbp_mode)
    if command is None:
        return _skipped("data_psp_decrypt", "pspdecrypt was not found and RE_PRO_PSP_DECRYPT_CMD is not configured.")
    log_path = output_dir / "pspdecrypt_data_psp.log"
    code, stdout, stderr = _run_logged(command, target.parent, log_path, logger=logger, label="psp-data-psp")
    ok = code == 0 and output_file.exists() and output_file.stat().st_size > 0
    return {
        "kind": "data_psp_decrypt",
        "ok": ok,
        "method": "external_tool",
        "command": _redact_command(command),
        "exit_code": code,
        "output_path": str(output_file),
        "output_dir": str(output_dir),
        "log_path": str(log_path),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
        **({} if ok else {"message": "DATA.PSP decryptor did not produce a non-empty output file."}),
    }


def extract_data_psar(
    target: Path,
    output_dir: Path,
    *,
    pbp_mode: bool = False,
    extract_only: bool = False,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    target = Path(target).resolve()
    output_dir = ensure_dir(Path(output_dir).resolve())
    command = _resolve_psar_extract_command(target, output_dir, pbp_mode=pbp_mode, extract_only=extract_only)
    if command is None:
        return _skipped("data_psar_extract", "pspdecrypt was not found and RE_PRO_PSP_PSAR_EXTRACT_CMD is not configured.")
    before = _snapshot_files(output_dir)
    log_path = output_dir / "pspdecrypt_data_psar.log"
    code, stdout, stderr = _run_logged(command, target.parent, log_path, logger=logger, label="psp-data-psar")
    extracted_files = [str(path) for path in _new_files(output_dir, before) if path != log_path]
    ok = code == 0 and bool(extracted_files)
    return {
        "kind": "data_psar_extract",
        "ok": ok,
        "method": "external_tool",
        "command": _redact_command(command),
        "exit_code": code,
        "output_dir": str(output_dir),
        "log_path": str(log_path),
        "extracted_file_count": len(extracted_files),
        "sample_outputs": extracted_files[:50],
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
        **({} if ok else {"message": "DATA.PSAR extractor did not produce files in the extraction directory."}),
    }


def encrypt_data_psp(
    input_path: Path,
    output_path: Path,
    *,
    work_dir: Path,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    input_path = Path(input_path).resolve()
    output_path = Path(output_path).resolve()
    work_dir = ensure_dir(Path(work_dir).resolve())
    ensure_dir(output_path.parent)
    command = _resolve_encrypt_command(input_path, output_path, work_dir)
    if command is None:
        return _skipped("data_psp_encrypt", "No DATA.PSP encrypt/pack tool is configured and psp-packer was not found.")
    log_path = work_dir / "psp_encrypt_data_psp.log"
    code, stdout, stderr = _run_logged(command, work_dir, log_path, logger=logger, label="psp-data-psp-pack")
    ok = code == 0 and output_path.exists() and output_path.stat().st_size > 0
    return {
        "kind": "data_psp_encrypt",
        "ok": ok,
        "method": "external_tool",
        "command": _redact_command(command),
        "exit_code": code,
        "output_path": str(output_path),
        "log_path": str(log_path),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
        **({} if ok else {"message": "DATA.PSP encrypt/pack tool did not produce a non-empty output file."}),
    }


def pack_data_psar(
    input_dir: Path,
    output_path: Path,
    *,
    work_dir: Path,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    input_dir = Path(input_dir).resolve()
    output_path = Path(output_path).resolve()
    work_dir = ensure_dir(Path(work_dir).resolve())
    ensure_dir(output_path.parent)
    command = _resolve_psar_pack_command(input_dir, output_path, work_dir)
    if command is None:
        return _skipped("data_psar_pack", "DATA.PSAR repack/encrypt requires RE_PRO_PSP_PSAR_PACK_CMD; no bundled PSAR repacker is available.")
    log_path = work_dir / "psp_pack_data_psar.log"
    code, stdout, stderr = _run_logged(command, work_dir, log_path, logger=logger, label="psp-data-psar-pack")
    ok = code == 0 and output_path.exists() and output_path.stat().st_size > 0
    return {
        "kind": "data_psar_pack",
        "ok": ok,
        "method": "external_tool",
        "command": _redact_command(command),
        "exit_code": code,
        "output_path": str(output_path),
        "log_path": str(log_path),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
        **({} if ok else {"message": "DATA.PSAR repack command did not produce a non-empty output file."}),
    }


def _resolve_decrypt_command(target: Path, output_file: Path, output_dir: Path, *, pbp_mode: bool) -> list[str] | None:
    env_command = _command_from_template(os.environ.get(COMMAND_ENV["decrypt"], ""), target, output_file, output_dir)
    if env_command:
        return env_command
    pspdecrypt = _resolve_pspdecrypt()
    if pspdecrypt is None:
        return None
    command = pspdecrypt + [f"--outfile={output_file}"]
    if pbp_mode:
        command.append("--psp-only")
    command.append(str(target))
    return command


def _resolve_psar_extract_command(target: Path, output_dir: Path, *, pbp_mode: bool, extract_only: bool) -> list[str] | None:
    env_command = _command_from_template(os.environ.get(COMMAND_ENV["psar_extract"], ""), target, output_dir, output_dir)
    if env_command:
        return env_command
    pspdecrypt = _resolve_pspdecrypt()
    if pspdecrypt is None:
        return None
    command = pspdecrypt + [f"--outdir={output_dir}"]
    if pbp_mode:
        command.append("--psar-only")
    if extract_only:
        command.append("--extract-only")
    command.append(str(target))
    return command


def _resolve_encrypt_command(input_path: Path, output_path: Path, output_dir: Path) -> list[str] | None:
    env_command = _command_from_template(os.environ.get(COMMAND_ENV["encrypt"], ""), input_path, output_path, output_dir)
    if env_command:
        return env_command
    packer = _resolve_psp_packer()
    if packer is None:
        return None
    command = packer + ["--output", str(output_path)]
    tags = shlex.split(os.environ.get(PSP_PACKER_TAG_ENV, ""), posix=os.name != "nt")
    if tags:
        command.extend(["--tags", *tags[:2]])
    command.append(str(input_path))
    return command


def _resolve_psar_pack_command(input_dir: Path, output_path: Path, output_dir: Path) -> list[str] | None:
    return _command_from_template(os.environ.get(COMMAND_ENV["psar_pack"], ""), input_dir, output_path, output_dir)


def _resolve_pspdecrypt() -> list[str] | None:
    return resolve_command([["pspdecrypt"], ["pspdecrypt.exe"]])


def _resolve_psp_packer() -> list[str] | None:
    return resolve_command([["psp-packer"], ["psp-packer.exe"]])


def _command_from_template(template: str, target: Path, output: Path, output_dir: Path) -> list[str] | None:
    template = template.strip()
    if not template:
        return None
    rendered = template.format(
        input=str(target),
        output=str(output),
        output_dir=str(output_dir),
        stem=safe_slug(target.stem),
    )
    return shlex.split(rendered, posix=True)


def _run_logged(
    command: list[str],
    cwd: Path,
    log_path: Path,
    *,
    logger: Callable[[str], None] | None,
    label: str,
) -> tuple[int, str, str]:
    ensure_dir(log_path.parent)

    def _log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")
        if logger:
            logger(message)

    return run_command_logged(command, cwd=cwd, timeout=4 * 3600, logger=_log, label=label, heartbeat_seconds=20)


def _snapshot_files(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}


def _new_files(root: Path, before: set[str]) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and str(path.relative_to(root)) not in before)


def _skipped(kind: str, message: str) -> dict[str, Any]:
    return {"kind": kind, "ok": False, "method": "skipped", "message": message}


def _tool_info(command: list[str] | None) -> dict[str, Any]:
    if not command:
        return {"available": False}
    path = Path(command[0])
    payload: dict[str, Any] = {"available": True, "command": command, "path": str(path)}
    try:
        payload["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return payload


def _redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    sensitive_flags = {"--key", "--keys", "--tag", "--tags", "--kirk", "--seed", "--password"}
    for part in command:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        lowered = part.lower()
        if lowered in sensitive_flags:
            redacted.append(part)
            skip_next = True
            continue
        if any(token in lowered for token in ("key", "tag", "seed", "password")) and "=" in part:
            name, _value = part.split("=", 1)
            redacted.append(f"{name}=<redacted>")
            continue
        redacted.append(part)
    return redacted
