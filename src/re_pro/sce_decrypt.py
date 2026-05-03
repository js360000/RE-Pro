from __future__ import annotations

import json
import os
import shlex
import shutil
from pathlib import Path
from typing import Any, Callable

from .tooling import resolve_command, run_command_logged
from .utils import ensure_dir, safe_slug


SELF_FORMAT_IDS = {"sony-sce-self"}
PKG_FORMAT_IDS = {"sony-pkg"}
COMMAND_ENV = {
    "self": "RE_PRO_SELF_DECRYPT_CMD",
    "pkg": "RE_PRO_PKG_EXTRACT_CMD",
}
PKG_LICENSE_ENV = "RE_PRO_PKG_ZRIF"


def attempt_sce_unpack(
    target: Path,
    output_dir: Path,
    detections: list[dict[str, Any]],
    *,
    run_external_tools: bool = False,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    format_ids = {str(item.get("format_id", "")) for item in detections}
    result: dict[str, Any] = {
        "target": str(target),
        "run_external_tools": run_external_tools,
        "results": [],
        "notes": [
            "RE-Pro does not ship Sony keys or license material. Configure legal local tools/keys via environment variables or installed tool defaults.",
        ],
    }
    if SELF_FORMAT_IDS & format_ids:
        result["results"].append(_attempt_self_unpack(target, output_dir / "self", run_external_tools=run_external_tools, logger=logger))
    if PKG_FORMAT_IDS & format_ids:
        result["results"].append(_attempt_pkg_unpack(target, output_dir / "pkg", run_external_tools=run_external_tools, logger=logger))
    result["ok"] = any(bool(item.get("ok")) for item in result["results"])
    return result


def _attempt_self_unpack(target: Path, output_dir: Path, *, run_external_tools: bool, logger: Callable[[str], None] | None) -> dict[str, Any]:
    ensure_dir(output_dir)
    output_elf = output_dir / f"{safe_slug(target.stem)}.elf"
    carved = _carve_embedded_elf(target, output_elf)
    if carved["ok"]:
        return {
            "kind": "self",
            "ok": True,
            "method": "embedded_elf_carve",
            "output_path": str(output_elf),
            "details": carved,
        }

    if not run_external_tools:
        return _skipped(
            "self",
            "External tools are disabled. Re-run analysis with --external-tools, or set RE_PRO_SELF_DECRYPT_CMD for a custom legal SELF decryptor.",
            carved,
        )

    command = _resolve_self_command(target, output_elf)
    if command is None:
        return _skipped(
            "self",
            "No SELF decryptor was found. Install unfself/scetool or set RE_PRO_SELF_DECRYPT_CMD with {input}, {output}, and {output_dir} placeholders.",
            carved,
        )

    log_path = output_dir / "self_decrypt.log"
    code, stdout, stderr = _run_logged(command, target.parent, log_path, logger=logger, label="sce-self")
    ok = code == 0 and output_elf.exists() and output_elf.stat().st_size > 0
    result = {
        "kind": "self",
        "ok": ok,
        "method": "external_tool",
        "command": _redact_command(command),
        "exit_code": code,
        "output_path": str(output_elf),
        "log_path": str(log_path),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }
    if not ok:
        result["message"] = "SELF decryptor did not produce a non-empty ELF output."
    return result


def _attempt_pkg_unpack(target: Path, output_dir: Path, *, run_external_tools: bool, logger: Callable[[str], None] | None) -> dict[str, Any]:
    ensure_dir(output_dir)
    before = _snapshot_files(output_dir)
    if not run_external_tools:
        return _skipped(
            "pkg",
            "External tools are disabled. Re-run analysis with --external-tools, or set RE_PRO_PKG_EXTRACT_CMD for a custom legal PKG extractor.",
            {"ok": False, "reason": "external_tools_disabled"},
        )

    command = _resolve_pkg_command(target, output_dir)
    if command is None:
        return _skipped(
            "pkg",
            "No PKG extractor was found. Install pkg2zip/pkg_dec/pkgrip or set RE_PRO_PKG_EXTRACT_CMD with {input}, {output_dir}, and {output} placeholders.",
            {"ok": False, "reason": "tool_not_found"},
        )

    log_path = output_dir / "pkg_extract.log"
    code, stdout, stderr = _run_logged(command, output_dir, log_path, logger=logger, label="sce-pkg")
    extracted_files = [str(path) for path in _new_files(output_dir, before)]
    ok = code == 0 and bool(extracted_files)
    result = {
        "kind": "pkg",
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
    }
    if not ok:
        result["message"] = "PKG extractor did not produce files in the extraction directory."
    return result


def _resolve_self_command(target: Path, output_elf: Path) -> list[str] | None:
    env_command = _command_from_template(os.environ.get(COMMAND_ENV["self"], ""), target, output_elf, output_elf.parent)
    if env_command:
        return env_command
    unfself = resolve_command([["unfself"]])
    if unfself is not None:
        return unfself + [str(target), str(output_elf)]
    scetool = resolve_command([["scetool"]])
    if scetool is not None:
        return scetool + ["--decrypt", str(target), str(output_elf)]
    return None


def _resolve_pkg_command(target: Path, output_dir: Path) -> list[str] | None:
    default_output = output_dir / safe_slug(target.stem)
    env_command = _command_from_template(os.environ.get(COMMAND_ENV["pkg"], ""), target, default_output, output_dir)
    if env_command:
        return env_command
    pkg2zip = resolve_command([["pkg2zip"]])
    if pkg2zip is not None:
        command = pkg2zip + ["-x", str(target)]
        zrif = os.environ.get(PKG_LICENSE_ENV, "").strip()
        if zrif:
            command.append(zrif)
        return command
    pkg_dec = resolve_command([["pkg_dec"]])
    if pkg_dec is not None:
        return pkg_dec + [str(target), str(output_dir)]
    pkgrip = resolve_command([["pkgrip"]])
    if pkgrip is not None:
        return pkgrip + [str(target)]
    return None


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
    return shlex.split(rendered, posix=os.name != "nt")


def _carve_embedded_elf(target: Path, output_elf: Path) -> dict[str, Any]:
    try:
        data = target.read_bytes()
    except OSError as exc:
        return {"ok": False, "reason": f"read_failed: {exc}"}
    offset = data.find(b"\x7fELF", 4)
    if offset < 0:
        return {"ok": False, "reason": "no_embedded_elf_magic"}
    ensure_dir(output_elf.parent)
    output_elf.write_bytes(data[offset:])
    return {
        "ok": True,
        "offset": offset,
        "size": output_elf.stat().st_size,
    }


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


def _skipped(kind: str, message: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "ok": False,
        "method": "skipped",
        "message": message,
        "details": details,
    }


def _redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    sensitive_flags = {"--key", "--keys", "--rap", "--rif", "--zrif", "--passcode", "--password"}
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
        if any(token in lowered for token in ("zrif", "klicense", "passcode", "password")) and "=" in part:
            name, _value = part.split("=", 1)
            redacted.append(f"{name}=<redacted>")
            continue
        redacted.append(part)
    return redacted


def write_sce_unpack_manifest(path: Path, result: dict[str, Any]) -> Path:
    ensure_dir(path.parent)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path


def copy_pkg_zip_outputs(output_dir: Path) -> list[Path]:
    copied: list[Path] = []
    for zip_path in output_dir.glob("*.zip"):
        extract_dir = ensure_dir(output_dir / f"{safe_slug(zip_path.stem)}_zip_extract")
        try:
            shutil.unpack_archive(str(zip_path), str(extract_dir), "zip")
        except (shutil.ReadError, OSError):
            continue
        copied.append(extract_dir)
    return copied
