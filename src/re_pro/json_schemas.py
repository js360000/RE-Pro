"""Lightweight runtime validation for the JSON artifacts RE-Pro reads back.

Several call sites load JSON written by earlier analysis runs (``report.json``,
``browser_manifest.json``, ``edits.json``, ``analysis_index.json``). Until
now the readers used a bare ``json.loads`` followed by ``isinstance`` spot
checks; malformed or out-of-date artifacts surfaced as ``KeyError`` or
``TypeError`` deep in the call stack.

This module centralizes the "minimum viable" shape checks. It is deliberately
dependency-free (no pydantic) so the package can keep its small runtime
footprint. The schemas only validate the top-level structure and the
required keys — analyzers remain free to add fields without churn here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SchemaError(ValueError):
    """Raised when a JSON artifact does not match its expected shape."""

    def __init__(self, path: Path | str, message: str) -> None:
        self.path = Path(path)
        super().__init__(f"{self.path}: {message}")


def _require_object(path: Path, payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SchemaError(path, f"expected a JSON object, got {type(payload).__name__}")
    return payload


def _require_keys(path: Path, payload: dict[str, Any], required: tuple[str, ...]) -> None:
    missing = [key for key in required if key not in payload]
    if missing:
        raise SchemaError(path, f"missing required key(s): {', '.join(missing)}")


def _require_type(path: Path, payload: dict[str, Any], key: str, expected: type | tuple[type, ...]) -> None:
    value = payload.get(key)
    if value is None:
        return
    if not isinstance(value, expected):
        names = expected.__name__ if isinstance(expected, type) else "/".join(t.__name__ for t in expected)
        raise SchemaError(path, f"key '{key}' must be {names}, got {type(value).__name__}")


def load_json_object(path: Path) -> dict[str, Any]:
    """Read a JSON file and assert it deserializes to an object.

    Raises ``FileNotFoundError`` if the file is missing, ``SchemaError`` for
    invalid JSON or a non-object root.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        raise
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(path, f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc
    return _require_object(path, payload)


def validate_report(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the top-level shape of ``report.json`` produced by reporting.py.

    Only ``target`` is strictly required — all other fields are optional so
    older or partial reports remain readable, but where a key is present its
    type is enforced.
    """
    _require_keys(path, payload, ("target",))
    _require_type(path, payload, "target", str)
    _require_type(path, payload, "target_type", str)
    _require_type(path, payload, "output_dir", str)
    _require_type(path, payload, "frameworks", list)
    _require_type(path, payload, "findings", list)
    _require_type(path, payload, "artifacts", list)
    _require_type(path, payload, "recovered_sources", list)
    _require_type(path, payload, "notes", list)
    _require_type(path, payload, "fingerprints", dict)
    return payload


def validate_browser_manifest(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the top-level shape of ``browser_manifest.json``."""
    _require_keys(path, payload, ("workspace_root", "nodes"))
    _require_type(path, payload, "workspace_root", str)
    _require_type(path, payload, "nodes", list)
    _require_type(path, payload, "manifest_path", str)
    _require_type(path, payload, "edits_path", str)
    return payload


def validate_edits(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the top-level shape of ``edits.json``."""
    _require_type(path, payload, "edits", list)
    if "edits" in payload and not isinstance(payload["edits"], list):
        raise SchemaError(path, "key 'edits' must be a list")
    return payload


def validate_analysis_index(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the top-level shape of ``analysis_index.json``.

    ``entities`` and ``relations`` are required; ``summary`` is optional so
    older indexes (and minimal test fixtures) still load.
    """
    _require_keys(path, payload, ("entities", "relations"))
    _require_type(path, payload, "summary", dict)
    _require_type(path, payload, "entities", list)
    _require_type(path, payload, "relations", list)
    return payload


def load_report(path: Path) -> dict[str, Any]:
    return validate_report(path, load_json_object(path))


def load_browser_manifest(path: Path) -> dict[str, Any]:
    return validate_browser_manifest(path, load_json_object(path))


def load_edits(path: Path) -> dict[str, Any]:
    return validate_edits(path, load_json_object(path))


def load_analysis_index(path: Path) -> dict[str, Any]:
    return validate_analysis_index(path, load_json_object(path))
