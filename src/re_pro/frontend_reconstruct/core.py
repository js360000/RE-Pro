"""Orchestration for bundled frontend asset reconstruction.

Public entry point: ``reconstruct_bundled_frontend_assets``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from ..utils import ensure_dir, safe_output_path
from .helpers import (
    _basic_code_beautify,
    _infer_export_symbol_name,
    _looks_minified,
    _module_name_from_path,
    _relative_posix_reference,
    _resolve_posix_reference,
)
from .lifting import (
    _equivalence_checks,
    _lift_css_bundle,
    _lift_javascript_bundle,
    _optional_ast_format_and_validate,
    _prepare_or_run_llm_source_grade,
    _should_attempt_ast,
)

TEXT_ASSET_EXTENSIONS = {
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".html",
    ".json",
    ".svg",
    ".md",
    ".txt",
    ".xml",
}

CODE_ASSET_EXTENSIONS = {".js", ".mjs", ".cjs", ".css", ".html", ".json"}
MAX_RECONSTITUTED_TEXT_BYTES = 8_000_000


def reconstruct_bundled_frontend_assets(
    assets_dir: Path,
    manifest_path: Path,
    recovered_sources_root: Path,
    *,
    bundle_name: str = "tauri_bundle",
    clean_hashed_names: bool = True,
    llm_settings: object | None = None,
    llm_client_factory: Callable[[], Any] | None = None,
) -> dict[str, object]:
    """Create a best-effort source workspace from bundled frontend assets.

    This is intentionally not source-map recovery: the output preserves shipped
    chunk names and labels confidence as bundled-asset reconstruction.
    """

    if not assets_dir.exists():
        return {"recovered_sources": [], "notes": [f"No extracted frontend asset directory found at {assets_dir}."]}

    source_root = ensure_dir(recovered_sources_root / bundle_name)
    entries = _load_asset_manifest(manifest_path, assets_dir)
    recovered_sources: list[dict[str, str]] = []
    manifest: list[dict[str, object]] = []
    skipped = 0
    logical_paths = _build_logical_path_map(entries, assets_dir, clean_hashed_names=clean_hashed_names)
    module_graph = _build_module_graph(entries, assets_dir, logical_paths)
    ast_attempts = 0
    max_ast_attempts = 80

    for entry in entries:
        asset_path = Path(str(entry.get("path") or ""))
        if not asset_path.exists() or not asset_path.is_file():
            skipped += 1
            continue

        suffix = asset_path.suffix.lower()
        if suffix == ".map" or suffix not in TEXT_ASSET_EXTENSIONS:
            skipped += 1
            continue
        if asset_path.stat().st_size > MAX_RECONSTITUTED_TEXT_BYTES:
            skipped += 1
            continue

        try:
            raw_text = asset_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            skipped += 1
            continue
        if not raw_text.strip():
            skipped += 1
            continue

        original_logical_path = _logical_asset_path(entry, asset_path, assets_dir)
        logical_path = logical_paths.get(original_logical_path, original_logical_path)
        destination = _unique_output_path(safe_output_path(source_root, logical_path))
        ensure_dir(destination.parent)
        reconstituted = _reconstitute_text_asset(raw_text, suffix)
        lifted_text, lift_metadata = _source_lift_text_asset(
            reconstituted,
            suffix,
            original_logical_path,
            logical_path,
            logical_paths,
            module_graph,
        )
        if ast_attempts < max_ast_attempts and _should_attempt_ast(lifted_text, suffix, lift_metadata):
            ast_attempts += 1
            lifted_text, ast_metadata = _optional_ast_format_and_validate(lifted_text, logical_path)
        else:
            ast_metadata = {"available": False, "reason": "ast_budget_or_low_value_candidate"}
        if ast_metadata.get("formatted"):
            lift_metadata.setdefault("features", []).append("ast_formatted")
        lift_metadata["ast"] = ast_metadata
        lift_metadata["equivalence"] = _equivalence_checks(lifted_text, suffix, logical_path, logical_paths, ast_metadata)
        destination.write_text(_reconstruction_header(original_logical_path, suffix, lift_metadata) + lifted_text, encoding="utf-8")

        record = {
            "original_path": f"{bundle_name}::{original_logical_path}",
            "restored_path": str(destination),
            "source_map": f"{bundle_name}_asset_reconstruction",
        }
        recovered_sources.append(record)
        manifest.append(
            {
                "asset_path": original_logical_path,
                "cleaned_path": logical_path,
                "restored_path": str(destination),
                "extension": suffix,
                "kind": _asset_kind(suffix),
                "raw_size": asset_path.stat().st_size,
                "confidence": "bundled_asset_without_source_map",
                "source_lift": lift_metadata,
            }
        )

    reconstruction_manifest = source_root / "BUNDLE_RECONSTRUCTION_MANIFEST.json"
    llm_source_grade = _prepare_or_run_llm_source_grade(
        source_root,
        manifest,
        llm_settings=llm_settings,
        llm_client_factory=llm_client_factory,
    )
    reconstruction_manifest.write_text(
        json.dumps(
            {
                "strategy": "best_effort_bundled_asset_reconstitution",
                "source_maps_available": False,
                "asset_root": str(assets_dir),
                "recovered_count": len(recovered_sources),
                "skipped_count": skipped,
                "module_graph": module_graph,
                "ast_attempted_count": ast_attempts,
                "ast_budget": max_ast_attempts,
                "llm_source_grade": llm_source_grade,
                "files": manifest,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (source_root / "README.md").write_text(
        "# Bundled Frontend Reconstruction\n\n"
        "These files are reconstructed from shipped frontend bundle assets because no usable source maps were found. "
        "Names, module boundaries, and JSX syntax are recovered with deterministic heuristics and optional Babel AST "
        "validation from bundled asset paths, imports, exports, React runtime calls, and minifier patterns. JavaScript, "
        "CSS, HTML, and JSON assets are formatted when they appear minified, but behavior remains derived from the shipped bundle.\n",
        encoding="utf-8",
    )

    return {
        "source_root": source_root,
        "manifest_path": reconstruction_manifest,
        "recovered_sources": recovered_sources,
        "recovered_count": len(recovered_sources),
        "skipped_count": skipped,
        "notes": [
            f"Reconstituted {len(recovered_sources)} bundled frontend asset(s) into {source_root} without source maps.",
            str(llm_source_grade.get("note", "")),
        ],
    }


def _load_asset_manifest(manifest_path: Path, assets_dir: Path) -> list[dict[str, object]]:
    if manifest_path.exists():
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = []
        if isinstance(payload, list):
            return [entry for entry in payload if isinstance(entry, dict)]

    entries: list[dict[str, object]] = []
    for path in sorted(assets_dir.rglob("*")):
        if path.is_file():
            entries.append({"key": path.relative_to(assets_dir).as_posix(), "path": str(path), "raw_size": path.stat().st_size})
    return entries


def _logical_asset_path(entry: dict[str, object], asset_path: Path, assets_dir: Path) -> str:
    key = str(entry.get("key") or "").strip()
    if key:
        return key.lstrip("/")
    try:
        return asset_path.relative_to(assets_dir).as_posix()
    except ValueError:
        return asset_path.name


def _build_logical_path_map(entries: list[dict[str, object]], assets_dir: Path, *, clean_hashed_names: bool) -> dict[str, str]:
    path_map: dict[str, str] = {}
    used: set[str] = set()
    for entry in entries:
        asset_path = Path(str(entry.get("path") or ""))
        if not asset_path.exists() or not asset_path.is_file():
            continue
        original = _logical_asset_path(entry, asset_path, assets_dir)
        cleaned = _clean_logical_asset_path(original) if clean_hashed_names else original
        path_map[original] = _dedupe_logical_path(cleaned, used)
    return path_map


def _build_module_graph(entries: list[dict[str, object]], assets_dir: Path, logical_paths: dict[str, str]) -> dict[str, object]:
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, str]] = []
    for entry in entries:
        asset_path = Path(str(entry.get("path") or ""))
        if not asset_path.exists() or not asset_path.is_file():
            continue
        suffix = asset_path.suffix.lower()
        if suffix not in {".js", ".mjs", ".cjs", ".css"}:
            continue
        try:
            if asset_path.stat().st_size > MAX_RECONSTITUTED_TEXT_BYTES:
                continue
            raw_text = asset_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        original = _logical_asset_path(entry, asset_path, assets_dir)
        cleaned = logical_paths.get(original, original)
        imports = _extract_module_references(raw_text, original, cleaned, logical_paths)
        exports = _extract_export_names(raw_text)
        inferred = _infer_export_symbol_name(cleaned, raw_text)
        first_export = exports[0] if exports else ""
        primary_export = first_export if first_export and not _looks_like_minified_export_name(first_export) else inferred
        nodes[cleaned] = {
            "original_path": original,
            "cleaned_path": cleaned,
            "kind": _asset_kind(suffix),
            "imports": imports,
            "exports": exports,
            "inferred_module": _module_name_from_path(cleaned),
            "primary_export": primary_export,
        }
        for imported in imports:
            edges.append({"from": cleaned, "to": imported})
    return {"nodes": nodes, "edges": edges}


def _looks_like_minified_export_name(name: str) -> bool:
    return name == "default" or bool(re.fullmatch(r"[a-z_$][\w$]?", name))


def _extract_module_references(text: str, original_logical_path: str, cleaned_logical_path: str, logical_paths: dict[str, str]) -> list[str]:
    refs: list[str] = []
    patterns = [
        r"\bfrom\s*[\"'`](?P<ref>[^\"'`]+)[\"'`]",
        r"\bimport\s*\(\s*[\"'`](?P<ref>[^\"'`]+)[\"'`]",
        r"\bimport\s*[\"'`](?P<ref>[^\"'`]+)[\"'`]",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            reference = match.group("ref")
            rewritten = _rewrite_single_reference(reference, original_logical_path, cleaned_logical_path, logical_paths)
            if rewritten.startswith("."):
                target = _resolve_posix_reference(PurePosixPath(cleaned_logical_path).parent, rewritten)
            else:
                target = rewritten
            if target not in refs:
                refs.append(target)
    return refs


def _extract_export_names(text: str) -> list[str]:
    exports: list[str] = []
    for match in re.finditer(r"\bexport\s*\{(?P<body>[^}]+)\}", text, flags=re.DOTALL):
        body = " ".join(match.group("body").split())
        for piece in body.split(","):
            piece = piece.strip()
            if not piece:
                continue
            alias = re.search(r"\bas\s+([A-Za-z_$][\w$]*)\b", piece)
            direct = re.match(r"([A-Za-z_$][\w$]*)", piece)
            exports.append(alias.group(1) if alias else direct.group(1) if direct else piece)
    for match in re.finditer(r"\bexport\s+(?:default\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)", text):
        exports.append(match.group(1))
    if re.search(r"\bexport\s+default\b", text):
        exports.append("default")
    deduped: list[str] = []
    for item in exports:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def _dedupe_logical_path(logical_path: str, used: set[str]) -> str:
    if logical_path not in used:
        used.add(logical_path)
        return logical_path
    path = PurePosixPath(logical_path)
    suffix = "".join(path.suffixes)
    stem = path.name[: -len(suffix)] if suffix else path.name
    for index in range(2, 1000):
        candidate = str(path.with_name(f"{stem}_{index}{suffix}"))
        if candidate not in used:
            used.add(candidate)
            return candidate
    candidate = str(path.with_name(f"{stem}_{len(used)}{suffix}"))
    used.add(candidate)
    return candidate


def _clean_logical_asset_path(logical_path: str) -> str:
    path = PurePosixPath(logical_path.replace("\\", "/"))
    name = path.name
    suffixes = "".join(path.suffixes[-2:]) if name.endswith((".min.js", ".min.css", ".js.map", ".css.map")) else path.suffix
    stem = name[: -len(suffixes)] if suffixes else path.stem
    cleaned_stem = re.sub(r"([._-])([A-Za-z0-9_]{6,})$", _drop_hash_suffix, stem)
    if cleaned_stem == stem:
        cleaned_stem = re.sub(r"([._-])([0-9a-fA-F]{6,})$", "", stem)
    cleaned_name = (cleaned_stem or stem) + suffixes
    parent = path.parent.as_posix()
    return f"{parent}/{cleaned_name}" if parent and parent != "." else cleaned_name


def _drop_hash_suffix(match: re.Match[str]) -> str:
    token = match.group(2)
    if len(token) < 6:
        return match.group(0)
    has_alpha = any(character.isalpha() for character in token)
    has_digit = any(character.isdigit() for character in token)
    if has_alpha and has_digit:
        return ""
    has_lower = any(character.islower() for character in token)
    has_upper = any(character.isupper() for character in token)
    if "_" in token or (has_lower and has_upper):
        return ""
    if re.fullmatch(r"[0-9a-fA-F]{6,}", token):
        return ""
    return match.group(0)


def _unique_output_path(destination: Path) -> Path:
    if not destination.exists():
        return destination
    stem = destination.stem
    suffix = destination.suffix
    for index in range(2, 1000):
        candidate = destination.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    return destination.with_name(f"{stem}_{id(destination)}{suffix}")


def _asset_kind(suffix: str) -> str:
    if suffix in {".js", ".mjs", ".cjs"}:
        return "javascript_bundle_chunk"
    if suffix == ".css":
        return "stylesheet_bundle"
    if suffix == ".html":
        return "html_entrypoint"
    if suffix == ".json":
        return "json_manifest_or_data"
    if suffix == ".svg":
        return "svg_asset"
    return "text_asset"


def _reconstruction_header(logical_path: str, suffix: str, lift_metadata: dict[str, object] | None = None) -> str:
    lift_metadata = lift_metadata or {}
    features = ", ".join(str(item) for item in lift_metadata.get("features", []) or [])
    source_grade = " * Source-lift features: " + (features or "none") + "\n"
    if suffix in {".js", ".mjs", ".cjs", ".css"}:
        return (
            "/*\n"
            " * RE-Pro bundled asset reconstruction.\n"
            f" * Original bundled asset: {logical_path}\n"
            " * Source maps were not present; this is formatted shipped bundle code, not original source.\n"
            f"{source_grade}"
            " */\n"
        )
    if suffix in {".html", ".xml", ".svg"}:
        return (
            "<!--\n"
            "  RE-Pro bundled asset reconstruction.\n"
            f"  Original bundled asset: {logical_path}\n"
            "  Source maps were not present; this is formatted shipped bundle content, not original source.\n"
            f"  Source-lift features: {features or 'none'}\n"
            "-->\n"
        )
    if suffix == ".json":
        return ""
    return (
        "# RE-Pro bundled asset reconstruction\n"
        f"# Original bundled asset: {logical_path}\n"
        "# Source maps were not present; this is formatted shipped bundle content, not original source.\n"
        f"# Source-lift features: {features or 'none'}\n"
    )


def _reconstitute_text_asset(text: str, suffix: str) -> str:
    if suffix == ".json":
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n"
        except ValueError:
            return text if text.endswith("\n") else text + "\n"
    if suffix in CODE_ASSET_EXTENSIONS and _looks_minified(text):
        return _basic_code_beautify(text)
    return text if text.endswith("\n") else text + "\n"


def _source_lift_text_asset(
    text: str,
    suffix: str,
    original_logical_path: str,
    cleaned_logical_path: str,
    logical_paths: dict[str, str],
    module_graph: dict[str, object],
) -> tuple[str, dict[str, object]]:
    features: list[str] = []
    lifted = text
    lifted, rewritten_count = _rewrite_bundle_references(lifted, original_logical_path, cleaned_logical_path, logical_paths)
    if rewritten_count:
        features.append(f"rewrote_{rewritten_count}_hashed_references")
    if suffix in {".js", ".mjs", ".cjs"}:
        lifted, js_features = _lift_javascript_bundle(lifted, cleaned_logical_path, module_graph)
        features.extend(js_features)
    elif suffix == ".css":
        lifted, css_features = _lift_css_bundle(lifted)
        features.extend(css_features)
    return lifted, {"features": features, "inferred_module": _module_name_from_path(cleaned_logical_path)}


def _rewrite_bundle_references(
    text: str,
    original_logical_path: str,
    cleaned_logical_path: str,
    logical_paths: dict[str, str],
) -> tuple[str, int]:
    rewritten = 0

    def replace_reference(match: re.Match[str]) -> str:
        nonlocal rewritten
        quote = match.group("quote")
        reference = match.group("ref")
        replacement = _rewrite_single_reference(reference, original_logical_path, cleaned_logical_path, logical_paths)
        if replacement == reference:
            return match.group(0)
        rewritten += 1
        return f"{match.group('prefix')}{quote}{replacement}{quote}"

    patterns = [
        re.compile(r"(?P<prefix>\bfrom\s*)(?P<quote>[\"'`])(?P<ref>[^\"'`]+)(?P=quote)"),
        re.compile(r"(?P<prefix>\bfrom)(?P<quote>[\"'`])(?P<ref>[^\"'`]+)(?P=quote)"),
        re.compile(r"(?P<prefix>\bimport\s*\(\s*)(?P<quote>[\"'`])(?P<ref>[^\"'`]+)(?P=quote)"),
        re.compile(r"(?P<prefix>\bimport\s*)(?P<quote>[\"'`])(?P<ref>[^\"'`]+)(?P=quote)"),
    ]
    for pattern in patterns:
        text = pattern.sub(replace_reference, text)

    def replace_source_map(match: re.Match[str]) -> str:
        nonlocal rewritten
        reference = match.group("ref").strip()
        replacement = _rewrite_single_reference(reference, original_logical_path, cleaned_logical_path, logical_paths)
        if replacement == reference:
            replacement = _clean_logical_asset_path(reference)
        if replacement != reference:
            rewritten += 1
        return f"sourceMappingURL={replacement}"

    text = re.sub(r"sourceMappingURL=(?P<ref>[^\s*]+)", replace_source_map, text)
    return text, rewritten


def _rewrite_single_reference(
    reference: str,
    original_logical_path: str,
    cleaned_logical_path: str,
    logical_paths: dict[str, str],
) -> str:
    if not reference or reference.startswith(("data:", "http:", "https:", "node:", "#")):
        return reference
    original_parent = PurePosixPath(original_logical_path).parent
    cleaned_parent = PurePosixPath(cleaned_logical_path).parent
    target_original = _resolve_posix_reference(original_parent, reference)
    target_cleaned = logical_paths.get(target_original)
    if target_cleaned is None:
        normalized_reference = reference[2:] if reference.startswith("./") else reference
        target_cleaned = logical_paths.get(normalized_reference)
    if target_cleaned is None:
        cleaned_reference = _clean_logical_asset_path(reference)
        if reference.startswith("./") and not cleaned_reference.startswith((".", "/")):
            cleaned_reference = f"./{cleaned_reference}"
        return cleaned_reference if cleaned_reference != reference else reference
    return _relative_posix_reference(cleaned_parent, PurePosixPath(target_cleaned))

