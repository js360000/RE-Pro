from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .llm_auth import build_openai_client_for_settings
from .llm_auth import llm_auth_available
from .llm_auth import llm_auth_missing_message
from .utils import ensure_dir, safe_output_path


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


def _resolve_posix_reference(parent: PurePosixPath, reference: str) -> str:
    if reference.startswith("/"):
        return reference.lstrip("/")
    parts: list[str] = []
    for part in (*parent.parts, *PurePosixPath(reference).parts):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _relative_posix_reference(from_parent: PurePosixPath, target: PurePosixPath) -> str:
    from_parts = [] if str(from_parent) in {"", "."} else list(from_parent.parts)
    target_parts = list(target.parts)
    common = 0
    while common < len(from_parts) and common < len(target_parts) and from_parts[common] == target_parts[common]:
        common += 1
    relative_parts = [".."] * (len(from_parts) - common) + target_parts[common:]
    result = "/".join(relative_parts) if relative_parts else target.name
    if not result.startswith("."):
        result = f"./{result}"
    return result


def _lift_javascript_bundle(text: str, cleaned_logical_path: str, module_graph: dict[str, object]) -> tuple[str, list[str]]:
    features: list[str] = []
    inferred_name = _infer_export_symbol_name(cleaned_logical_path, text)
    text, graph_features = _apply_module_graph_names(text, cleaned_logical_path, module_graph)
    features.extend(graph_features)
    text, semantic_import_features = _apply_import_semantics(text)
    features.extend(semantic_import_features)
    text, jsx_runtime_features = _normalize_jsx_runtime(text)
    features.extend(jsx_runtime_features)
    text, cache_features = _normalize_react_compiler_cache(text)
    features.extend(cache_features)
    text, jsx_features = _rehydrate_simple_jsx(text)
    features.extend(jsx_features)
    if inferred_name:
        text, rename_features = _rename_primary_export(text, inferred_name)
        features.extend(rename_features)
        text, prop_features = _expand_component_props(text, inferred_name)
        features.extend(prop_features)
    text, import_features = _annotate_inferred_imports(text)
    features.extend(import_features)
    text = _normalize_export_spacing(text)
    return text, features


def _apply_module_graph_names(text: str, cleaned_logical_path: str, module_graph: dict[str, object]) -> tuple[str, list[str]]:
    nodes = module_graph.get("nodes") if isinstance(module_graph, dict) else {}
    if not isinstance(nodes, dict):
        return text, []
    features: list[str] = []
    component_renames: list[tuple[str, str, str]] = []

    def rewrite_import(match: re.Match[str]) -> str:
        body = match.group("body")
        reference = match.group("module")
        if not reference.startswith("."):
            return match.group(0)
        target = _resolve_posix_reference(PurePosixPath(cleaned_logical_path).parent, reference)
        node = nodes.get(target)
        if not isinstance(node, dict):
            return match.group(0)
        inferred_module = str(node.get("inferred_module") or "").lower()
        if inferred_module in {"jsxruntime", "logger", "clsx", "classnames", "cn"}:
            return match.group(0)
        primary_export = str(node.get("primary_export") or "").strip()
        if not primary_export or not re.match(r"^[A-Za-z_$][\w$]*$", primary_export):
            return match.group(0)
        local_name = _single_import_local_name(body)
        if not local_name or local_name == primary_export or len(local_name) > 2:
            return match.group(0)
        if _import_local_used_as_jsx_component(text, local_name):
            primary_export = _pascal_case(str(node.get("inferred_module") or primary_export))
            if not primary_export or not re.match(r"^[A-Za-z_$][\w$]*$", primary_export):
                return match.group(0)
            component_renames.append((local_name, primary_export, str(node.get("inferred_module") or primary_export)))
        new_body = _replace_import_local_name(body, local_name, primary_export)
        features.append(f"graph_renamed_import_{local_name}_to_{primary_export}")
        return match.group(0)[: match.start("body") - match.start(0)] + new_body + match.group(0)[match.end("body") - match.start(0) :]

    text = re.sub(r"import\s*\{(?P<body>.*?)\}\s*from\s*[\"'`](?P<module>[^\"'`]+)[\"'`]\s*;", rewrite_import, text, flags=re.DOTALL)
    for local_name, semantic_name, module_name in component_renames:
        text = _rewrite_semantic_import_usages(text, local_name, semantic_name, module_name)
    return text, features


def _import_local_used_as_jsx_component(text: str, local_name: str) -> bool:
    return bool(
        re.search(rf"(?:jsx|jsxs)\s*\)?\s*\(\s*{re.escape(local_name)}\s*,", text)
        or re.search(rf"\b[a-zA-Z_$][\w$]*\.(?:jsx|jsxs)\s*\(\s*{re.escape(local_name)}\s*,", text)
        or re.search(rf"\b[A-Za-z_$][\w$]*\.(?:jsx|jsxs)\)\s*\(\s*{re.escape(local_name)}\s*,", text)
    )


def _apply_import_semantics(text: str) -> tuple[str, list[str]]:
    features: list[str] = []
    renames: list[tuple[str, str, str]] = []

    def rewrite_import(match: re.Match[str]) -> str:
        module_name = _module_name_from_path(match.group("module"))
        body = match.group("body")
        semantic_name = _semantic_import_name(module_name, body, text)
        if not semantic_name:
            return match.group(0)
        local_name = _single_import_local_name(body)
        if not local_name or local_name == semantic_name:
            return match.group(0)
        new_body = _replace_import_local_name(body, local_name, semantic_name)
        renames.append((local_name, semantic_name, module_name))
        return match.group(0)[: match.start("body") - match.start(0)] + new_body + match.group(0)[match.end("body") - match.start(0) :]

    text = re.sub(r"import\s*\{(?P<body>.*?)\}\s*from\s*[\"'`](?P<module>[^\"'`]+)[\"'`]\s*;", rewrite_import, text, flags=re.DOTALL)
    for local_name, semantic_name, module_name in renames:
        text = _rewrite_semantic_import_usages(text, local_name, semantic_name, module_name)
        features.append(f"renamed_import_{local_name}_to_{semantic_name}")
    return text, features


def _semantic_import_name(module_name: str, body: str, text: str) -> str:
    local_name = _single_import_local_name(body)
    if not local_name or len(local_name) > 2:
        return ""
    lower_module = module_name.lower()
    if lower_module in {"clsx", "classnames", "cn"}:
        return "clsx"
    if lower_module in {"jsxruntime", "jsxRuntime".lower()} or "jsx-runtime" in lower_module:
        return "createJsxRuntime"
    if lower_module == "logger":
        return "createLogger"
    if _import_local_used_as_jsx_component(text, local_name):
        return _pascal_case(module_name)
    return ""


def _single_import_local_name(body: str) -> str:
    body = " ".join(body.split()).strip()
    if not body:
        return ""
    if "," in body:
        return ""
    alias_match = re.search(r"\b[A-Za-z_$][\w$]*\s+as\s+([A-Za-z_$][\w$]*)\b", body)
    if alias_match:
        return alias_match.group(1)
    direct_match = re.fullmatch(r"([A-Za-z_$][\w$]*)", body)
    return direct_match.group(1) if direct_match else ""


def _replace_import_local_name(body: str, local_name: str, semantic_name: str) -> str:
    if re.search(r"\bas\b", body):
        return re.sub(rf"\bas\s+{re.escape(local_name)}\b", f"as {semantic_name}", body, count=1)
    return re.sub(rf"\b{re.escape(local_name)}\b", f"{local_name} as {semantic_name}", body, count=1)


def _rewrite_semantic_import_usages(text: str, local_name: str, semantic_name: str, module_name: str) -> str:
    if semantic_name == "clsx":
        text = re.sub(rf"\b{re.escape(local_name)}\s*\(", f"{semantic_name}(", text)
    elif semantic_name == "createLogger":
        logger_holder = ""

        def replace_logger_factory(match: re.Match[str]) -> str:
            nonlocal logger_holder
            logger_holder = match.group(1)
            return f"const logger = {semantic_name}();\nvar "

        text, count = re.subn(
            rf"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*{re.escape(local_name)}\(\)\s*,",
            replace_logger_factory,
            text,
            count=1,
        )
        if not count:
            text, count = re.subn(rf"\b([A-Za-z_$][\w$]*)\s*=\s*{re.escape(local_name)}\(\)", rf"logger = {semantic_name}()", text, count=1)
        if logger_holder:
            text = re.sub(rf"\b{re.escape(logger_holder)}\.c\b", "logger.c", text)
    elif semantic_name == "createJsxRuntime":
        text = re.sub(rf"\b{re.escape(local_name)}\(\)", f"{semantic_name}()", text)
    elif semantic_name == _pascal_case(module_name):
        text = re.sub(
            rf"(\(0,\s*[A-Za-z_$][\w$]*\.(?:jsx|jsxs)\)\s*\(\s*){re.escape(local_name)}(\s*,)",
            rf"\1{semantic_name}\2",
            text,
        )
        text = re.sub(
            rf"(\b[A-Za-z_$][\w$]*\.(?:jsx|jsxs)\s*\(\s*){re.escape(local_name)}(\s*,)",
            rf"\1{semantic_name}\2",
            text,
        )
    return text


def _lift_css_bundle(text: str) -> tuple[str, list[str]]:
    features: list[str] = []
    if "@tailwind" in text or re.search(r"\b(?:text|bg|border|flex|grid|rounded|gap|px|py)-", text):
        features.append("preserved_tailwind_semantics")
    return text, features


def _normalize_jsx_runtime(text: str) -> tuple[str, list[str]]:
    features: list[str] = []
    runtime_var = None
    match = re.search(r"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\(\)\s*;", text)
    if match and re.search(rf"\(0,\s*{re.escape(match.group(1))}\.(?:jsx|jsxs)\)", text):
        runtime_var = match.group(1)
    if runtime_var:
        text = re.sub(rf"\bvar\s+{re.escape(runtime_var)}\s*=", "const jsxRuntime = ", text, count=1)
        text = re.sub(rf"\(0,\s*{re.escape(runtime_var)}\.(jsx|jsxs|Fragment)\)", r"jsxRuntime.\1", text)
        features.append("normalized_jsx_runtime_alias")
    text = re.sub(r"\(0,\s*([A-Za-z_$][\w$]*)\.(jsx|jsxs|Fragment)\)", r"\1.\2", text)
    text = re.sub(r"\breturn(?=jsxRuntime\.)", "return ", text)
    return text, features


def _normalize_react_compiler_cache(text: str) -> tuple[str, list[str]]:
    match = re.search(r"\blet\s+([A-Za-z_$][\w$]*)\s*=\s*\(0,\s*([A-Za-z_$][\w$]*)\.c\)\((\d+)\)", text)
    if not match:
        return text, []
    cache_var = match.group(1)
    text = re.sub(rf"\blet\s+{re.escape(cache_var)}\s*=", "let reactCompilerCache = ", text, count=1)
    text = re.sub(rf"\b{re.escape(cache_var)}\[(\d+)\]", r"reactCompilerCache[\1]", text)
    text = re.sub(
        r"Symbol\.for\(`react\.early_return_sentinel`\)",
        "REACT_EARLY_RETURN_SENTINEL",
        text,
    )
    if "REACT_EARLY_RETURN_SENTINEL" in text and "const REACT_EARLY_RETURN_SENTINEL" not in text:
        text = _insert_after_import_block(text, "const REACT_EARLY_RETURN_SENTINEL = Symbol.for(`react.early_return_sentinel`);")
    return text, ["normalized_react_compiler_cache_slots"]


def _insert_after_import_block(text: str, statement: str) -> str:
    position = 0
    while True:
        match = re.match(r"\s*import\b[\s\S]*?;\s*", text[position:])
        if not match:
            break
        position += match.end()
    return text[:position] + statement + "\n" + text[position:]


def _rehydrate_simple_jsx(text: str) -> tuple[str, list[str]]:
    features: list[str] = []
    before = text
    text = re.sub(
        r"jsxRuntime\.jsx\(`(?P<tag>[A-Za-z][\w:-]*)`,\s*\{\s*children:\s*(?P<child>[A-Za-z_$][\w$]*)\s*\}\)",
        r"<\g<tag>>{\g<child>}</\g<tag>>",
        text,
    )
    text = re.sub(
        r"jsxRuntime\.jsx\(`(?P<tag>[A-Za-z][\w:-]*)`,\s*\{\s*className:\s*`(?P<class>[^`]+)`,\s*children:\s*(?P<child>[A-Za-z_$][\w$]*)\s*\}\)",
        r'<\g<tag> className="\g<class>">{\g<child>}</\g<tag>>',
        text,
    )
    text = re.sub(
        r"jsxRuntime\.jsx\((?P<component>[A-Z_][A-Za-z0-9_$]*),\s*\{\s*className:\s*(?P<class>[A-Za-z_$][\w$]*)\s*\}\)",
        r"<\g<component> className={\g<class>} />",
        text,
    )
    text = re.sub(
        r"jsxRuntime\.jsx\((?P<component>[A-Z_][A-Za-z0-9_$]*),\s*\{\s*\}\)",
        r"<\g<component> />",
        text,
    )
    if text != before:
        features.append("rehydrated_simple_jsx_calls")
    return text, features


def _rename_primary_export(text: str, inferred_name: str) -> tuple[str, list[str]]:
    function_match = re.search(r"\bfunction\s+([a-z_$][\w$]{0,2})\s*\(", text)
    if not function_match:
        return text, []
    old_name = function_match.group(1)
    if old_name == inferred_name:
        return text, []
    text = re.sub(rf"\bfunction\s+{re.escape(old_name)}\s*\(", f"function {inferred_name}(", text, count=1)
    text = re.sub(rf"export\s*\{{\s*{re.escape(old_name)}\s+as\s+([^}}]+)\}};", f"export {{ {inferred_name} as \\1 }};", text)
    text = re.sub(rf"export\s*\{{\s*{re.escape(old_name)}\s*\}};", f"export {{ {inferred_name} }};", text)
    return text, [f"renamed_primary_export_{old_name}_to_{inferred_name}"]


def _expand_component_props(text: str, component_name: str) -> tuple[str, list[str]]:
    match = re.search(rf"\bfunction\s+{re.escape(component_name)}\((?P<param>[A-Za-z_$][\w$]*)\)\{{", text)
    if not match:
        return text, []
    param_name = match.group("param")
    body_start = match.end()
    search_window = text[body_start : body_start + 3000]
    destructure_match = re.search(r"\{(?P<body>[^{}]{10,2000})\}\s*=\s*" + re.escape(param_name), search_window, flags=re.DOTALL)
    if not destructure_match:
        return text, []
    destructure_body = destructure_match.group("body")
    alias_pairs = _component_prop_alias_pairs(destructure_body)
    if not alias_pairs:
        return text, []
    absolute_body_start = body_start + destructure_match.start("body")
    absolute_body_end = body_start + destructure_match.end("body")
    before = text[:body_start]
    function_body = text[body_start:]
    before = re.sub(rf"\bfunction\s+{re.escape(component_name)}\({re.escape(param_name)}\)", f"function {component_name}(props)", before, count=1)
    function_body = re.sub(rf"=\s*{re.escape(param_name)}\b", "=props", function_body, count=1)
    destructure_body_updated = text[absolute_body_start:absolute_body_end]
    for prop_name, local_name in alias_pairs:
        destructure_body_updated = re.sub(rf"\b{re.escape(prop_name)}\s*:\s*{re.escape(local_name)}\b", prop_name, destructure_body_updated)
    function_body = (
        function_body[: absolute_body_start - body_start]
        + destructure_body_updated
        + function_body[absolute_body_end - body_start :]
    )
    destructure_end_in_body = (absolute_body_start - body_start) + len(destructure_body_updated)
    prefix = function_body[:destructure_end_in_body]
    suffix = function_body[destructure_end_in_body:]
    for prop_name, local_name in alias_pairs:
        suffix = _replace_identifier_outside_literals(suffix, local_name, prop_name)
    return before + prefix + suffix, [f"expanded_{len(alias_pairs)}_component_props"]


def _component_prop_alias_pairs(destructure_body: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen_locals: set[str] = set()
    for prop_name, local_name in re.findall(r"\b([A-Za-z_$][\w$]{2,})\s*:\s*([A-Za-z_$][\w$]{0,2})\b", destructure_body):
        if prop_name in seen_locals or local_name in seen_locals:
            continue
        if prop_name in {"let", "var", "const", "return"}:
            continue
        pairs.append((prop_name, local_name))
        seen_locals.add(local_name)
    return pairs[:40]


def _replace_identifier_outside_literals(text: str, old_name: str, new_name: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            i += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
            i += 1
            continue
        if char == "/" and nxt == "/":
            end = text.find("\n", i)
            if end == -1:
                output.append(text[i:])
                break
            output.append(text[i:end])
            i = end
            continue
        if char == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                output.append(text[i:])
                break
            output.append(text[i : end + 2])
            i = end + 2
            continue
        if text.startswith(old_name, i) and _identifier_boundary(text, i - 1) and _identifier_boundary(text, i + len(old_name)):
            output.append(new_name)
            i += len(old_name)
            continue
        output.append(char)
        i += 1
    return "".join(output)


def _identifier_boundary(text: str, index: int) -> bool:
    if index < 0 or index >= len(text):
        return True
    return not (text[index].isalnum() or text[index] in {"_", "$"})


def _annotate_inferred_imports(text: str) -> tuple[str, list[str]]:
    hints: list[str] = []
    for match in re.finditer(r"import\s*\{(?P<body>.*?)\}\s*from\s*[\"'`](?P<module>[^\"'`]+)[\"'`]\s*;", text, flags=re.DOTALL):
        module_name = _module_name_from_path(match.group("module"))
        body = " ".join(match.group("body").split())
        for imported, local in re.findall(r"\b([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)\b", body):
            if len(local) <= 2:
                hints.append(f"{local} likely {module_name}.{imported}")
    if not hints:
        return text, []
    comment = "// RE-Pro inferred minifier aliases: " + "; ".join(hints[:12]) + "\n"
    return comment + text, ["annotated_minifier_import_aliases"]


def _normalize_export_spacing(text: str) -> str:
    text = re.sub(r"export\{\s*", "export { ", text)
    text = re.sub(r"export\s*\{\s*([^}\n]+?)\s*\n?\s*\};", lambda match: "export { " + " ".join(match.group(1).split()) + " };\n", text)
    return text


def _optional_ast_format_and_validate(text: str, logical_path: str) -> tuple[str, dict[str, object]]:
    if PurePosixPath(logical_path).suffix.lower() not in {".js", ".mjs", ".cjs"}:
        return text, {"available": False, "reason": "not_javascript"}
    if len(text) > 1_500_000:
        return text, {"available": False, "reason": "file_too_large"}
    script_path = _frontend_ast_script_path()
    node_path = shutil.which("node")
    if not script_path.exists() or not node_path:
        return text, {"available": False, "reason": "babel_ast_tool_unavailable"}
    try:
        completed = subprocess.run(
            [node_path, str(script_path)],
            input=json.dumps({"filename": logical_path, "code": text}),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=6,
            cwd=str(script_path.parent),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return text, {"available": True, "ok": False, "error": str(exc)}
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return text, {"available": True, "ok": False, "error": (completed.stderr or completed.stdout or "invalid_ast_output")[:1000]}
    if not payload.get("ok"):
        return text, {
            "available": True,
            "ok": False,
            "error": str(payload.get("error") or "parse_failed")[:1000],
        }
    formatted = str(payload.get("formatted") or "")
    errors = payload.get("errors") or []
    if formatted and not errors:
        return formatted, {
            "available": True,
            "ok": True,
            "formatted": True,
            "summary": payload.get("summary") or {},
            "errors": [],
        }
    return text, {
        "available": True,
        "ok": not bool(errors),
        "formatted": False,
        "summary": payload.get("summary") or {},
        "errors": errors[:8],
    }


def _frontend_ast_script_path() -> Path:
    return Path(__file__).resolve().parents[2] / "tools" / "frontend-ast" / "repro_frontend_ast.mjs"


def _equivalence_checks(
    text: str,
    suffix: str,
    logical_path: str,
    logical_paths: dict[str, str],
    ast_metadata: dict[str, object],
) -> dict[str, object]:
    references = _extract_references_from_lifted_text(text, logical_path)
    known_targets = set(logical_paths.values())
    missing_imports = [reference for reference in references if reference.startswith(".") and _resolve_posix_reference(PurePosixPath(logical_path).parent, reference) not in known_targets]
    ast_summary = ast_metadata.get("summary") if isinstance(ast_metadata, dict) else {}
    return {
        "syntax_checked": bool(ast_metadata.get("available") and ast_metadata.get("ok")) if isinstance(ast_metadata, dict) else False,
        "syntax_errors": ast_metadata.get("errors", []) if isinstance(ast_metadata, dict) else [],
        "missing_relative_imports": missing_imports[:32],
        "imports": references[:128],
        "exports": (ast_summary or {}).get("exports", []) if isinstance(ast_summary, dict) else [],
        "functions": (ast_summary or {}).get("functions", []) if isinstance(ast_summary, dict) else [],
        "jsx_elements": (ast_summary or {}).get("jsx_elements", []) if isinstance(ast_summary, dict) else [],
        "extension": suffix,
    }


def _extract_references_from_lifted_text(text: str, logical_path: str) -> list[str]:
    del logical_path
    refs: list[str] = []
    for pattern in (r"\bfrom\s*[\"'`](?P<ref>[^\"'`]+)[\"'`]", r"\bimport\s*\(\s*[\"'`](?P<ref>[^\"'`]+)[\"'`]"):
        for match in re.finditer(pattern, text):
            reference = match.group("ref")
            if reference not in refs:
                refs.append(reference)
    return refs


def _should_attempt_ast(text: str, suffix: str, lift_metadata: dict[str, object]) -> bool:
    if suffix not in {".js", ".mjs", ".cjs"}:
        return False
    if len(text) > 900_000:
        return False
    features = [str(feature) for feature in lift_metadata.get("features", []) or []]
    if any(
        feature == "rehydrated_simple_jsx_calls"
        or feature == "normalized_react_compiler_cache_slots"
        or feature.startswith("expanded_")
        or feature.startswith("renamed_primary_export")
        or feature.startswith("renamed_import")
        or feature.startswith("graph_renamed_import")
        for feature in features
    ):
        return True
    return len(text) < 80_000 and any(token in text for token in ("export ", "import ", "jsxRuntime", "className"))


def _prepare_or_run_llm_source_grade(
    source_root: Path,
    manifest: list[dict[str, object]],
    *,
    llm_settings: object | None,
    llm_client_factory: Callable[[], Any] | None,
) -> dict[str, object]:
    llm_dir = ensure_dir(source_root / "SOURCE_GRADE_LLM")
    candidates = _select_llm_source_grade_candidates(manifest)
    requests: list[dict[str, object]] = []
    for index, entry in enumerate(candidates, start=1):
        restored_path = Path(str(entry.get("restored_path") or ""))
        try:
            code = restored_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        prompt = _build_source_grade_prompt(entry, code)
        request_path = llm_dir / f"{index:03d}_{safe_output_stem(restored_path)}.prompt.md"
        request_path.write_text(prompt, encoding="utf-8")
        requests.append({"source": str(restored_path), "prompt": str(request_path), "output": ""})
    enabled = bool(getattr(llm_settings, "enabled", False))
    if not requests:
        return {"status": "no_candidates", "request_count": 0, "note": "No frontend files were strong enough candidates for source-grade LLM rewriting."}
    if not enabled:
        _write_llm_source_grade_manifest(llm_dir, requests, "prepared_disabled", "LLM source-grade prompts prepared; enable LLM to run rewrites.")
        return {
            "status": "prepared_disabled",
            "directory": str(llm_dir),
            "request_count": len(requests),
            "note": "LLM source-grade prompts prepared but not executed because LLM assistance is disabled.",
        }
    if not llm_auth_available(llm_settings) and llm_client_factory is None:
        message = llm_auth_missing_message(llm_settings)
        _write_llm_source_grade_manifest(llm_dir, requests, "prepared_missing_auth", message)
        return {
            "status": "prepared_missing_auth",
            "directory": str(llm_dir),
            "request_count": len(requests),
            "note": message,
        }
    try:
        client = llm_client_factory() if llm_client_factory else _default_openai_client(llm_settings)
        model = str(getattr(llm_settings, "model", "gpt-5.4"))
        max_output = min(int(getattr(llm_settings, "max_output_tokens", 128000) or 128000), 128000)
        for request in requests[: min(3, len(requests))]:
            prompt = Path(str(request["prompt"])).read_text(encoding="utf-8", errors="ignore")
            response = client.responses.create(
                model=model,
                instructions=(
                    "Rewrite the provided recovered bundled JavaScript into source-grade equivalent TypeScript/React where possible. "
                    "Preserve behavior, imports, exports, prop names, string literals, and control flow. Do not invent external dependencies. "
                    "If uncertain, keep the recovered logic and add concise comments."
                ),
                input=prompt,
                reasoning={"effort": str(getattr(llm_settings, "reasoning_effort", "medium"))},
                text={"verbosity": str(getattr(llm_settings, "verbosity", "medium"))},
                max_output_tokens=max_output,
            )
            output_text = _extract_response_text(response)
            output_path = llm_dir / (Path(str(request["prompt"])).stem + ".source-grade.tsx")
            output_path.write_text(output_text, encoding="utf-8")
            request["output"] = str(output_path)
        _write_llm_source_grade_manifest(llm_dir, requests, "completed", "LLM source-grade rewriting completed for selected candidates.")
        return {
            "status": "completed",
            "directory": str(llm_dir),
            "request_count": len(requests),
            "rewritten_count": len([item for item in requests if item.get("output")]),
            "note": "LLM source-grade rewriting completed for selected candidates.",
        }
    except Exception as exc:
        _write_llm_source_grade_manifest(llm_dir, requests, "failed", str(exc))
        return {
            "status": "failed",
            "directory": str(llm_dir),
            "request_count": len(requests),
            "error": str(exc),
            "note": "LLM source-grade rewriting failed; deterministic source-lift outputs remain available.",
        }


def _select_llm_source_grade_candidates(manifest: list[dict[str, object]]) -> list[dict[str, object]]:
    def score(entry: dict[str, object]) -> int:
        features = [str(item) for item in ((entry.get("source_lift") or {}).get("features") or [])]
        value = 0
        for feature in features:
            if feature.startswith("expanded_"):
                value += 5
            elif feature.startswith("renamed_primary_export"):
                value += 4
            elif feature.startswith("renamed_import") or feature.startswith("graph_renamed_import"):
                value += 3
            elif feature == "normalized_react_compiler_cache_slots":
                value += 3
            elif feature == "rehydrated_simple_jsx_calls":
                value += 2
            elif feature.startswith("rewrote_"):
                value += 1
        return value

    candidates = [
        entry
        for entry in manifest
        if str(entry.get("extension")) in {".js", ".mjs", ".cjs"} and score(entry) >= 5
    ]
    return sorted(candidates, key=score, reverse=True)[:8]


def _build_source_grade_prompt(entry: dict[str, object], code: str) -> str:
    return (
        "# RE-Pro Source-Grade Frontend Rewrite Request\n\n"
        f"Original bundled asset: `{entry.get('asset_path')}`\n"
        f"Cleaned path: `{entry.get('cleaned_path')}`\n"
        f"Detected source-lift metadata:\n```json\n{json.dumps(entry.get('source_lift') or {}, indent=2)}\n```\n\n"
        "Rewrite this into the closest source-grade equivalent while preserving behavior, exports, imports, JSX structure, strings, and prop semantics. "
        "Prefer TypeScript/React style if the recovered code is React-like. Do not invent missing APIs.\n\n"
        "```tsx\n"
        f"{code[:40000]}\n"
        "```\n"
    )


def _write_llm_source_grade_manifest(llm_dir: Path, requests: list[dict[str, object]], status: str, note: str) -> None:
    (llm_dir / "manifest.json").write_text(
        json.dumps({"status": status, "note": note, "requests": requests}, indent=2),
        encoding="utf-8",
    )


def safe_output_stem(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem)[:80] or "source"


def _default_openai_client(llm_settings: object) -> Any:
    return build_openai_client_for_settings(llm_settings)


def _extract_response_text(response: Any) -> str:
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    chunks: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            text = getattr(content, "text", None)
            if text:
                chunks.append(str(text))
    return "\n".join(chunks).strip() or "No source-grade rewrite text was returned."


def _infer_export_symbol_name(cleaned_logical_path: str, text: str) -> str:
    stem = PurePosixPath(cleaned_logical_path).name
    for suffix in (".min.js", ".js", ".mjs", ".cjs"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if not stem:
        return ""
    is_component_like = bool(re.search(r"\b(?:jsxRuntime\.)?jsx(?:s)?\(", text)) or "className" in text or "children" in text
    return _pascal_case(stem) if is_component_like else _camel_case(stem)


def _module_name_from_path(path: str) -> str:
    stem = PurePosixPath(path.replace("\\", "/")).name
    for suffix in (".min.js", ".js", ".mjs", ".cjs", ".css", ".json", ".map"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return _camel_case(stem) or stem


def _pascal_case(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in _identifier_parts(value)) or "RecoveredComponent"


def _camel_case(value: str) -> str:
    parts = _identifier_parts(value)
    if not parts:
        return ""
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _identifier_parts(value: str) -> list[str]:
    parts = re.split(r"[^A-Za-z0-9]+", value)
    return [part[:1].lower() + part[1:] for part in parts if part and not re.fullmatch(r"[0-9a-fA-F]{6,}", part)]


def _looks_minified(text: str) -> bool:
    if not text:
        return False
    sample = text[:200_000]
    lines = sample.splitlines() or [sample]
    longest = max((len(line) for line in lines), default=0)
    average = sum(len(line) for line in lines) / max(1, len(lines))
    dense_syntax = sum(sample.count(token) for token in (";", "{", "}", "=>"))
    if len(lines) <= 3 and len(sample) > 40 and dense_syntax >= 4:
        return True
    return longest > 500 or average > 220


def _basic_code_beautify(text: str) -> str:
    output: list[str] = []
    indent = 0
    quote: str | None = None
    escaped = False
    line_has_text = False
    pending_space = False
    i = 0

    def newline() -> None:
        nonlocal line_has_text, pending_space
        while output and output[-1] == " ":
            output.pop()
        if output and output[-1] != "\n":
            output.append("\n")
        output.append("  " * max(indent, 0))
        line_has_text = False
        pending_space = False

    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            i += 1
            continue

        if char in {"'", '"', "`"}:
            if pending_space and line_has_text:
                output.append(" ")
            pending_space = False
            quote = char
            output.append(char)
            line_has_text = True
            i += 1
            continue

        if char == "/" and nxt == "/":
            if line_has_text:
                output.append(" ")
            end = text.find("\n", i)
            if end == -1:
                output.append(text[i:])
                break
            output.append(text[i:end].rstrip())
            newline()
            i = end + 1
            continue

        if char == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            comment = text[i:] if end == -1 else text[i : end + 2]
            if line_has_text:
                output.append(" ")
            output.append(comment)
            line_has_text = True
            i = len(text) if end == -1 else end + 2
            continue

        if char.isspace():
            pending_space = line_has_text
            i += 1
            continue

        if char == "{":
            if pending_space and line_has_text:
                output.append(" ")
            output.append("{")
            indent += 1
            newline()
        elif char == "}":
            indent = max(0, indent - 1)
            if line_has_text:
                newline()
            output.append("}")
            line_has_text = True
            if nxt not in {";", ",", ")", "]", ""}:
                newline()
        elif char == ";":
            output.append(";")
            line_has_text = True
            newline()
        elif char == ",":
            output.append(",")
            line_has_text = True
            if _should_break_after_comma(text, i):
                newline()
            else:
                output.append(" ")
        else:
            if pending_space and line_has_text and _needs_space_before(char, output[-1] if output else ""):
                output.append(" ")
            output.append(char)
            line_has_text = True
        pending_space = False
        i += 1

    return re.sub(r"\n{3,}", "\n\n", "".join(output).rstrip()) + "\n"


def _needs_space_before(char: str, previous: str) -> bool:
    if not previous or previous in "\n([{./!~+-*=<>?:&|,%":
        return False
    if char in ")]}.,;:+-*/%=<>?:&|":
        return False
    return True


def _should_break_after_comma(text: str, index: int) -> bool:
    window = text[index : index + 160]
    return len(window) > 120 and any(token in window for token in ("=>", "function", "const ", "let ", "var ", "{", "["))
