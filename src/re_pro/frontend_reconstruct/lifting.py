"""JS/CSS bundle lifting, AST validation, and LLM source-grade preparation.

This module owns the semantic transformation passes (import renaming, JSX
rehydration, component prop expansion, etc.) plus the optional Babel AST
formatter integration and the LLM source-grade scaffolding.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from ..llm_auth import build_openai_client_for_settings, llm_auth_available, llm_auth_missing_message
from ..utils import ensure_dir
from .helpers import (
    _infer_export_symbol_name,
    _module_name_from_path,
    _pascal_case,
    _resolve_posix_reference,
)


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


