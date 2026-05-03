from __future__ import annotations

import re
from pathlib import Path

from .utils import ensure_dir, safe_output_path


SOURCE_PATH_PATTERN = re.compile(
    r"([A-Za-z]:[\\/][^\r\n\t\"'<>|?*]+\.(?:cpp|cxx|cc|c|hpp|hxx|hh|h|inl))"
    r"|((?:[\w.\-]+/)+[\w.\-]+\.(?:cpp|cxx|cc|c|hpp|hxx|hh|h|inl))",
    re.IGNORECASE,
)
QUALIFIED_SYMBOL_PATTERN = re.compile(r"~?[A-Za-z_]\w*(?:::\~?[A-Za-z_]\w*)+")
CALLABLE_NAME_PATTERN = re.compile(r"\b(~?[A-Za-z_]\w*)\s*\(")
IGNORE_CALLABLE_NAMES = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
}


def extract_source_file_hints(text: str) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()
    for match in SOURCE_PATH_PATTERN.finditer(text or ""):
        value = match.group(1) or match.group(2) or ""
        normalized = value.replace("\\", "/").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        hints.append(normalized)
    return hints


def extract_symbol_names(text: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for match in QUALIFIED_SYMBOL_PATTERN.finditer(text or ""):
        value = match.group(0).strip()
        if value and value not in seen:
            seen.add(value)
            names.append(value)
    for match in CALLABLE_NAME_PATTERN.finditer(text or ""):
        value = match.group(1).strip()
        lowered = value.lower()
        if not value or lowered in IGNORE_CALLABLE_NAMES or value in seen:
            continue
        seen.add(value)
        names.append(value)
    return names


def synthesize_symbolic_source_tree(
    output_dir: Path,
    *,
    origin_label: str,
    source_paths: list[str] | None = None,
    function_names: list[str] | None = None,
    max_files: int = 96,
) -> list[tuple[str, str]]:
    ensure_dir(output_dir)
    normalized_paths = _unique_paths(source_paths or [])
    normalized_functions = _unique_symbols(function_names or [])
    generated: list[tuple[str, str]] = []

    if normalized_paths:
        by_path = _associate_symbols_to_paths(normalized_paths, normalized_functions)
        for original_path, symbols in list(by_path.items())[:max_files]:
            destination = safe_output_path(output_dir, original_path)
            ensure_dir(destination.parent)
            destination.write_text(_render_source_hint_file(original_path, symbols, origin_label), encoding="utf-8")
            generated.append((original_path, str(destination)))
        return generated

    class_groups, globals_group = _group_symbolic_functions(normalized_functions)
    written = 0
    for class_key, methods in class_groups.items():
        if written >= max_files:
            break
        header_rel, source_rel = _class_relative_paths(class_key)
        header_path = safe_output_path(output_dir, header_rel)
        source_path = safe_output_path(output_dir, source_rel)
        ensure_dir(header_path.parent)
        header_path.write_text(_render_class_header(class_key, methods, origin_label), encoding="utf-8")
        source_path.write_text(_render_class_source(class_key, methods, header_path.name, origin_label), encoding="utf-8")
        generated.append((header_rel, str(header_path)))
        generated.append((source_rel, str(source_path)))
        written += 2
    if globals_group and written < max_files:
        relative_path = "symbols/globals.cpp"
        destination = safe_output_path(output_dir, relative_path)
        ensure_dir(destination.parent)
        destination.write_text(_render_globals_source(globals_group, origin_label), encoding="utf-8")
        generated.append((relative_path, str(destination)))
    return generated


def _unique_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for path in paths:
        normalized = str(path or "").replace("\\", "/").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _unique_symbols(symbols: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for symbol in symbols:
        normalized = str(symbol or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _associate_symbols_to_paths(paths: list[str], function_names: list[str]) -> dict[str, list[str]]:
    by_path = {path: [] for path in paths}
    for function_name in function_names:
        lowered = function_name.lower()
        matched = False
        for path in paths:
            stem = Path(path).stem.lower()
            if stem and stem in lowered:
                by_path[path].append(function_name)
                matched = True
        if not matched and paths:
            by_path[paths[0]].append(function_name)
    return by_path


def _group_symbolic_functions(function_names: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    classes: dict[str, list[str]] = {}
    globals_group: list[str] = []
    for function_name in function_names:
        parts = [part for part in function_name.split("::") if part]
        if len(parts) >= 2:
            class_key = "::".join(parts[:-1])
            classes.setdefault(class_key, []).append(parts[-1])
        else:
            globals_group.append(function_name)
    return classes, globals_group


def _class_relative_paths(class_key: str) -> tuple[str, str]:
    parts = [part for part in class_key.split("::") if part]
    class_name = parts[-1] if parts else "RecoveredClass"
    namespace_parts = parts[:-1]
    prefix = "/".join(["symbols", *namespace_parts]) if namespace_parts else "symbols"
    return f"{prefix}/{class_name}.hpp", f"{prefix}/{class_name}.cpp"


def _render_source_hint_file(original_path: str, symbols: list[str], origin_label: str) -> str:
    lines = [
        f"// Source path recovered from {origin_label}.",
        f"// Original path hint: {original_path}",
    ]
    if symbols:
        lines.extend(["// Related symbols:", *[f"//   - {symbol}" for symbol in symbols[:128]]])
    suffix = Path(original_path).suffix.lower()
    if suffix in {".h", ".hh", ".hpp", ".hxx", ".inl"}:
        lines.extend(["", "#pragma once", "", "// Original declarations were not embedded; symbol evidence follows above."])
    else:
        lines.extend(["", "// Original function bodies were not embedded; symbol evidence follows above."])
    lines.append("")
    return "\n".join(lines)


def _render_class_header(class_key: str, methods: list[str], origin_label: str) -> str:
    parts = [part for part in class_key.split("::") if part]
    class_name = parts[-1] if parts else "RecoveredClass"
    namespace_parts = parts[:-1]
    lines = [
        "#pragma once",
        "",
        f"// Class skeleton synthesized from {origin_label}.",
    ]
    for namespace_name in namespace_parts:
        lines.extend(["", f"namespace {namespace_name} {{"])
    lines.extend(["", f"class {class_name} {{", "public:"])
    for method_name in methods[:256]:
        if method_name == class_name or method_name == f"~{class_name}":
            lines.append(f"    {method_name}();")
        else:
            lines.append(f"    void {method_name}();")
    lines.append("};")
    for namespace_name in reversed(namespace_parts):
        lines.append(f"}} // namespace {namespace_name}")
    lines.append("")
    return "\n".join(lines)


def _render_class_source(class_key: str, methods: list[str], header_name: str, origin_label: str) -> str:
    parts = [part for part in class_key.split("::") if part]
    class_name = parts[-1] if parts else "RecoveredClass"
    namespace_parts = parts[:-1]
    lines = [
        f'#include "{header_name}"',
        "",
        f"// Class skeleton synthesized from {origin_label}.",
    ]
    for namespace_name in namespace_parts:
        lines.extend(["", f"namespace {namespace_name} {{"])
    for method_name in methods[:256]:
        if method_name == class_name or method_name == f"~{class_name}":
            signature = f"{class_name}::{method_name}()"
        else:
            signature = f"void {class_name}::{method_name}()"
        lines.extend(
            [
                "",
                f"{signature} {{",
                "    // TODO: recover original body from decompiler or debug line data.",
                "}",
            ]
        )
    for namespace_name in reversed(namespace_parts):
        lines.extend(["", f"}} // namespace {namespace_name}"])
    lines.append("")
    return "\n".join(lines)


def _render_globals_source(function_names: list[str], origin_label: str) -> str:
    lines = [
        f"// Global function skeletons synthesized from {origin_label}.",
    ]
    for function_name in function_names[:512]:
        lines.extend(
            [
                "",
                f"void {function_name}() {{",
                "    // TODO: recover original body from decompiler or debug line data.",
                "}",
            ]
        )
    lines.append("")
    return "\n".join(lines)
