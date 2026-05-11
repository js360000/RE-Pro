"""Pure leaf helpers for frontend reconstruction.

These functions have no internal dependencies — they're the safe base of
the reconstruction package's import graph.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath


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
