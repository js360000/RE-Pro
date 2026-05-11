"""Pure text / parsing helpers used throughout MSVC class recovery.

These functions only depend on stdlib (``re``); they form the leaf layer
of the package's import graph and are imported by every other submodule
that needs to normalize addresses, identifiers, type strings, or parse
C++ signatures.
"""

from __future__ import annotations

import re

CALLING_CONVENTION_TOKENS = {
    "__cdecl",
    "__stdcall",
    "__fastcall",
    "__thiscall",
    "__vectorcall",
    "__usercall",
    "__golang",
}


def _parse_int_literal(value: object) -> int | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _normalize_address(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return f"0x{int(text, 16):x}"
    except ValueError:
        return ""


def _pascal_token(token: str) -> str:
    text = str(token or "").strip("_")
    if not text:
        return ""
    if len(text) == 1:
        return text.upper()
    if text.isupper():
        return text
    return text[:1].upper() + text[1:]


def _normalize_qualified_function_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("(", 1)[0].strip()
    if "scalar_deleting_destructor" in text:
        return "scalar_deleting_destructor"
    if "vector_deleting_destructor" in text:
        return "vector_deleting_destructor"
    text = text.strip("`' ")
    if "::" in text:
        return text.split("::")[-1].strip()
    return text


def _parse_signature(signature: str) -> dict[str, object]:
    text = signature.strip().rstrip(";")
    if "(" not in text or ")" not in text:
        return {"return_type": "void", "name": "", "params": []}
    before_paren, after_paren = text.split("(", 1)
    params_text = after_paren.rsplit(")", 1)[0].strip()
    pieces = before_paren.strip().split()
    if not pieces:
        return {"return_type": "void", "name": "", "params": _split_params(params_text)}
    name = pieces[-1]
    return_tokens = [token for token in pieces[:-1] if token not in CALLING_CONVENTION_TOKENS]
    return_type = " ".join(return_tokens).strip() or "void"
    return {"return_type": return_type, "name": name, "params": _split_params(params_text)}


def _split_params(params_text: str) -> list[str]:
    text = params_text.strip()
    if not text or text == "void":
        return []
    return [piece.strip() for piece in text.split(",") if piece.strip()]


def _split_param(piece: str, index: int) -> dict[str, str]:
    text = piece.strip()
    pieces = text.rsplit(" ", 1)
    if len(pieces) == 2:
        param_type = pieces[0].strip()
        raw_name = pieces[1].strip()
        pointer_prefix = ""
        while raw_name.startswith(("*", "&")):
            pointer_prefix += raw_name[0]
            raw_name = raw_name[1:]
        param_name = raw_name.strip()
        if pointer_prefix:
            param_type = f"{param_type} {pointer_prefix}".strip()
        if re.match(r"^[A-Za-z_]\w*$", param_name) and param_type:
            return {"type": param_type, "name": param_name}
    return {"type": text, "name": f"arg{index}"}


def _normalize_return_type(value: str) -> str:
    text = str(value or "").strip()
    return text or "void"


def _tokenize_identifier(value: str) -> list[str]:
    text = str(value or "").replace("::", "_")
    pieces = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", text)
    tokens = [piece.lower() for piece in pieces if piece]
    if not tokens and text:
        tokens = [text.lower()]
    return tokens


def _normalize_identifier_token(value: str) -> str:
    text = str(value or "").strip().lower().strip("_")
    return re.sub(r"[^a-z0-9]+", "", text)


def _class_names_match(left: str, right: str) -> bool:
    left_text = str(left or "").strip()
    right_text = str(right or "").strip()
    if not left_text or not right_text:
        return False
    if left_text == right_text:
        return True
    return left_text.split("::")[-1] == right_text.split("::")[-1]


