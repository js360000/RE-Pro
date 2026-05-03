from __future__ import annotations

import copy
import re

GENERIC_NAME_PREFIXES = ("sub_", "fcn.", "fun_", "vf_", "thunk_", "lab_")
ANSI_PATH_APIS = {
    "createfilea",
    "deletefilea",
    "copyfilea",
    "movefilea",
    "movefileexa",
    "findfirstfilea",
    "getfileattributesa",
    "loadlibrarya",
    "setcurrentdirectorya",
    "fopen",
    "_fsopen",
}
WIDE_PATH_APIS = {
    "createfilew",
    "deletefilew",
    "copyfilew",
    "movefilew",
    "movefileexw",
    "findfirstfilew",
    "getfileattributesw",
    "loadlibraryw",
    "setcurrentdirectoryw",
    "_wfopen",
}
ANSI_STRING_APIS = {
    "strlen",
    "lstrlena",
    "strcmp",
    "strncmp",
    "stricmp",
    "_stricmp",
    "strstr",
    "puts",
    "printf",
    "outputdebugstringa",
    "messageboxa",
    "pathfindfilenamea",
    "pathremovefilespeca",
}
WIDE_STRING_APIS = {
    "lstrlenw",
    "wcscmp",
    "wcsncmp",
    "wcsstr",
    "outputdebugstringw",
    "messageboxw",
    "pathfindfilenamew",
    "pathremovefilespecw",
}
ANSI_DEBUG_APIS = {"outputdebugstringa"}
WIDE_DEBUG_APIS = {"outputdebugstringw"}


def infer_argument_hint_from_callee(target_name: str, position: int) -> dict[str, str] | None:
    normalized = normalize_target_name(target_name)
    lowered = normalized.lower()
    if not lowered:
        return None
    leaf = lowered.split("::")[-1]
    if leaf in WIDE_PATH_APIS and position == 0:
        return {"name_hint": "path", "type_hint": "const wchar_t *", "reason": "wide_path_api_argument", "callee": normalized}
    if leaf in ANSI_PATH_APIS and position == 0:
        return {"name_hint": "path", "type_hint": "const char *", "reason": "ansi_path_api_argument", "callee": normalized}
    if leaf in ANSI_DEBUG_APIS and position == 0:
        return {"name_hint": "message", "type_hint": "const char *", "reason": "ansi_debug_api_argument", "callee": normalized}
    if leaf in WIDE_DEBUG_APIS and position == 0:
        return {"name_hint": "message", "type_hint": "const wchar_t *", "reason": "wide_debug_api_argument", "callee": normalized}
    if leaf == "messageboxa":
        if position == 1:
            return {"name_hint": "message", "type_hint": "const char *", "reason": "messagebox_text_argument", "callee": normalized}
        if position == 2:
            return {"name_hint": "title", "type_hint": "const char *", "reason": "messagebox_title_argument", "callee": normalized}
    if leaf == "messageboxw":
        if position == 1:
            return {"name_hint": "message", "type_hint": "const wchar_t *", "reason": "messagebox_text_argument", "callee": normalized}
        if position == 2:
            return {"name_hint": "title", "type_hint": "const wchar_t *", "reason": "messagebox_title_argument", "callee": normalized}
    if leaf in {"strlen", "lstrlena"} and position == 0:
        return {"name_hint": "text", "type_hint": "const char *", "reason": "ansi_string_api_argument", "callee": normalized}
    if leaf == "lstrlenw" and position == 0:
        return {"name_hint": "text", "type_hint": "const wchar_t *", "reason": "wide_string_api_argument", "callee": normalized}
    if leaf in {"strcmp", "strncmp", "stricmp", "_stricmp", "strstr"}:
        if position == 0:
            return {"name_hint": "text", "type_hint": "const char *", "reason": "ansi_string_api_argument", "callee": normalized}
        if position == 1:
            return {"name_hint": "other", "type_hint": "const char *", "reason": "ansi_string_api_argument", "callee": normalized}
    if leaf in {"wcscmp", "wcsncmp", "wcsstr"}:
        if position == 0:
            return {"name_hint": "text", "type_hint": "const wchar_t *", "reason": "wide_string_api_argument", "callee": normalized}
        if position == 1:
            return {"name_hint": "other", "type_hint": "const wchar_t *", "reason": "wide_string_api_argument", "callee": normalized}
    if "logmessage" in leaf and position == 0:
        return {"name_hint": "message", "type_hint": "const char *", "reason": "logger_message_argument", "callee": normalized}
    if "currentname" in leaf and position == 0:
        return {"name_hint": "name", "type_hint": "const char *", "reason": "name_accessor_argument", "callee": normalized}
    return None


def normalize_target_name(target_name: str) -> str:
    text = str(target_name or "").strip()
    if not text:
        return ""
    text = text.split("(", 1)[0].strip()
    text = text.lstrip("&")
    text = re.sub(r"^(?:__imp_|imp_|ptr_)+", "", text, flags=re.IGNORECASE)
    return text.strip()


def infer_result_hint_from_callee(
    target_name: str,
    *,
    argument_position: int | None = None,
    targeted_entries_by_name: dict[str, dict[str, object]] | None = None,
) -> dict[str, str] | None:
    normalized = normalize_target_name(target_name)
    lowered = normalized.lower()
    if not lowered:
        return None

    class_pointer_hint = _infer_class_pointer_hint(
        normalized,
        argument_position=argument_position,
        targeted_entries_by_name=targeted_entries_by_name or {},
    )
    if class_pointer_hint is not None:
        return class_pointer_hint

    leaf = lowered.split("::")[-1]
    if leaf in WIDE_PATH_APIS:
        return {"type_hint": "const wchar_t *", "reason": "result_used_as_path", "callee": normalized}
    if leaf in ANSI_PATH_APIS:
        return {"type_hint": "const char *", "reason": "result_used_as_path", "callee": normalized}
    if leaf in WIDE_STRING_APIS:
        return {"type_hint": "const wchar_t *", "reason": "result_passed_to_wide_string_api", "callee": normalized}
    if leaf in ANSI_STRING_APIS:
        return {"type_hint": "const char *", "reason": "result_passed_to_string_like_api", "callee": normalized}

    if any(keyword in leaf for keyword in ("path", "file", "directory", "module", "library")):
        return {
            "type_hint": "const wchar_t *" if leaf.endswith("w") else "const char *",
            "reason": "result_used_as_path",
            "callee": normalized,
        }
    if any(keyword in leaf for keyword in ("messagebox", "debugstring", "strlen", "strcmp", "strstr", "text", "label", "title")):
        return {
            "type_hint": "const wchar_t *" if leaf.endswith("w") else "const char *",
            "reason": "result_passed_to_wide_string_api" if leaf.endswith("w") else "result_passed_to_string_like_api",
            "callee": normalized,
        }
    return None


def refine_result_hint(hint: dict[str, object] | None) -> dict[str, object] | None:
    return _refine_result_hint_with_context(hint, targeted_entries_by_name={})


def _refine_result_hint_with_context(
    hint: dict[str, object] | None,
    *,
    targeted_entries_by_name: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    if not isinstance(hint, dict):
        return None
    refined = copy.deepcopy(hint)
    callee = str(refined.get("callee") or "").strip()
    argument_position = _coerce_int(refined.get("argument_position"))
    inferred = infer_result_hint_from_callee(
        callee,
        argument_position=argument_position,
        targeted_entries_by_name=targeted_entries_by_name,
    )
    if inferred is None:
        return refined
    for key, value in inferred.items():
        refined[key] = value
    return refined


def refine_targeted_decompilation(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    targeted_entries_by_name = _build_targeted_entry_index(entries)
    refined_entries: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        updated = copy.deepcopy(entry)
        collected_result_hints: list[dict[str, object]] = []
        updated["callsite_argument_hints"] = refine_argument_hints(
            updated.get("callsite_argument_hints"),
            entry_name=str(updated.get("name") or ""),
        )
        callers = []
        for caller in updated.get("callers") or []:
            if not isinstance(caller, dict):
                continue
            caller_copy = copy.deepcopy(caller)
            caller_copy["argument_hints"] = refine_argument_hints(caller_copy.get("argument_hints"), entry_name=str(updated.get("name") or ""))
            refined_hint = _refine_result_hint_with_context(
                caller_copy.get("result_hint"),
                targeted_entries_by_name=targeted_entries_by_name,
            )
            if refined_hint is not None:
                caller_copy["result_hint"] = refined_hint
                collected_result_hints.append(refined_hint)
            callers.append(caller_copy)
        if callers:
            updated["callers"] = callers
        for hint in updated.get("result_hints") or []:
            refined_hint = _refine_result_hint_with_context(
                hint if isinstance(hint, dict) else None,
                targeted_entries_by_name=targeted_entries_by_name,
            )
            if refined_hint is not None:
                collected_result_hints.append(refined_hint)
        if collected_result_hints:
            updated["result_hints"] = collected_result_hints
        refined_entries.append(updated)
    return refined_entries


def refine_argument_hints(
    hints: list[dict[str, object]] | None,
    *,
    entry_name: str = "",
    callee_name: str = "",
) -> list[dict[str, object]]:
    refined_hints: list[dict[str, object]] = []
    effective_callee = callee_name or entry_name
    for hint in hints or []:
        if not isinstance(hint, dict):
            continue
        refined = copy.deepcopy(hint)
        try:
            position = int(refined.get("position"))
        except (TypeError, ValueError):
            position = -1
        if position >= 0:
            inferred = infer_argument_hint_from_callee(effective_callee, position)
            if inferred is not None:
                if not refined.get("name_hint") or str(refined.get("name_hint")).strip().lower() in {"text", "value"}:
                    refined["name_hint"] = inferred["name_hint"]
                if not refined.get("type_hint") or str(refined.get("type_hint")).strip().lower() in {"void *", "undefined8", "undefined4"}:
                    refined["type_hint"] = inferred["type_hint"]
                refined["reason"] = inferred["reason"]
                refined["callee"] = inferred["callee"]
        refined_hints.append(refined)
    return refined_hints


def _infer_class_pointer_hint(
    target_name: str,
    *,
    argument_position: int | None = None,
    targeted_entries_by_name: dict[str, dict[str, object]],
) -> dict[str, str] | None:
    parameter_hint = _infer_parameter_type_hint_from_entry(
        target_name,
        argument_position=argument_position,
        targeted_entries_by_name=targeted_entries_by_name,
    )
    if parameter_hint is not None:
        return parameter_hint
    if "::" not in target_name:
        return None
    class_name, _, method_name = target_name.rpartition("::")
    class_name = class_name.strip()
    method_name = method_name.strip()
    if not _is_recoverable_class_name(class_name) or not method_name:
        return None
    if argument_position not in {None, 0}:
        return None
    return {"type_hint": f"{class_name} *", "reason": "result_passed_to_class_method", "callee": target_name}


def _infer_parameter_type_hint_from_entry(
    target_name: str,
    *,
    argument_position: int | None,
    targeted_entries_by_name: dict[str, dict[str, object]],
) -> dict[str, str] | None:
    if argument_position is None or argument_position < 0:
        return None
    entry = targeted_entries_by_name.get(normalize_target_name(target_name).lower())
    if entry is None:
        return None
    parameters = [parameter for parameter in entry.get("parameters") or [] if isinstance(parameter, dict)]
    if not parameters:
        return None
    if str(parameters[0].get("name") or "").strip().lower() == "this":
        effective_index = argument_position
    else:
        effective_index = argument_position
    if effective_index >= len(parameters):
        return None
    parameter = parameters[effective_index]
    type_hint = _normalize_parameter_type_hint(parameter.get("data_type"))
    if not type_hint:
        return None
    return {
        "type_hint": type_hint,
        "reason": "result_forwarded_to_typed_parameter",
        "callee": normalize_target_name(target_name),
    }


def _is_recoverable_class_name(class_name: str) -> bool:
    if not class_name:
        return False
    leaf = class_name.split("::")[-1].strip()
    lowered = leaf.lower()
    if not leaf or lowered == "std":
        return False
    if lowered.startswith(GENERIC_NAME_PREFIXES):
        return False
    return bool(re.match(r"^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*$", class_name))


def _build_targeted_entry_index(entries: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = normalize_target_name(str(entry.get("name") or ""))
        namespace = normalize_target_name(str(entry.get("namespace") or ""))
        if name:
            index[name.lower()] = entry
        if namespace and name:
            index[f"{namespace}::{name}".lower()] = entry
    return index


def _normalize_parameter_type_hint(value: object) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if not text or lowered in {"void *", "undefined", "undefined4", "undefined8", "int", "longlong", "ulonglong"}:
        return ""
    if lowered == "char *":
        return "const char *"
    if lowered == "wchar_t *":
        return "const wchar_t *"
    return text


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
