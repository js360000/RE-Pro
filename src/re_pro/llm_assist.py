from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .recompile import (
    create_recompile_workspace,
    detect_toolchains,
    install_dependency,
    run_recompile_command,
    validate_reconstruction_file,
)
from .llm_auth import build_openai_client_for_settings
from .llm_auth import llm_auth_status
from .utils import ensure_dir, safe_output_path


def run_llm_assist_job(
    request_path: str | Path,
    *,
    logger: Callable[[str], None] | None = None,
    client_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    request_file = Path(request_path).resolve()
    payload = json.loads(request_file.read_text(encoding="utf-8"))
    llm_dir = Path(payload["llm_dir"]).resolve()
    reconstructed_root = ensure_dir(Path(payload["reconstructed_root"]).resolve())
    ensure_dir(llm_dir)
    log_path = llm_dir / "llm.log"
    status_path = llm_dir / "status.json"
    writes_manifest_path = llm_dir / "written_files.json"
    summary_path = llm_dir / "assistant_summary.md"
    recompile_root = ensure_dir(llm_dir / "recompile_workspace")
    create_recompile_workspace(recompile_root, payload.get("report") or {}, (payload.get("report") or {}).get("frameworks") or [])

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")
        if logger:
            logger(message)

    def write_status(state: str, **extra: Any) -> None:
        status = {
            "state": state,
            "updated_at": _utc_now(),
            "request_path": str(request_file),
            "llm_dir": str(llm_dir),
            "reconstructed_root": str(reconstructed_root),
        }
        status.update(extra)
        status_path.write_text(json.dumps(status, indent=2), encoding="utf-8")

    write_status("running", started_at=_utc_now())
    log("Preparing LLM reconstruction run")

    try:
        context_items = payload.get("context_items") or []
        analysis_index = payload.get("analysis_index") or {}
        settings = payload.get("settings") or {}
        client = client_factory() if client_factory else _default_client_factory(settings)
        naming_hints = _find_context_json(context_items, "naming_hints.json")
        tools = _tool_specs()
        writes: list[dict[str, Any]] = []
        validations: list[dict[str, Any]] = []
        max_tool_rounds = 24
        tool_rounds = 0
        response = client.responses.create(
            model=settings.get("model", "gpt-5.4"),
            instructions=_build_instructions(payload),
            input=_build_user_input(payload),
            reasoning={"effort": settings.get("reasoning_effort", "high")},
            text={"verbosity": settings.get("verbosity", "medium")},
            max_output_tokens=int(settings.get("max_output_tokens", 12000)),
            tools=tools,
        )
        log(f"Initial response received from model {settings.get('model', 'gpt-5.4')}")

        while tool_rounds < max_tool_rounds:
            function_calls = _extract_function_calls(response)
            if not function_calls:
                break
            tool_rounds += 1
            log(f"Processing tool round {tool_rounds} with {len(function_calls)} function call(s)")
            tool_outputs = []
            for call in function_calls:
                tool_name = call["name"]
                arguments = _json_loads(call["arguments"])
                result = _dispatch_tool_call(
                    tool_name,
                    arguments,
                    context_items=context_items,
                    analysis_index=analysis_index,
                    reconstructed_root=reconstructed_root,
                    writes=writes,
                    validations=validations,
                    recompile_root=recompile_root,
                    settings=settings,
                    naming_hints=naming_hints,
                    logger=log,
                )
                tool_outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": call["call_id"],
                        "output": json.dumps(result, ensure_ascii=False),
                    }
                )
                log(f"Executed tool {tool_name}")
            writes_manifest_path.write_text(json.dumps(writes, indent=2), encoding="utf-8")
            response = client.responses.create(
                model=settings.get("model", "gpt-5.4"),
                previous_response_id=_get_value(response, "id"),
                input=tool_outputs,
                reasoning={"effort": settings.get("reasoning_effort", "high")},
                text={"verbosity": settings.get("verbosity", "medium")},
                max_output_tokens=int(settings.get("max_output_tokens", 12000)),
                tools=tools,
            )

        summary = _extract_output_text(response)
        if not summary.strip():
            summary = "The reconstruction job finished without a text summary from the model."
        summary_path.write_text(summary, encoding="utf-8")
        writes_manifest_path.write_text(json.dumps(writes, indent=2), encoding="utf-8")
        (llm_dir / "validation_results.json").write_text(json.dumps(validations, indent=2), encoding="utf-8")
        write_status(
            "completed",
            finished_at=_utc_now(),
            model=settings.get("model", "gpt-5.4"),
            auth=llm_auth_status(SimpleSettings(settings)),
            response_id=_get_value(response, "id"),
            tool_rounds=tool_rounds,
            written_files=len(writes),
            summary_path=str(summary_path),
            validation_results=str(llm_dir / "validation_results.json"),
        )
        return {
            "status": "completed",
            "summary_path": str(summary_path),
            "written_files_path": str(writes_manifest_path),
            "written_files": writes,
            "validation_results_path": str(llm_dir / "validation_results.json"),
            "response_id": _get_value(response, "id"),
        }
    except Exception as exc:
        write_status("failed", finished_at=_utc_now(), error=str(exc))
        log(f"LLM assist failed: {exc}")
        raise


def _default_client_factory(settings: dict[str, Any]):
    return build_openai_client_for_settings(SimpleSettings(settings))


class SimpleSettings:
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    def __getattr__(self, name: str) -> Any:
        return self.values.get(name)


def _build_instructions(payload: dict[str, Any]) -> str:
    settings = payload.get("settings") or {}
    porting = settings.get("porting_settings") or {}
    target_arch = str(porting.get("target_arch", "")).strip()
    source_arch = str(porting.get("source_arch", "")).strip()
    porting_instruction = ""
    if target_arch:
        porting_instruction = (
            f" The requested architecture port is {source_arch or 'detected source architecture'} to {target_arch}; "
            "emit source-level equivalents that compile for the target architecture, isolate architecture-specific shims, "
            "and explicitly mark any x86/x64 assumptions, calling-convention assumptions, pointer-width assumptions, SIMD intrinsics, inline assembly, or ABI-sensitive code."
        )
    return (
        "You are assisting a reverse-engineering and platform-porting workflow. "
        "Inspect the provided context using tools before making strong claims. "
        "Use the analysis index tools to inspect normalized frameworks, artifacts, functions, strings, and cross-tool correlations before falling back to raw files. "
        "When RTTI, vtable, class, symbol, namespace, or debug-source names are available, preserve them and let them drive filenames, class names, function names, and comments. "
        "Do not fall back to generic names like app_approx, module1, class_1, file1, or function_401000 when naming evidence already exists. "
        "If debug symbols or recovered source paths exist, mirror those original paths unless there is concrete contrary evidence. "
        "If RTTI or vtable evidence links a function to a class, write the pseudo-source under that class rather than as a detached anonymous function. "
        "When class layouts, fields, subobjects, constructor phases, thunks, call edges, or flag domains are present in naming_hints.json or the analysis index, preserve those names and comments in the reconstructed source. "
        "Use field offsets and provenance as hard evidence for member declarations, and keep uncertain field shapes visibly marked instead of renaming them away. "
        "Create a small number of high-value reconstructed files instead of spraying low-value boilerplate. "
        "Do not invent APIs, imports, or files unless you can tie them to concrete evidence from context items, manifests, imports, strings, or prior reconstructed files. "
        "Every reconstructed file must include evidence_refs naming the context items or search hits it came from, plus a confidence value. "
        "Prefer partial but grounded reconstructions over polished fantasy code. "
        "When possible, validate reconstructed files immediately and then attempt a constrained recompile or syntax-check using the available toolchains. "
        "Prioritize entrypoints, app lifecycle, UI shell, IPC/update/network/config logic, and porting blockers. "
        "When certainty is low, state that clearly in comments and file content. "
        "Use plausible filenames and extensions for the detected language/framework. "
        "Write a PORTING_GUIDE.md file if portability concerns are relevant. "
        f"{porting_instruction} "
        "Write a STRING_TO_FUNCTION_MAP.json file mapping concrete recovered strings or evidence to plausible modules/functions and confidence levels. "
        "Finish with a concise textual summary of what you reconstructed, what remains uncertain, and which files matter most."
    )


def _build_user_input(payload: dict[str, Any]) -> str:
    report = payload.get("report") or {}
    settings = payload.get("settings") or {}
    porting = settings.get("porting_settings") or {}
    context_items = payload.get("context_items") or []
    task = (settings.get("user_task") or "").strip()
    base_task = (
        "Reconstruct a plausible source layout and porting guidance from the reverse-engineering evidence. "
        "Use the tools to inspect indexed context items and then write reconstructed files."
    )
    if task:
        base_task += f"\n\nOperator steering:\n{task}"
    if str(porting.get("target_arch", "")).strip():
        base_task += (
            "\n\nArchitecture port request:\n"
            f"- Source architecture: {str(porting.get('source_arch', '')).strip() or 'infer from binary metadata'}\n"
            f"- Target architecture: {str(porting.get('target_arch', '')).strip()}\n"
            f"- Mode: {str(porting.get('mode', 'heuristic')).strip() or 'heuristic'}\n"
            "- Preserve recovered RTTI/vtable/class/function/source names when creating target-architecture source files.\n"
            "- Prefer portable C/C++/Rust/JS/TS source equivalents over assembly; isolate unavoidable target-specific code behind named adapters.\n"
        )
    base_task += (
        "\n\nAnalysis summary:\n"
        f"- Target: {report.get('target')}\n"
        f"- Type: {report.get('target_type')}\n"
        f"- Frameworks: {', '.join(report.get('frameworks') or []) or 'none'}\n"
        f"- Findings: {len(report.get('findings') or [])}\n"
        f"- Artifacts: {len(report.get('artifacts') or [])}\n"
        f"- Recovered sources: {len(report.get('recovered_sources') or [])}\n"
        f"- Analysis index entities: {sum((report.get('analysis_index_summary') or {}).get('entity_counts', {}).values()) if isinstance(report.get('analysis_index_summary'), dict) else 'unknown'}\n"
    )
    context_names = {str(item.get("name", "")) for item in context_items}
    if "naming_hints.json" in context_names:
        base_task += (
            "\nNaming constraints:\n"
            "- Read `naming_hints.json` before writing files.\n"
            "- Reuse recovered source paths and symbol-derived names wherever possible.\n"
            "- Reuse recovered class layouts, field names, constructor phases, call edges, and flag names when present.\n"
            "- Treat generic placeholder filenames as invalid when better names exist.\n"
        )
    return base_task


def _tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": "list_context_items",
            "description": "List the indexed context items available for inspection.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "read_context_item",
            "description": "Read text from one indexed context item.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "max_chars": {"type": "integer", "minimum": 256, "maximum": 24000},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "search_context",
            "description": "Search indexed context item contents for a literal case-insensitive query string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "list_index_entities",
            "description": "List normalized entities from the unified analysis index, optionally filtered by kind.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "search_index",
            "description": "Search the unified analysis index across entity labels, keys, and string values.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "kind": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "get_index_entity",
            "description": "Fetch one entity and its immediate relations from the unified analysis index.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string"},
                    "relation_limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["entity_id"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "write_reconstruction_file",
            "description": "Write a reconstructed file into the output tree.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {"type": "string"},
                    "content": {"type": "string"},
                    "rationale": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                    },
                },
                "required": ["relative_path", "content", "confidence", "evidence_refs"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "read_reconstruction_file",
            "description": "Read back a file previously written into the reconstruction output tree.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {"type": "string"},
                },
                "required": ["relative_path"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "validate_reconstruction_file",
            "description": "Run a syntax or structural validator for a reconstructed file when supported.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {"type": "string"},
                },
                "required": ["relative_path"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "inspect_toolchains",
            "description": "List available build toolchains in the local environment and recompile workspace.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "install_dependency",
            "description": "Install a missing dependency into the dedicated recompile workspace using a supported ecosystem package manager.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string"},
                    "package": {"type": "string"},
                },
                "required": ["ecosystem", "package"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "run_recompile_command",
            "description": "Run a constrained build or syntax-check command in the recompile workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string"},
                    "action": {"type": "string"},
                },
                "required": ["ecosystem", "action"],
                "additionalProperties": False,
            },
        },
    ]


def _dispatch_tool_call(
    name: str,
    arguments: dict[str, Any],
    *,
    context_items: list[dict[str, Any]],
    analysis_index: dict[str, Any],
    reconstructed_root: Path,
    writes: list[dict[str, Any]],
    validations: list[dict[str, Any]],
    recompile_root: Path,
    settings: dict[str, Any],
    naming_hints: dict[str, Any] | None = None,
    logger=None,
) -> dict[str, Any]:
    if name == "list_context_items":
        return {"items": context_items}
    if name == "list_index_entities":
        kind = str(arguments.get("kind", "")).strip().lower()
        limit = int(arguments.get("limit", 50))
        entities = analysis_index.get("entities") or []
        if kind:
            entities = [entity for entity in entities if str(entity.get("kind", "")).lower() == kind]
        return {"entities": entities[:limit]}
    if name == "search_index":
        query = str(arguments.get("query", "")).strip().lower()
        kind = str(arguments.get("kind", "")).strip().lower()
        limit = int(arguments.get("limit", 20))
        if not query:
            return {"matches": []}
        matches: list[dict[str, Any]] = []
        for entity in analysis_index.get("entities") or []:
            if kind and str(entity.get("kind", "")).lower() != kind:
                continue
            haystacks = [
                str(entity.get("label", "")),
                str(entity.get("key", "")),
                json.dumps(entity.get("attributes") or {}, ensure_ascii=False),
            ]
            if not any(query in haystack.lower() for haystack in haystacks):
                continue
            matches.append(entity)
            if len(matches) >= limit:
                break
        return {"matches": matches}
    if name == "get_index_entity":
        entity_id = str(arguments.get("entity_id", "")).strip()
        relation_limit = int(arguments.get("relation_limit", 50))
        entity = None
        for candidate in analysis_index.get("entities") or []:
            candidate_id = f"{candidate.get('kind')}:{candidate.get('key')}"
            if candidate_id == entity_id:
                entity = candidate
                break
        if entity is None:
            return {"error": f"Unknown entity {entity_id!r}"}
        related = [
            relation
            for relation in analysis_index.get("relations") or []
            if relation.get("source") == entity_id or relation.get("target") == entity_id
        ][:relation_limit]
        return {"entity": entity, "relations": related}
    if name == "read_context_item":
        item = _find_context_item(context_items, arguments.get("name", ""))
        if item is None:
            return {"error": f"Unknown context item {arguments.get('name')!r}"}
        path = Path(item["path"])
        payload = path.read_text(encoding="utf-8", errors="ignore")
        offset = int(arguments.get("offset", 0))
        max_chars = int(arguments.get("max_chars", 12000))
        chunk = payload[offset : offset + max_chars]
        return {
            "name": item["name"],
            "offset": offset,
            "returned_chars": len(chunk),
            "total_chars": len(payload),
            "content": chunk,
        }
    if name == "search_context":
        query = str(arguments.get("query", "")).strip().lower()
        if not query:
            return {"matches": []}
        max_results = int(arguments.get("max_results", 10))
        matches: list[dict[str, Any]] = []
        for item in context_items:
            path = Path(item["path"])
            content = path.read_text(encoding="utf-8", errors="ignore")
            hit = content.lower().find(query)
            if hit == -1:
                continue
            start = max(0, hit - 120)
            end = min(len(content), hit + 240)
            matches.append(
                {
                    "name": item["name"],
                    "path": item["path"],
                    "excerpt": content[start:end],
                }
            )
            if len(matches) >= max_results:
                break
        return {"matches": matches}
    if name == "write_reconstruction_file":
        relative_path = str(arguments.get("relative_path", "")).strip().replace("\\", "/")
        if not relative_path:
            return {"error": "relative_path is required"}
        generic_error = _validate_reconstruction_path(relative_path, naming_hints or {})
        if generic_error:
            return {"error": generic_error}
        evidence_refs = arguments.get("evidence_refs") or []
        if not isinstance(evidence_refs, list) or not evidence_refs:
            return {"error": "At least one evidence reference is required"}
        known_items = {item.get("name") for item in context_items}
        unknown_refs = [ref for ref in evidence_refs if ref not in known_items]
        if unknown_refs:
            return {"error": f"Unknown evidence refs: {', '.join(unknown_refs)}"}
        destination = safe_output_path(reconstructed_root, relative_path)
        ensure_dir(destination.parent)
        content = str(arguments.get("content", ""))
        destination.write_text(content, encoding="utf-8")
        recompile_destination = safe_output_path(recompile_root / "src", relative_path)
        ensure_dir(recompile_destination.parent)
        recompile_destination.write_text(content, encoding="utf-8")
        record = {
            "relative_path": relative_path,
            "path": str(destination),
            "recompile_path": str(recompile_destination),
            "rationale": str(arguments.get("rationale", "")),
            "confidence": float(arguments.get("confidence", 0.0)),
            "evidence_refs": evidence_refs,
            "bytes": destination.stat().st_size,
        }
        writes.append(record)
        return {"ok": True, "path": str(destination), "bytes": record["bytes"], "confidence": record["confidence"]}
    if name == "read_reconstruction_file":
        relative_path = str(arguments.get("relative_path", "")).strip().replace("\\", "/")
        destination = safe_output_path(reconstructed_root, relative_path)
        if not destination.exists():
            return {"error": f"Reconstructed file {relative_path!r} does not exist"}
        return {
            "relative_path": relative_path,
            "content": destination.read_text(encoding="utf-8", errors="ignore"),
        }
    if name == "validate_reconstruction_file":
        relative_path = str(arguments.get("relative_path", "")).strip().replace("\\", "/")
        destination = safe_output_path(reconstructed_root, relative_path)
        if not destination.exists():
            return {"error": f"Reconstructed file {relative_path!r} does not exist"}
        result = validate_reconstruction_file(destination, workspace_root=recompile_root, logger=logger)
        result["relative_path"] = relative_path
        validations.append(result)
        return result
    if name == "inspect_toolchains":
        return {
            "toolchains": detect_toolchains(),
            "recompile_root": str(recompile_root),
        }
    if name == "install_dependency":
        if not settings.get("allow_dependency_installs", True):
            return {"error": "Dependency installation is disabled for this reconstruction run"}
        return install_dependency(
            workspace_root=recompile_root,
            ecosystem=str(arguments.get("ecosystem", "")),
            package=str(arguments.get("package", "")),
            logger=logger,
        )
    if name == "run_recompile_command":
        if not settings.get("run_recompile_checks", True):
            return {"error": "Recompile commands are disabled for this reconstruction run"}
        return run_recompile_command(
            workspace_root=recompile_root,
            ecosystem=str(arguments.get("ecosystem", "")),
            action=str(arguments.get("action", "")),
            logger=logger,
        )
    return {"error": f"Unsupported tool {name}"}


def _validate_reconstruction_path(relative_path: str, naming_hints: dict[str, Any]) -> str | None:
    preferred_paths = [str(value) for value in naming_hints.get("preferred_source_paths") or [] if value]
    class_names = [str(value) for value in naming_hints.get("class_names") or [] if value]
    function_names = [str(value) for value in naming_hints.get("function_names") or [] if value]
    path_lower = relative_path.lower()
    generic_markers = ("app_approx", "module", "file", "class_", "function_", "recovered")
    looks_generic = any(marker in path_lower for marker in generic_markers)
    if not looks_generic:
        return None
    if not preferred_paths and not class_names and not function_names:
        return None
    return "Use recovered RTTI/symbol/debug names from naming_hints.json instead of a generic placeholder path."


def _extract_function_calls(response: Any) -> list[dict[str, str]]:
    calls: list[dict[str, str]] = []
    for item in _get_value(response, "output", []) or []:
        if _get_value(item, "type") != "function_call":
            continue
        calls.append(
            {
                "call_id": str(_get_value(item, "call_id") or _get_value(item, "id") or ""),
                "name": str(_get_value(item, "name") or ""),
                "arguments": str(_get_value(item, "arguments") or "{}"),
            }
        )
    return [call for call in calls if call["call_id"] and call["name"]]


def _extract_output_text(response: Any) -> str:
    output_text = _get_value(response, "output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    chunks: list[str] = []
    for item in _get_value(response, "output", []) or []:
        item_type = _get_value(item, "type")
        if item_type == "message":
            for content in _get_value(item, "content", []) or []:
                text = _get_value(content, "text")
                if text:
                    chunks.append(str(text))
        elif item_type == "output_text":
            text = _get_value(item, "text")
            if text:
                chunks.append(str(text))
    return "\n".join(chunk for chunk in chunks if chunk.strip())


def _find_context_item(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for item in items:
        if item.get("name") == name:
            return item
    return None


def _find_context_json(items: list[dict[str, Any]], name: str) -> dict[str, Any]:
    item = _find_context_item(items, name)
    if item is None:
        return {}
    path = Path(str(item.get("path", "")))
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_loads(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _get_value(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
