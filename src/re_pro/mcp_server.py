from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import (
    ClientCapabilities,
    ModelHint,
    ModelPreferences,
    SamplingCapability,
    SamplingMessage,
    TextContent,
)

from .analysis_diff import compare_analysis_runs, create_patch_bundle_from_runs
from .analyzers.porting import generate_architecture_port_from_run
from .dependency_installer import DependencyInstaller
from .engine import ReverseEngineeringEngine
from .live_process import capture_live_process, list_live_processes
from .models import LiveProcessSettings
from .plugins import build_analyzers, resolve_plugin_dirs
from .recompile import (
    create_recompile_workspace,
    detect_toolchains,
    install_dependency,
    run_packaging_action,
    run_recompile_command,
    validate_reconstruction_file,
)
from .utils import ensure_dir, safe_output_path, sanitize_text
from .workspace_browser import build_browser_workspace, patch_browser_node_bytes, read_browser_node, write_browser_node

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class McpServerState:
    workspace_root: Path
    output_root: Path
    tools_root: Path
    plugin_dirs: list[Path] = field(default_factory=list)
    logger: Any = None
    known_run_dirs: set[Path] = field(default_factory=set)

    def log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


def build_mcp_server(
    *,
    workspace_root: str | Path | None = None,
    output_root: str | Path | None = None,
    tools_root: str | Path | None = None,
    plugin_dirs: list[str | Path] | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    logger=None,
) -> FastMCP:
    workspace = Path(workspace_root).resolve() if workspace_root else REPO_ROOT.resolve()
    output = Path(output_root).resolve() if output_root else (workspace / "analysis_output").resolve()
    tools = Path(tools_root).resolve() if tools_root else (workspace / "tools").resolve()
    state = McpServerState(
        workspace_root=workspace,
        output_root=output,
        tools_root=tools,
        plugin_dirs=resolve_plugin_dirs(plugin_dirs),
        logger=logger,
    )
    ensure_dir(state.output_root)

    server = FastMCP(
        name="RE-Pro MCP",
        instructions=(
            "RE-Pro exposes reverse-engineering, recovery, reconstruction, and rebuild workflows over MCP. "
            "Use the analysis tools to create or inspect runs, the index tools to search normalized evidence, "
            "the reconstruction tools to write grounded approximations, and the rebuild tools to validate or "
            "compile recovered projects. Prefer indexed evidence and explicit artifacts over speculation."
        ),
        dependencies=("mcp>=1.27,<2",),
        log_level="INFO",
        host=host,
        port=port,
    )

    @server.resource(
        "repro://roadmap",
        name="roadmap",
        title="RE-Pro Versatility Roadmap",
        description="Backlog of major capability expansions for RE-Pro.",
    )
    def roadmap_resource() -> str:
        roadmap_path = state.workspace_root / "VERSATILITY_ROADMAP.md"
        if not roadmap_path.exists():
            return "# RE-Pro Versatility Roadmap\n\nRoadmap file not found.\n"
        return roadmap_path.read_text(encoding="utf-8", errors="ignore")

    @server.resource(
        "repro://capabilities",
        name="capabilities",
        title="RE-Pro MCP Capabilities",
        description="High-level summary of the MCP server surface and current workspace configuration.",
    )
    def capabilities_resource() -> str:
        payload = {
            "workspace_root": str(state.workspace_root),
            "output_root": str(state.output_root),
            "tools_root": str(state.tools_root),
            "plugin_dirs": [str(path) for path in state.plugin_dirs],
            "toolchains": detect_toolchains(),
        }
        return json.dumps(payload, indent=2)

    @server.resource(
        "repro://latest-runs",
        name="latest_runs",
        title="Latest Analysis Runs",
        description="Structured list of the most recent analysis runs under the configured output root.",
    )
    def latest_runs_resource() -> str:
        payload = {"runs": _list_analysis_runs(state, limit=20)}
        return json.dumps(payload, indent=2)

    @server.prompt(
        name="grounded_reconstruction",
        title="Grounded Reconstruction",
        description="Prompt template for an MCP client to reconstruct source from RE-Pro evidence.",
    )
    def grounded_reconstruction_prompt(run_output_dir: str, task: str = "", focus: str = "") -> str:
        report = _load_report_dict(Path(run_output_dir))
        frameworks = ", ".join(report.get("frameworks") or []) or "none"
        focus_line = f"\nFocus: {focus}" if focus.strip() else ""
        task_line = f"\nOperator steering: {task}" if task.strip() else ""
        return (
            "Use RE-Pro's MCP tools to inspect the analysis graph before reconstructing code. "
            "Start with `search_analysis_index`, `get_index_entity`, `list_artifacts`, and `list_recovered_sources`, "
            "then write only grounded files with explicit evidence references."
            f"\nRun: {run_output_dir}"
            f"\nTarget: {report.get('target', 'unknown')}"
            f"\nFrameworks: {frameworks}"
            f"{focus_line}"
            f"{task_line}"
        )

    @server.tool(
        name="analyze_target",
        description="Analyze a file or directory with RE-Pro and return the resulting report.",
        structured_output=True,
    )
    async def analyze_target(
        target: str,
        output_root: str | None = None,
        plugin_dirs: list[str] | None = None,
        run_external_tools: bool = False,
        run_ghidra: bool = False,
        live_pid: int = 0,
        live_process_name: str = "",
        live_dump_memory: bool = True,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        effective_output_root = Path(output_root).resolve() if output_root else state.output_root
        effective_plugin_dirs = plugin_dirs if plugin_dirs is not None else [str(path) for path in state.plugin_dirs]
        await _ctx_info(ctx, f"Analyzing {target}")
        engine = ReverseEngineeringEngine(
            output_root=effective_output_root,
            logger=state.logger,
            run_external_tools=run_external_tools or run_ghidra,
            run_ghidra=run_ghidra,
            plugin_dirs=effective_plugin_dirs,
            live_process_settings=LiveProcessSettings(
                enabled=bool(live_pid or live_process_name),
                pid=live_pid,
                process_name=live_process_name,
                dump_memory=live_dump_memory,
            ),
        )
        report = engine.analyze(target)
        state.known_run_dirs.add(Path(report.output_dir).resolve())
        return report.to_dict()

    @server.tool(
        name="list_live_processes",
        description="List running local processes visible to RE-Pro, optionally filtered by name/path/command line.",
        structured_output=True,
    )
    def list_live_processes_tool(query: str = "", limit: int = 100) -> dict[str, Any]:
        return {"processes": list_live_processes(query, limit=limit)}

    @server.tool(
        name="capture_live_process",
        description="Attach to a running local process and capture modules, readable memory metadata, selected dumps, carved payloads, and strings.",
        structured_output=True,
    )
    def capture_live_process_tool(
        output_dir: str,
        pid: int = 0,
        process_name: str = "",
        dump_memory: bool = True,
        max_region_mb: int = 8,
        max_total_mb: int = 256,
        include_mapped_images: bool = False,
        include_all_readable: bool = False,
    ) -> dict[str, Any]:
        return capture_live_process(
            output_dir=Path(output_dir),
            settings=LiveProcessSettings(
                enabled=True,
                pid=pid,
                process_name=process_name,
                dump_memory=dump_memory,
                max_region_bytes=max(4096, max_region_mb * 1024 * 1024),
                max_total_bytes=max(4096, max_total_mb * 1024 * 1024),
                include_mapped_images=include_mapped_images,
                include_all_readable=include_all_readable,
            ),
            logger=state.logger,
        )

    @server.tool(
        name="install_tooling",
        description="Download and install RE-Pro's portable reverse-engineering toolchain.",
        structured_output=True,
    )
    async def install_tooling(tools_root: str | None = None, ctx: Context | None = None) -> dict[str, Any]:
        destination = Path(tools_root).resolve() if tools_root else state.tools_root
        await _ctx_info(ctx, f"Installing tooling into {destination}")
        installer = DependencyInstaller(tools_root=destination, logger=state.logger)
        return installer.install_all()

    @server.tool(
        name="list_analyzers",
        description="List built-in and plugin analyzers that RE-Pro will run.",
        structured_output=True,
    )
    def list_analyzers(plugin_dirs: list[str] | None = None) -> dict[str, Any]:
        effective_plugin_dirs = plugin_dirs if plugin_dirs is not None else [str(path) for path in state.plugin_dirs]
        analyzers = build_analyzers(plugin_dirs=effective_plugin_dirs, logger=state.logger)
        return {
            "plugin_dirs": effective_plugin_dirs,
            "analyzers": [
                {
                    "name": analyzer.name,
                    "class": analyzer.__class__.__name__,
                    "module": analyzer.__class__.__module__,
                }
                for analyzer in analyzers
            ],
        }

    @server.tool(
        name="list_analysis_runs",
        description="List analysis runs that exist under the configured output root.",
        structured_output=True,
    )
    def list_analysis_runs(limit: int = 50) -> dict[str, Any]:
        return {"runs": _list_analysis_runs(state, limit=max(1, min(limit, 200)))}

    @server.tool(
        name="compare_analysis_runs",
        description="Compare two analysis runs and optionally emit a JSON/Markdown diff bundle.",
        structured_output=True,
    )
    def compare_analysis_runs_tool(base_run_output_dir: str, head_run_output_dir: str, output_dir: str = "") -> dict[str, Any]:
        destination = Path(output_dir).resolve() if output_dir.strip() else None
        return compare_analysis_runs(Path(base_run_output_dir), Path(head_run_output_dir), destination)

    @server.tool(
        name="create_patch_bundle_from_runs",
        description="Create a resource/source patch bundle from two analysis runs using the diff graph and head-run artifacts.",
        structured_output=True,
    )
    def create_patch_bundle_from_runs_tool(base_run_output_dir: str, head_run_output_dir: str, output_dir: str) -> dict[str, Any]:
        return create_patch_bundle_from_runs(Path(base_run_output_dir), Path(head_run_output_dir), Path(output_dir))

    @server.tool(
        name="read_report",
        description="Read the JSON report for one analysis run.",
        structured_output=True,
    )
    def read_report(run_output_dir: str) -> dict[str, Any]:
        return _load_report_dict(Path(run_output_dir))

    @server.tool(
        name="read_analysis_index",
        description="Read the unified analysis index for one run.",
        structured_output=True,
    )
    def read_analysis_index(run_output_dir: str) -> dict[str, Any]:
        return _load_analysis_index(Path(run_output_dir))

    @server.tool(
        name="search_analysis_index",
        description="Search the unified analysis index by label, key, or serialized attributes.",
        structured_output=True,
    )
    def search_analysis_index(run_output_dir: str, query: str, kind: str = "", limit: int = 20) -> dict[str, Any]:
        analysis_index = _load_analysis_index(Path(run_output_dir))
        return {
            "matches": _search_analysis_index(
                analysis_index,
                query=query,
                kind=kind,
                limit=max(1, min(limit, 200)),
            )
        }

    @server.tool(
        name="get_index_entity",
        description="Fetch one analysis-index entity and its immediate relations.",
        structured_output=True,
    )
    def get_index_entity(run_output_dir: str, entity_id: str, relation_limit: int = 50) -> dict[str, Any]:
        analysis_index = _load_analysis_index(Path(run_output_dir))
        entity, relations = _get_index_entity(
            analysis_index,
            entity_id=entity_id,
            relation_limit=max(1, min(relation_limit, 500)),
        )
        return {"entity": entity, "relations": relations}

    @server.tool(
        name="list_artifacts",
        description="List artifacts produced by one analysis run.",
        structured_output=True,
    )
    def list_artifacts(run_output_dir: str, category: str = "") -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        artifacts = report.get("artifacts") or []
        if category.strip():
            lowered = category.strip().lower()
            artifacts = [artifact for artifact in artifacts if str(artifact.get("category", "")).lower() == lowered]
        return {"artifacts": artifacts}

    @server.tool(
        name="list_recovered_sources",
        description="List recovered source files for one analysis run.",
        structured_output=True,
    )
    def list_recovered_sources(run_output_dir: str) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        return {"recovered_sources": report.get("recovered_sources") or []}

    @server.tool(
        name="read_output_file",
        description="Read a text or binary output file from RE-Pro and return a bounded preview.",
        structured_output=True,
    )
    def read_output_file(path: str, offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
        return _read_output_file(Path(path), offset=offset, max_bytes=max_bytes)

    @server.tool(
        name="build_browser_workspace",
        description=(
            "Build or refresh a source-first editable file browser for one analysis run. "
            "Recovered source is listed before pseudo-source, artifacts, archive members, and raw binaries."
        ),
        structured_output=True,
    )
    def build_browser_workspace_tool(run_output_dir: str) -> dict[str, Any]:
        return build_browser_workspace(Path(run_output_dir))

    @server.tool(
        name="read_browser_node",
        description="Read one file-browser node as text, JSON, hex, or base64.",
        structured_output=True,
    )
    def read_browser_node_tool(
        run_output_dir: str,
        node_id: str,
        mode: str = "auto",
        offset: int = 0,
        max_bytes: int = 65536,
    ) -> dict[str, Any]:
        return read_browser_node(Path(run_output_dir), node_id, mode=mode, offset=offset, max_bytes=max_bytes)

    @server.tool(
        name="write_browser_node",
        description="Overwrite an editable browser node. Prefer source/pseudo-source nodes before binary patching.",
        structured_output=True,
    )
    def write_browser_node_tool(run_output_dir: str, node_id: str, content: str, mode: str = "text") -> dict[str, Any]:
        return write_browser_node(Path(run_output_dir), node_id, content, mode=mode)

    @server.tool(
        name="patch_browser_node_bytes",
        description="Patch hexadecimal bytes into an editable browser node at a byte offset.",
        structured_output=True,
    )
    def patch_browser_node_bytes_tool(run_output_dir: str, node_id: str, offset: int, hex_bytes: str) -> dict[str, Any]:
        return patch_browser_node_bytes(Path(run_output_dir), node_id, offset, hex_bytes)

    @server.tool(
        name="prepare_recompile_workspace",
        description="Create or refresh a recompile workspace for one analysis run.",
        structured_output=True,
    )
    def prepare_recompile_workspace(run_output_dir: str) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        return _prepare_recompile_workspace(Path(run_output_dir), report)

    @server.tool(
        name="prepare_architecture_port",
        description="Generate or refresh target-architecture source-port scaffolding for an existing analysis run.",
        structured_output=True,
    )
    def prepare_architecture_port(
        run_output_dir: str,
        target_arch: str = "arm64",
        source_arch: str = "",
        mode: str = "heuristic",
    ) -> dict[str, Any]:
        if mode not in {"heuristic", "llm", "hybrid"}:
            raise ValueError("mode must be one of: heuristic, llm, hybrid")
        return generate_architecture_port_from_run(
            Path(run_output_dir),
            source_arch=source_arch,
            target_arch=target_arch,
            mode=mode,
            logger=state.logger,
        )

    @server.tool(
        name="inspect_toolchains",
        description="List available local build toolchains.",
        structured_output=True,
    )
    def inspect_toolchains() -> dict[str, Any]:
        return {
            "workspace_root": str(state.workspace_root),
            "output_root": str(state.output_root),
            "tools_root": str(state.tools_root),
            "toolchains": detect_toolchains(),
        }

    @server.tool(
        name="write_reconstruction_file",
        description="Write a grounded reconstructed source file for one run and mirror it into the recompile workspace.",
        structured_output=True,
    )
    def write_reconstruction_file(
        run_output_dir: str,
        relative_path: str,
        content: str,
        confidence: float,
        evidence_refs: list[str],
        rationale: str = "",
    ) -> dict[str, Any]:
        if not evidence_refs:
            raise ValueError("At least one evidence reference is required.")
        report = _load_report_dict(Path(run_output_dir))
        workspace = _prepare_recompile_workspace(Path(run_output_dir), report)
        return _write_reconstruction_file(
            run_dir=Path(run_output_dir),
            relative_path=relative_path,
            content=content,
            confidence=confidence,
            evidence_refs=evidence_refs,
            rationale=rationale,
            workspace=workspace,
        )

    @server.tool(
        name="validate_reconstruction_file",
        description="Run syntax or structural validation on a reconstructed file.",
        structured_output=True,
    )
    def validate_reconstruction(
        run_output_dir: str,
        relative_path: str,
    ) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        workspace = _prepare_recompile_workspace(Path(run_output_dir), report)
        output_path = safe_output_path(Path(run_output_dir) / "mcp_reconstruction" / "reconstructed_src", relative_path)
        if not output_path.exists():
            raise FileNotFoundError(output_path)
        result = validate_reconstruction_file(output_path, workspace_root=Path(workspace["workspace_root"]))
        result["relative_path"] = relative_path
        return result

    @server.tool(
        name="install_project_dependency",
        description="Install a dependency into the run-specific recompile workspace.",
        structured_output=True,
    )
    def install_project_dependency(run_output_dir: str, ecosystem: str, package: str) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        workspace = _prepare_recompile_workspace(Path(run_output_dir), report)
        return install_dependency(
            workspace_root=Path(workspace["workspace_root"]),
            ecosystem=ecosystem,
            package=package,
            logger=state.logger,
        )

    @server.tool(
        name="run_project_command",
        description="Run a constrained build or check command in the run-specific recompile workspace.",
        structured_output=True,
    )
    def run_project_command(run_output_dir: str, ecosystem: str, action: str) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        workspace = _prepare_recompile_workspace(Path(run_output_dir), report)
        return run_recompile_command(
            workspace_root=Path(workspace["workspace_root"]),
            ecosystem=ecosystem,
            action=action,
            logger=state.logger,
        )

    @server.tool(
        name="run_packaging_action",
        description="Run a bounded package rebuild, repack, signing, or patch application action in the run-specific recompile workspace.",
        structured_output=True,
    )
    def run_packaging_action_tool(
        run_output_dir: str,
        ecosystem: str,
        action: str,
        artifact_path: str = "",
        output_path: str = "",
        keystore_path: str = "",
        key_alias: str = "",
        store_pass: str = "",
        key_pass: str = "",
        patch_bundle_path: str = "",
        target_root: str = "",
        compression: str = "zlib",
        compression_level: int = 9,
        block_size: int = 0x10000,
    ) -> dict[str, Any]:
        report = _load_report_dict(Path(run_output_dir))
        workspace = _prepare_recompile_workspace(Path(run_output_dir), report)
        return run_packaging_action(
            workspace_root=Path(workspace["workspace_root"]),
            ecosystem=ecosystem,
            action=action,
            artifact_path=artifact_path,
            output_path=output_path,
            keystore_path=keystore_path,
            key_alias=key_alias,
            store_pass=store_pass,
            key_pass=key_pass,
            patch_bundle_path=patch_bundle_path,
            target_root=target_root,
            compression=compression,
            compression_level=compression_level,
            block_size=block_size,
            logger=state.logger,
        )

    @server.tool(
        name="approximate_source_with_sampling",
        description=(
            "Ask the connected MCP client model to approximate one grounded source file from RE-Pro evidence and "
            "write it into the run-specific reconstruction workspace."
        ),
        structured_output=True,
    )
    async def approximate_source_with_sampling(
        run_output_dir: str,
        relative_path: str,
        task: str = "",
        focus_query: str = "",
        model_hint: str = "",
        max_tokens: int = 5000,
        intelligence_priority: float = 1.0,
        speed_priority: float = 0.2,
        cost_priority: float = 0.1,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        if ctx is None:
            raise RuntimeError("MCP sampling requires an active request context.")
        if not ctx.session.check_client_capability(ClientCapabilities(sampling=SamplingCapability())):
            return {"ok": False, "error": "Connected MCP client does not advertise sampling support."}

        run_dir = Path(run_output_dir)
        report = _load_report_dict(run_dir)
        analysis_index = _load_analysis_index(run_dir)
        workspace = _prepare_recompile_workspace(run_dir, report)
        evidence_bundle = _select_sampling_evidence(
            report=report,
            analysis_index=analysis_index,
            relative_path=relative_path,
            focus_query=focus_query or task,
        )
        system_prompt, user_prompt = _build_sampling_prompts(
            report=report,
            relative_path=relative_path,
            task=task,
            evidence=evidence_bundle,
        )
        await _ctx_info(ctx, f"Requesting client-side MCP sampling for {relative_path}")
        result = await ctx.session.create_message(
            messages=[
                SamplingMessage(role="user", content=TextContent(type="text", text=user_prompt)),
            ],
            max_tokens=max(512, min(max_tokens, 16000)),
            system_prompt=system_prompt,
            include_context="thisServer",
            model_preferences=ModelPreferences(
                hints=[ModelHint(name=model_hint)] if model_hint.strip() else None,
                intelligencePriority=max(0.0, min(intelligence_priority, 1.0)),
                speedPriority=max(0.0, min(speed_priority, 1.0)),
                costPriority=max(0.0, min(cost_priority, 1.0)),
            ),
            metadata={
                "re_pro_task": "approximate_source",
                "run_output_dir": str(run_dir),
                "relative_path": relative_path,
            },
        )
        response_text = _extract_sampling_text(result)
        parsed = _parse_sampling_json(response_text)
        if parsed is None:
            return {
                "ok": False,
                "error": "Client sampling response was not valid JSON.",
                "raw_response": response_text[:12000],
            }
        evidence_refs = parsed.get("evidence_refs") or evidence_bundle["allowed_refs"][:3]
        content = str(parsed.get("content", ""))
        if not content.strip():
            return {"ok": False, "error": "Client sampling response did not include file content."}
        write_result = _write_reconstruction_file(
            run_dir=run_dir,
            relative_path=str(parsed.get("relative_path") or relative_path),
            content=content,
            confidence=float(parsed.get("confidence", 0.0)),
            evidence_refs=[str(item) for item in evidence_refs],
            rationale=str(parsed.get("rationale", "")),
            workspace=workspace,
        )
        validation = validate_reconstruction_file(
            Path(write_result["path"]),
            workspace_root=Path(workspace["workspace_root"]),
        )
        return {
            "ok": True,
            "sampling_model": getattr(result, "model", model_hint or "client-selected"),
            "sampling_stop_reason": getattr(result, "stopReason", None),
            "draft": parsed,
            "write": write_result,
            "validation": validation,
        }

    return server


def parse_mcp_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="re-pro-mcp", description="Run the RE-Pro MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--workspace-root", default=str(REPO_ROOT))
    parser.add_argument("--output-root", default=str(REPO_ROOT / "analysis_output"))
    parser.add_argument("--tools-root", default=str(REPO_ROOT / "tools"))
    parser.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_mcp_args(argv)
    server = build_mcp_server(
        workspace_root=args.workspace_root,
        output_root=args.output_root,
        tools_root=args.tools_root,
        plugin_dirs=args.plugin_dir,
        host=args.host,
        port=args.port,
        logger=print,
    )
    server.run(args.transport)
    return 0


def _list_analysis_runs(state: McpServerState, *, limit: int) -> list[dict[str, Any]]:
    report_paths: dict[Path, None] = {}
    if state.output_root.exists():
        for report_path in state.output_root.rglob("report.json"):
            report_paths[report_path.resolve()] = None
    for run_dir in state.known_run_dirs:
        candidate = run_dir / "report.json"
        if candidate.exists():
            report_paths[candidate.resolve()] = None
    runs: list[dict[str, Any]] = []
    for report_path in sorted(report_paths, key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        run_dir = report_path.parent
        runs.append(
            {
                "output_dir": str(run_dir),
                "target": report.get("target"),
                "target_type": report.get("target_type"),
                "frameworks": report.get("frameworks") or [],
                "artifact_count": len(report.get("artifacts") or []),
                "recovered_source_count": len(report.get("recovered_sources") or []),
                "updated_at": report_path.stat().st_mtime,
            }
        )
    return runs


def _load_report_dict(run_dir: Path) -> dict[str, Any]:
    report_path = run_dir.resolve() / "report.json"
    if not report_path.exists():
        raise FileNotFoundError(report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {report_path}")
    return payload


def _load_analysis_index(run_dir: Path) -> dict[str, Any]:
    index_path = run_dir.resolve() / "analysis_index.json"
    if not index_path.exists():
        raise FileNotFoundError(index_path)
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {index_path}")
    return payload


def _search_analysis_index(
    analysis_index: dict[str, Any],
    *,
    query: str,
    kind: str = "",
    limit: int = 20,
) -> list[dict[str, Any]]:
    lowered_query = query.strip().lower()
    lowered_kind = kind.strip().lower()
    if not lowered_query:
        return []
    matches: list[dict[str, Any]] = []
    for entity in analysis_index.get("entities") or []:
        if lowered_kind and str(entity.get("kind", "")).lower() != lowered_kind:
            continue
        haystacks = [
            str(entity.get("label", "")),
            str(entity.get("key", "")),
            json.dumps(entity.get("attributes") or {}, ensure_ascii=False),
        ]
        if not any(lowered_query in haystack.lower() for haystack in haystacks):
            continue
        matches.append(entity)
        if len(matches) >= limit:
            break
    return matches


def _get_index_entity(
    analysis_index: dict[str, Any],
    *,
    entity_id: str,
    relation_limit: int = 50,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    entity = None
    for candidate in analysis_index.get("entities") or []:
        candidate_id = f"{candidate.get('kind')}:{candidate.get('key')}"
        if candidate_id == entity_id:
            entity = candidate
            break
    if entity is None:
        raise KeyError(entity_id)
    relations = [
        relation
        for relation in analysis_index.get("relations") or []
        if relation.get("source") == entity_id or relation.get("target") == entity_id
    ][:relation_limit]
    return entity, relations


def _read_output_file(path: Path, *, offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(resolved)
    payload = resolved.read_bytes()
    start = max(0, min(offset, len(payload)))
    end = min(len(payload), start + max(512, min(max_bytes, 65536)))
    chunk = payload[start:end]
    try:
        decoded = chunk.decode("utf-8")
        return {
            "path": str(resolved),
            "encoding": "utf-8",
            "offset": start,
            "returned_bytes": len(chunk),
            "total_bytes": len(payload),
            "content": decoded,
        }
    except UnicodeDecodeError:
        return {
            "path": str(resolved),
            "encoding": "base64",
            "offset": start,
            "returned_bytes": len(chunk),
            "total_bytes": len(payload),
            "content_base64": base64.b64encode(chunk).decode("ascii"),
        }


def _prepare_recompile_workspace(run_dir: Path, report: dict[str, Any]) -> dict[str, Any]:
    reconstruction_root = ensure_dir(run_dir.resolve() / "mcp_reconstruction")
    metadata = create_recompile_workspace(reconstruction_root, report, report.get("frameworks") or [])
    manifest_path = reconstruction_root / "workspace_info.json"
    manifest_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def _write_reconstruction_file(
    *,
    run_dir: Path,
    relative_path: str,
    content: str,
    confidence: float,
    evidence_refs: list[str],
    rationale: str,
    workspace: dict[str, Any],
) -> dict[str, Any]:
    reconstruction_root = ensure_dir(run_dir.resolve() / "mcp_reconstruction" / "reconstructed_src")
    destination = safe_output_path(reconstruction_root, relative_path)
    ensure_dir(destination.parent)
    destination.write_text(content, encoding="utf-8")

    workspace_source_root = ensure_dir(Path(workspace["source_root"]))
    mirrored = safe_output_path(workspace_source_root, relative_path)
    ensure_dir(mirrored.parent)
    mirrored.write_text(content, encoding="utf-8")

    manifest_path = run_dir.resolve() / "mcp_reconstruction" / "written_files.json"
    writes = []
    if manifest_path.exists():
        try:
            writes = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            writes = []
    record = {
        "relative_path": relative_path.replace("\\", "/"),
        "path": str(destination),
        "mirrored_path": str(mirrored),
        "confidence": max(0.0, min(confidence, 1.0)),
        "evidence_refs": [sanitize_text(str(item)) for item in evidence_refs],
        "rationale": sanitize_text(rationale),
        "bytes": destination.stat().st_size,
    }
    writes.append(record)
    manifest_path.write_text(json.dumps(writes, indent=2), encoding="utf-8")
    return record


def _select_sampling_evidence(
    *,
    report: dict[str, Any],
    analysis_index: dict[str, Any],
    relative_path: str,
    focus_query: str,
) -> dict[str, Any]:
    notes = [sanitize_text(str(note)) for note in (report.get("notes") or [])[:12]]
    findings = [
        {
            "title": sanitize_text(str(finding.get("title", ""))),
            "summary": sanitize_text(str(finding.get("summary", ""))),
            "severity": sanitize_text(str(finding.get("severity", ""))),
        }
        for finding in (report.get("findings") or [])[:12]
    ]
    if focus_query.strip():
        entities = _search_analysis_index(analysis_index, query=focus_query, limit=20)
    else:
        entities = (analysis_index.get("entities") or [])[:20]
    entity_refs = [f"{entity.get('kind')}:{entity.get('key')}" for entity in entities]
    return {
        "target": report.get("target"),
        "target_type": report.get("target_type"),
        "frameworks": report.get("frameworks") or [],
        "relative_path": relative_path,
        "notes": notes,
        "findings": findings,
        "entities": entities,
        "allowed_refs": entity_refs + [finding["title"] for finding in findings if finding["title"]],
    }


def _build_sampling_prompts(
    *,
    report: dict[str, Any],
    relative_path: str,
    task: str,
    evidence: dict[str, Any],
) -> tuple[str, str]:
    system_prompt = (
        "You are performing grounded source approximation for a reverse-engineering workflow. "
        "Return a single JSON object only, with keys: relative_path, confidence, evidence_refs, rationale, content. "
        "The file must be plausible, syntactically consistent, and explicitly conservative about uncertain details. "
        "Use only evidence references that appear in the provided evidence bundle. "
        "Prefer partial but valid source over complete but speculative source."
    )
    user_prompt = json.dumps(
        {
            "task": task or "Approximate one high-value source file from the evidence.",
            "target": report.get("target"),
            "target_type": report.get("target_type"),
            "frameworks": report.get("frameworks") or [],
            "output_relative_path": relative_path,
            "evidence_bundle": evidence,
        },
        indent=2,
        ensure_ascii=False,
    )
    return system_prompt, user_prompt


def _extract_sampling_text(result: Any) -> str:
    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if isinstance(content, TextContent):
        return content.text
    if isinstance(content, dict) and content.get("type") == "text":
        return str(content.get("text", ""))
    if hasattr(content, "text"):
        return str(content.text)
    return str(content or "")


def _parse_sampling_json(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        candidate = "\n".join(lines).strip()
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


async def _ctx_info(ctx: Context | None, message: str) -> None:
    if ctx is None:
        return
    try:
        await ctx.info(message)
    except Exception:
        return


if __name__ == "__main__":
    raise SystemExit(main())
