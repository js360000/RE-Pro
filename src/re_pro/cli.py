from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .analysis_diff import compare_analysis_runs, create_patch_bundle_from_runs
from .analyzers.external_tools import ExternalToolAnalyzer
from .analyzers.porting import generate_architecture_port_from_run
from .dependency_installer import DependencyInstaller
from .engine import ReverseEngineeringEngine
from .fixture_regression import run_msvc_fixture_regression
from .live_process import capture_live_process
from .live_process import list_live_processes
from .live_process import resolve_live_process
from .llm_assist import run_llm_assist_job
from .mcp_launch import build_mcp_launch_details
from .mcp_launch import start_mcp_server_process
from .mcp_server import main as mcp_server_main
from .models import LlmAssistSettings
from .models import FrontendSettings
from .models import LiveProcessSettings
from .models import PortingSettings
from .models import RuntimeTraceSettings
from .profiles import analysis_settings_from_profile
from .profiles import build_analysis_profile
from .profiles import build_package_action_profile
from .profiles import list_profiles
from .profiles import load_profile
from .profiles import package_settings_from_profile
from .profiles import save_profile
from .recompile import run_packaging_action
from .tooling import resolve_command, run_command_logged
from .workspace_browser import build_browser_workspace
from .workspace_browser import list_browser_nodes
from .workspace_browser import patch_browser_node_bytes
from .workspace_browser import read_browser_node
from .workspace_browser import write_browser_node


DEFAULT_OUTPUT_ROOT = "analysis_output"
DEFAULT_TOOLS_ROOT = "tools"
DEFAULT_LLM_MODEL = "gpt-5.4"
DEFAULT_LLM_AUTH_PROVIDER = "auto"
DEFAULT_LLM_REASONING = "high"
DEFAULT_LLM_VERBOSITY = "medium"
DEFAULT_LLM_MAX_OUTPUT = 12000
DEFAULT_TRACE_SECONDS = 8


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="re-pro", description="Reverse-engineering analysis workbench")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a file or directory")
    analyze.add_argument("target", nargs="?", help="Executable or app directory to analyze")
    analyze.add_argument("-o", "--output", default=DEFAULT_OUTPUT_ROOT, help="Output root directory")
    analyze.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load (.py plugins)")
    analyze.add_argument("--json", action="store_true", help="Print the final JSON report to stdout")
    analyze.add_argument("--external-tools", action="store_true", help="Run installed rizin/radare2 export passes")
    analyze.add_argument("--ghidra", action="store_true", help="Run the slower Ghidra headless import/export step")
    analyze.add_argument("--beautify-frontend", action="store_true", help="When source maps are absent, emit best-effort beautified JS/CSS/HTML bundle sources")
    analyze.add_argument("--profile", default="", help="Load analysis settings from a saved JSON profile or profile id")
    analyze.add_argument("--save-profile", default="", help="Optional friendly profile name for saving this analysis run")
    analyze.add_argument("--profiles-root", default="profiles", help="Directory used to save and search JSON profiles")
    analyze.add_argument("--llm", action="store_true", help="Run LLM-assisted reconstruction")
    analyze.add_argument("--llm-auto", action="store_true", help="Auto-trigger LLM-assisted reconstruction only when source recovery is weak")
    analyze.add_argument("--llm-model", default=DEFAULT_LLM_MODEL, help="Model ID for LLM-assisted reconstruction")
    analyze.add_argument("--llm-auth", choices=["auto", "api-key", "codex-oauth"], default=DEFAULT_LLM_AUTH_PROVIDER, help="LLM auth source: OPENAI_API_KEY, Codex .codex/auth.json OAuth token, or auto")
    analyze.add_argument("--codex-auth-json", default="", help="Path to Codex OAuth auth.json; defaults to CODEX_AUTH_JSON, CODEX_HOME/auth.json, or ~/.codex/auth.json")
    analyze.add_argument("--llm-reasoning", default=DEFAULT_LLM_REASONING, help="Reasoning effort: none, low, medium, high, xhigh")
    analyze.add_argument("--llm-verbosity", default=DEFAULT_LLM_VERBOSITY, help="Text verbosity: low, medium, high")
    analyze.add_argument("--llm-background", action="store_true", help="Run the GPT-assisted reconstruction in a detached background job")
    analyze.add_argument("--llm-max-output", type=int, default=DEFAULT_LLM_MAX_OUTPUT, help="Maximum output tokens for the GPT-assisted pass")
    analyze.add_argument("--llm-task", default="", help="Optional operator steering prompt for the GPT-assisted pass")
    analyze.add_argument("--llm-no-install", action="store_true", help="Disallow the GPT-assisted pass from installing missing dependencies in its recompile workspace")
    analyze.add_argument("--llm-no-build-checks", action="store_true", help="Disallow the GPT-assisted pass from running validation/recompile commands")
    analyze.add_argument("--runtime-trace", action="store_true", help="Run a bounded runtime observation pass")
    analyze.add_argument("--trace-seconds", type=int, default=DEFAULT_TRACE_SECONDS, help="Maximum runtime trace duration in seconds")
    analyze.add_argument("--trace-no-frida", action="store_true", help="Disable Frida-based runtime hooks during the runtime trace pass")
    analyze.add_argument("--live-attach", action="store_true", help="Attach to an already-running local process and analyze materialized runtime memory")
    analyze.add_argument("--live-pid", type=int, default=0, help="PID to attach for live-process analysis")
    analyze.add_argument("--live-process-name", default="", help="Process name to attach when --live-pid is not supplied, e.g. pcsx2-qt.exe")
    analyze.add_argument("--live-no-memory", action="store_true", help="Record live process metadata without dumping readable memory regions")
    analyze.add_argument("--live-max-region-mb", type=int, default=8, help="Maximum bytes per memory region dump, in MiB")
    analyze.add_argument("--live-max-total-mb", type=int, default=256, help="Maximum total live memory dump bytes, in MiB")
    analyze.add_argument("--live-include-images", action="store_true", help="Also dump mapped image regions from the live process")
    analyze.add_argument("--live-all-readable", action="store_true", help="Dump all readable committed regions up to configured limits")
    analyze.add_argument("--port", action="store_true", help="Generate architecture-porting output even without a target architecture")
    analyze.add_argument("--port-source-arch", default="", help="Known source architecture, e.g. x86_64")
    analyze.add_argument("--port-target-arch", default="", help="Desired target architecture/source port, e.g. arm64")
    analyze.add_argument("--port-mode", choices=["heuristic", "llm", "hybrid"], default="", help="Architecture porting mode")

    install_tools = subparsers.add_parser("install-tools", help="Download portable reverse-engineering dependencies")
    install_tools.add_argument("--tools-root", default=DEFAULT_TOOLS_ROOT, help="Installation root for downloaded tools")

    compare_runs = subparsers.add_parser("compare-runs", help="Compare two analysis run directories")
    compare_runs.add_argument("base_run", help="Base analysis run directory")
    compare_runs.add_argument("head_run", help="Head analysis run directory")
    compare_runs.add_argument("-o", "--output", default="", help="Optional output directory for diff artifacts")
    compare_runs.add_argument("--json", action="store_true", help="Print the diff JSON to stdout")

    create_patch_bundle = subparsers.add_parser("create-patch-bundle", help="Create a patch bundle from two analysis runs")
    create_patch_bundle.add_argument("base_run", help="Base analysis run directory")
    create_patch_bundle.add_argument("head_run", help="Head analysis run directory")
    create_patch_bundle.add_argument("-o", "--output", required=True, help="Output directory for the patch bundle")

    live_process = subparsers.add_parser("live-process", help="List or capture already-running local processes")
    live_subparsers = live_process.add_subparsers(dest="live_command", required=True)
    live_list = live_subparsers.add_parser("list", help="List running processes visible to RE-Pro")
    live_list.add_argument("--query", default="", help="Optional process name/path/command line filter")
    live_list.add_argument("--limit", type=int, default=100)
    live_list.add_argument("--json", action="store_true")
    live_capture = live_subparsers.add_parser("capture", help="Capture modules, memory metadata, dumps, and carved payloads from a running process")
    live_capture.add_argument("-o", "--output", default="analysis_output/live_process_capture", help="Output directory for the live capture")
    live_capture.add_argument("--pid", type=int, default=0, help="PID to attach")
    live_capture.add_argument("--process-name", default="", help="Process name to attach if PID is not supplied")
    live_capture.add_argument("--no-memory", action="store_true", help="Do not dump readable memory regions")
    live_capture.add_argument("--max-region-mb", type=int, default=8)
    live_capture.add_argument("--max-total-mb", type=int, default=256)
    live_capture.add_argument("--include-images", action="store_true")
    live_capture.add_argument("--all-readable", action="store_true")
    live_capture.add_argument("--json", action="store_true")

    browse = subparsers.add_parser("browse", help="Build, inspect, and edit a source-first browser workspace for an analysis run")
    browse_subparsers = browse.add_subparsers(dest="browse_command", required=True)
    browse_build = browse_subparsers.add_parser("build", help="Build or refresh the browser workspace and list nodes")
    browse_build.add_argument("run_output_dir", help="Existing analysis run output directory")
    browse_build.add_argument("--json", action="store_true", help="Print the full browser manifest")
    browse_build.add_argument("--rebuild", action="store_true", help="Force manifest regeneration")
    browse_read = browse_subparsers.add_parser("read", help="Read one browser node as text, JSON, hex, or base64")
    browse_read.add_argument("run_output_dir", help="Existing analysis run output directory")
    browse_read.add_argument("node_id", help="Browser node id, e.g. node_00001")
    browse_read.add_argument("--mode", choices=["auto", "text", "json", "hex", "base64"], default="auto")
    browse_read.add_argument("--offset", type=int, default=0, help="Byte offset for hex/base64 reads")
    browse_read.add_argument("--max-bytes", type=int, default=65536, help="Maximum bytes to return")
    browse_read.add_argument("--json", action="store_true", help="Print structured read result")
    browse_write = browse_subparsers.add_parser("write", help="Overwrite an editable browser node")
    browse_write.add_argument("run_output_dir", help="Existing analysis run output directory")
    browse_write.add_argument("node_id", help="Browser node id")
    browse_write.add_argument("--mode", choices=["text", "json", "hex", "base64"], default="text")
    browse_write.add_argument("--content", default="", help="Inline replacement content")
    browse_write.add_argument("--content-file", default="", help="File containing replacement content")
    browse_patch = browse_subparsers.add_parser("patch", help="Patch bytes into an editable browser node")
    browse_patch.add_argument("run_output_dir", help="Existing analysis run output directory")
    browse_patch.add_argument("node_id", help="Browser node id")
    browse_patch.add_argument("--offset", type=int, required=True, help="Byte offset to patch")
    browse_patch.add_argument("--hex", required=True, help="Hex bytes to write, e.g. '90 90'")

    architecture_port = subparsers.add_parser("architecture-port", help="Generate a target-architecture source port from an existing run")
    architecture_port.add_argument("run_output_dir", help="Existing analysis run output directory")
    architecture_port.add_argument("--source-arch", default="", help="Known source architecture, e.g. x86_64")
    architecture_port.add_argument("--target-arch", default="arm64", help="Desired target architecture, e.g. arm64")
    architecture_port.add_argument("--mode", choices=["heuristic", "llm", "hybrid"], default="heuristic", help="Port generation mode")
    architecture_port.add_argument("--json", action="store_true", help="Print machine-readable result")

    package_action = subparsers.add_parser("package-action", help="Run a rebuild, repack, signing, or patch action")
    package_action.add_argument("--workspace-root", default="", help="Recompile workspace root")
    package_action.add_argument("--ecosystem", default="", help="Packaging ecosystem: android-gradle, electron, tauri, archive, patch")
    package_action.add_argument("--action", default="", help="Action name such as repack, sign-apk, or apply-bundle")
    package_action.add_argument("--artifact-path", default="", help="Artifact path for signing/repacking actions")
    package_action.add_argument("--output-path", default="", help="Output artifact path for packaging actions that create or rebuild files")
    package_action.add_argument("--keystore-path", default="", help="Keystore path for Android signing")
    package_action.add_argument("--key-alias", default="", help="Key alias for Android signing")
    package_action.add_argument("--store-pass", default="", help="Store password for Android signing")
    package_action.add_argument("--key-pass", default="", help="Key password for Android signing")
    package_action.add_argument("--patch-bundle-path", default="", help="Patch bundle root for patch actions")
    package_action.add_argument("--target-root", default="", help="Target root for patch actions")
    package_action.add_argument("--compression", choices=["zlib", "lzma", "none"], default="zlib", help="Archive compression for create-psarc")
    package_action.add_argument("--compression-level", type=int, default=9, help="Archive compression level for create-psarc")
    package_action.add_argument("--block-size", type=lambda value: int(value, 0), default=0x10000, help="PSARC block size for create-psarc")
    package_action.add_argument("--profile", default="", help="Load package action settings from a saved JSON profile or profile id")
    package_action.add_argument("--save-profile", default="", help="Optional friendly profile name for saving this package action")
    package_action.add_argument("--profiles-root", default="profiles", help="Directory used to save and search JSON profiles")

    profiles = subparsers.add_parser("profiles", help="List, search, and inspect saved JSON profiles")
    profiles_subparsers = profiles.add_subparsers(dest="profiles_command", required=True)
    profiles_list = profiles_subparsers.add_parser("list", help="List saved profiles")
    profiles_list.add_argument("--query", default="", help="Optional free-text search query")
    profiles_list.add_argument("--kind", default="", help="Optional profile type filter: analysis or package_action")
    profiles_list.add_argument("--profiles-root", default="profiles", help="Directory used to save and search JSON profiles")
    profiles_list.add_argument("--json", action="store_true", help="Print the profile list as JSON")
    profiles_show = profiles_subparsers.add_parser("show", help="Show one saved profile")
    profiles_show.add_argument("profile", help="Profile path, id, or name")
    profiles_show.add_argument("--profiles-root", default="profiles", help="Directory used to save and search JSON profiles")

    mcp_server = subparsers.add_parser("mcp-server", help="Run the RE-Pro MCP server")
    mcp_server.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    mcp_server.add_argument("--host", default="127.0.0.1", help="Host for HTTP-based MCP transports")
    mcp_server.add_argument("--port", type=int, default=8000, help="Port for HTTP-based MCP transports")
    mcp_server.add_argument("--workspace-root", default=".", help="Workspace root exposed by the MCP server")
    mcp_server.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT, help="Default analysis output root")
    mcp_server.add_argument("--tools-root", default=DEFAULT_TOOLS_ROOT, help="Local tooling root")
    mcp_server.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load (.py plugins)")

    mcp_info = subparsers.add_parser("mcp-info", help="Show MCP launch details and exact client JSON")
    mcp_info.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="streamable-http")
    mcp_info.add_argument("--host", default="127.0.0.1", help="Host for HTTP-based MCP transports")
    mcp_info.add_argument("--port", type=int, default=8000, help="Port for HTTP-based MCP transports")
    mcp_info.add_argument("--workspace-root", default=".", help="Workspace root exposed by the MCP server")
    mcp_info.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT, help="Default analysis output root")
    mcp_info.add_argument("--tools-root", default=DEFAULT_TOOLS_ROOT, help="Local tooling root")
    mcp_info.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load (.py plugins)")
    mcp_info.add_argument("--start", action="store_true", help="Start the MCP server in the background and print connection details")
    mcp_info.add_argument("--client-json-only", action="store_true", help="Print only the JSON block used by MCP-capable clients")
    mcp_info.add_argument("--json", action="store_true", help="Print machine-readable launch details")

    android_jadx_job = subparsers.add_parser("android-jadx-job", help=argparse.SUPPRESS)
    android_jadx_job.add_argument("--apk", required=True, help="APK file to decompile with JADX")
    android_jadx_job.add_argument("--output", required=True, help="Output directory for JADX artifacts")
    android_jadx_job.add_argument("--jobs", type=int, default=4, help="JADX thread count")

    llm_job = subparsers.add_parser("llm-job", help=argparse.SUPPRESS)
    llm_job.add_argument("--request", required=True, help="Path to an LLM reconstruction request.json file")

    external_tool_job = subparsers.add_parser("external-tool-job", help=argparse.SUPPRESS)
    external_tool_job.add_argument("--request", required=True, help="Path to an external tool background request.json file")

    fixture_regression = subparsers.add_parser("fixture-regression", help="Build and validate the MSVC fixture regression target")
    fixture_regression.add_argument("--output-root", default="analysis_output/fixture_regression", help="Output root for fixture analysis runs")
    fixture_regression.add_argument("--no-ghidra", action="store_true", help="Skip Ghidra and validate only the native RTTI/PDB path")
    fixture_regression.add_argument("--timeout", type=int, default=300, help="Maximum seconds to wait for async fixture jobs")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        profile = _load_profile_if_requested(args.profile, args.profiles_root, expected_type="analysis")
        profile_settings = analysis_settings_from_profile(profile) if profile else {}
        target = args.target or str(profile_settings.get("target", ""))
        output_root = _merge_value(args.output, DEFAULT_OUTPUT_ROOT, profile_settings.get("output_root", DEFAULT_OUTPUT_ROOT))
        plugin_dirs = args.plugin_dir or list(profile_settings.get("plugin_dirs") or [])
        llm_profile = profile_settings.get("llm_settings") if profile_settings else LlmAssistSettings()
        porting_profile = profile_settings.get("porting_settings") if profile_settings else PortingSettings()
        runtime_profile = profile_settings.get("runtime_trace_settings") if profile_settings else RuntimeTraceSettings()
        live_profile = profile_settings.get("live_process_settings") if profile_settings else LiveProcessSettings()
        frontend_profile = profile_settings.get("frontend_settings") if profile_settings else FrontendSettings()
        live_process_settings = LiveProcessSettings(
            enabled=bool(args.live_attach or args.live_pid or args.live_process_name or live_profile.enabled),
            pid=int(args.live_pid or live_profile.pid),
            process_name=_merge_value(args.live_process_name, "", live_profile.process_name),
            dump_memory=False if args.live_no_memory else live_profile.dump_memory,
            max_region_bytes=max(4096, int(_merge_value(args.live_max_region_mb, 8, live_profile.max_region_bytes // (1024 * 1024))) * 1024 * 1024),
            max_total_bytes=max(4096, int(_merge_value(args.live_max_total_mb, 256, live_profile.max_total_bytes // (1024 * 1024))) * 1024 * 1024),
            include_mapped_images=bool(args.live_include_images or live_profile.include_mapped_images),
            include_all_readable=bool(args.live_all_readable or live_profile.include_all_readable),
        )
        if not target and live_process_settings.enabled:
            process = resolve_live_process(pid=live_process_settings.pid, process_name=live_process_settings.process_name)
            target = str(process.get("executable_path") or Path.cwd())
        if not target:
            parser.error("analyze requires a target path or --profile with a saved target")
        run_ghidra = bool(args.ghidra or profile_settings.get("run_ghidra", False))
        run_external_tools = bool(args.external_tools or profile_settings.get("run_external_tools", False) or run_ghidra)
        llm_settings = LlmAssistSettings(
            enabled=bool(args.llm or llm_profile.enabled),
            auto=bool(args.llm_auto or llm_profile.auto),
            model=_merge_value(args.llm_model, DEFAULT_LLM_MODEL, llm_profile.model),
            auth_provider=_merge_value(args.llm_auth, DEFAULT_LLM_AUTH_PROVIDER, llm_profile.auth_provider),
            codex_auth_path=_merge_value(args.codex_auth_json, "", llm_profile.codex_auth_path),
            reasoning_effort=_merge_value(args.llm_reasoning, DEFAULT_LLM_REASONING, llm_profile.reasoning_effort),
            verbosity=_merge_value(args.llm_verbosity, DEFAULT_LLM_VERBOSITY, llm_profile.verbosity),
            background=bool(args.llm_background or llm_profile.background),
            max_output_tokens=_merge_value(args.llm_max_output, DEFAULT_LLM_MAX_OUTPUT, llm_profile.max_output_tokens),
            user_task=_merge_value(args.llm_task, "", llm_profile.user_task),
            allow_dependency_installs=False if args.llm_no_install else llm_profile.allow_dependency_installs,
            run_recompile_checks=False if args.llm_no_build_checks else llm_profile.run_recompile_checks,
        )
        runtime_trace_settings = RuntimeTraceSettings(
            enabled=bool(args.runtime_trace or runtime_profile.enabled),
            duration_seconds=max(1, _merge_value(args.trace_seconds, DEFAULT_TRACE_SECONDS, runtime_profile.duration_seconds)),
            use_frida=False if args.trace_no_frida else runtime_profile.use_frida,
        )
        porting_settings = PortingSettings(
            enabled=bool(args.port or args.port_target_arch or porting_profile.enabled),
            source_arch=_merge_value(args.port_source_arch, "", porting_profile.source_arch),
            target_arch=_merge_value(args.port_target_arch, "", porting_profile.target_arch),
            mode=_merge_value(args.port_mode, "", porting_profile.mode) or "heuristic",
        )
        frontend_settings = FrontendSettings(
            beautify_bundles=bool(args.beautify_frontend or frontend_profile.beautify_bundles),
        )
        if porting_settings.enabled and porting_settings.target_arch:
            port_task = (
                f"Generate target-architecture porting output for {porting_settings.target_arch}. "
                f"Treat the input as {porting_settings.source_arch or 'the detected source architecture'} and produce portable, "
                "human-readable source-level equivalents rather than target-specific assembly where possible."
            )
            llm_settings.user_task = "\n\n".join(part for part in [llm_settings.user_task, port_task] if part).strip()
            if porting_settings.mode in {"llm", "hybrid"}:
                llm_settings.enabled = True
        engine = ReverseEngineeringEngine(
            output_root=Path(output_root),
            logger=print,
            run_external_tools=run_external_tools,
            run_ghidra=run_ghidra,
            plugin_dirs=plugin_dirs,
            llm_settings=llm_settings,
            porting_settings=porting_settings,
            runtime_trace_settings=runtime_trace_settings,
            live_process_settings=live_process_settings,
            frontend_settings=frontend_settings,
        )
        report = engine.analyze(target)
        profile_path = save_profile(
            build_analysis_profile(
                name=args.save_profile or (profile.get("name", "") if profile else "") or Path(target).stem,
                target=str(target),
                output_root=str(output_root),
                plugin_dirs=[str(path) for path in plugin_dirs],
                run_external_tools=run_external_tools,
                run_ghidra=run_ghidra,
                llm_settings=llm_settings,
                porting_settings=porting_settings,
                runtime_trace_settings=runtime_trace_settings,
                live_process_settings=live_process_settings,
                frontend_settings=frontend_settings,
                report=report.to_dict(),
                output_dir=report.output_dir,
            ),
            profiles_root=args.profiles_root,
        )
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"Analysis complete: {report.output_dir}")
            print(f"Profile saved: {profile_path}")
        return 0
    if args.command == "install-tools":
        installer = DependencyInstaller(tools_root=Path(args.tools_root), logger=print)
        result = installer.install_all()
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "live-process":
        if args.live_command == "list":
            processes = list_live_processes(args.query, limit=args.limit)
            if args.json:
                print(json.dumps({"processes": processes}, indent=2))
            else:
                for process in processes:
                    print(f"{process.get('pid'):>7} {process.get('name')} {process.get('executable_path')}")
            return 0
        if args.live_command == "capture":
            settings = LiveProcessSettings(
                enabled=True,
                pid=args.pid,
                process_name=args.process_name,
                dump_memory=not args.no_memory,
                max_region_bytes=max(4096, args.max_region_mb * 1024 * 1024),
                max_total_bytes=max(4096, args.max_total_mb * 1024 * 1024),
                include_mapped_images=args.include_images,
                include_all_readable=args.all_readable,
            )
            result = capture_live_process(output_dir=Path(args.output), settings=settings, logger=None if args.json else print)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                summary = result.get("summary") or {}
                print(f"Live capture written: {result.get('manifest_path')}")
                print(
                    f"PID={(result.get('process') or {}).get('pid')} "
                    f"regions={summary.get('dumped_region_count', 0)} "
                    f"carved={summary.get('carved_payload_count', 0)} "
                    f"bytes={summary.get('dumped_bytes', 0)}"
                )
            return 0
    if args.command == "compare-runs":
        output_dir = Path(args.output).resolve() if args.output else None
        diff = compare_analysis_runs(Path(args.base_run), Path(args.head_run), output_dir)
        if args.json or output_dir is None:
            print(json.dumps(diff, indent=2))
        else:
            print(f"Analysis diff written to {output_dir}")
        return 0
    if args.command == "create-patch-bundle":
        bundle = create_patch_bundle_from_runs(Path(args.base_run), Path(args.head_run), Path(args.output))
        print(json.dumps(bundle, indent=2))
        return 0
    if args.command == "browse":
        if args.browse_command == "build":
            manifest = build_browser_workspace(Path(args.run_output_dir)) if args.rebuild else list_browser_nodes(Path(args.run_output_dir))
            if args.json:
                print(json.dumps(manifest, indent=2))
            else:
                summary = manifest.get("summary") or {}
                print(f"Browser workspace: {manifest.get('workspace_root')}")
                print(
                    f"Nodes: {summary.get('node_count', 0)} | "
                    f"Editable: {summary.get('editable_count', 0)} | "
                    f"Source-like: {summary.get('source_like_count', 0)}"
                )
                for node in manifest.get("nodes", [])[:200]:
                    editable = "editable" if node.get("editable") else "read-only"
                    print(f"{node.get('id')} [{node.get('view_mode')}/{editable}] {node.get('relative_path')}")
            return 0
        if args.browse_command == "read":
            result = read_browser_node(
                Path(args.run_output_dir),
                args.node_id,
                mode=args.mode,
                offset=args.offset,
                max_bytes=args.max_bytes,
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(result.get("content", ""))
            return 0
        if args.browse_command == "write":
            if args.content_file:
                content = Path(args.content_file).read_text(encoding="utf-8", errors="ignore")
            else:
                content = args.content
            result = write_browser_node(Path(args.run_output_dir), args.node_id, content, mode=args.mode)
            print(json.dumps(result, indent=2))
            return 0
        if args.browse_command == "patch":
            result = patch_browser_node_bytes(Path(args.run_output_dir), args.node_id, args.offset, args.hex)
            print(json.dumps(result, indent=2))
            return 0
    if args.command == "architecture-port":
        result = generate_architecture_port_from_run(
            Path(args.run_output_dir),
            source_arch=args.source_arch,
            target_arch=args.target_arch,
            mode=args.mode,
            logger=None if args.json else print,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Architecture port generated: {result.get('porting_manifest_path')}")
            for architecture_port in result.get("architecture_ports") or []:
                print(
                    f"- {architecture_port.get('source_arch')} -> {architecture_port.get('target_arch')}: "
                    f"{architecture_port.get('workspace_root')}"
                )
        return 0
    if args.command == "package-action":
        profile = _load_profile_if_requested(args.profile, args.profiles_root, expected_type="package_action")
        profile_settings = package_settings_from_profile(profile) if profile else {}
        workspace_root = _merge_value(args.workspace_root, "", profile_settings.get("workspace_root", ""))
        ecosystem = _merge_value(args.ecosystem, "", profile_settings.get("ecosystem", ""))
        action = _merge_value(args.action, "", profile_settings.get("action", ""))
        artifact_path = _merge_value(args.artifact_path, "", profile_settings.get("artifact_path", ""))
        output_path = _merge_value(args.output_path, "", profile_settings.get("output_path", ""))
        keystore_path = _merge_value(args.keystore_path, "", profile_settings.get("keystore_path", ""))
        key_alias = _merge_value(args.key_alias, "", profile_settings.get("key_alias", ""))
        patch_bundle_path = _merge_value(args.patch_bundle_path, "", profile_settings.get("patch_bundle_path", ""))
        target_root = _merge_value(args.target_root, "", profile_settings.get("target_root", ""))
        compression = _merge_value(args.compression, "zlib", profile_settings.get("compression", "zlib"))
        compression_level = _merge_value(args.compression_level, 9, profile_settings.get("compression_level", 9))
        block_size = _merge_value(args.block_size, 0x10000, profile_settings.get("block_size", 0x10000))
        if not workspace_root or not ecosystem or not action:
            parser.error("package-action requires --workspace-root, --ecosystem, and --action, or --profile with those settings")
        result = run_packaging_action(
            workspace_root=Path(workspace_root),
            ecosystem=ecosystem,
            action=action,
            logger=print,
            artifact_path=artifact_path,
            keystore_path=keystore_path,
            key_alias=key_alias,
            store_pass=args.store_pass,
            key_pass=args.key_pass,
            patch_bundle_path=patch_bundle_path,
            target_root=target_root,
            output_path=output_path,
            compression=compression,
            compression_level=compression_level,
            block_size=block_size,
        )
        profile_path = save_profile(
            build_package_action_profile(
                name=args.save_profile or (profile.get("name", "") if profile else "") or f"{ecosystem}-{action}",
                workspace_root=workspace_root,
                ecosystem=ecosystem,
                action=action,
                artifact_path=artifact_path,
                output_path=output_path,
                keystore_path=keystore_path,
                key_alias=key_alias,
                patch_bundle_path=patch_bundle_path,
                target_root=target_root,
                compression=compression,
                compression_level=compression_level,
                block_size=block_size,
                result=result,
            ),
            profiles_root=args.profiles_root,
        )
        print(json.dumps(result, indent=2))
        print(f"Profile saved: {profile_path}")
        return 0 if result.get("ok") else 1
    if args.command == "profiles":
        if args.profiles_command == "list":
            entries = list_profiles(profiles_root=args.profiles_root, query=args.query, profile_type=args.kind)
            if args.json:
                print(json.dumps(entries, indent=2))
            else:
                for entry in entries:
                    print(
                        f"[{entry.get('profile_type')}] {entry.get('name')} "
                        f"({entry.get('profile_id')}) -> {entry.get('primary_target')} "
                        f"{entry.get('secondary_target')}".rstrip()
                    )
            return 0
        if args.profiles_command == "show":
            print(json.dumps(load_profile(args.profile, profiles_root=args.profiles_root), indent=2))
            return 0
    if args.command == "mcp-server":
        mcp_args = [
            "--transport",
            args.transport,
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--workspace-root",
            str(Path(args.workspace_root).resolve()),
            "--output-root",
            str(Path(args.output_root).resolve()),
            "--tools-root",
            str(Path(args.tools_root).resolve()),
        ]
        for plugin_dir in args.plugin_dir:
            mcp_args.extend(["--plugin-dir", str(Path(plugin_dir).resolve())])
        return mcp_server_main(mcp_args)
    if args.command == "mcp-info":
        if args.start and args.transport == "stdio":
            parser.error("mcp-info --start cannot use --transport stdio; use streamable-http or sse for detached launch")
        details = _mcp_launch_details_from_args(args, start=bool(args.start))
        if args.client_json_only:
            print(json.dumps(details["client_config"], indent=2))
        elif args.json:
            print(json.dumps(details, indent=2))
        else:
            print(f"MCP server: {details['server_name']}")
            print(f"Transport: {details['transport']}")
            if details.get("url"):
                print(f"URL: {details['url']}")
            if details.get("pid"):
                print(f"PID: {details['pid']}")
            if details.get("log_path"):
                print(f"Log: {details['log_path']}")
            if details.get("client_config_path"):
                print(f"Client config written: {details['client_config_path']}")
            print("Command:")
            print(" ".join(str(part) for part in details["command"]))
            print("Client JSON:")
            print(json.dumps(details["client_config"], indent=2))
        return 0
    if args.command == "android-jadx-job":
        return _run_android_jadx_job(Path(args.apk), Path(args.output), args.jobs)
    if args.command == "llm-job":
        result = run_llm_assist_job(Path(args.request), logger=print)
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "external-tool-job":
        return ExternalToolAnalyzer.run_background_job(Path(args.request))
    if args.command == "fixture-regression":
        result = run_msvc_fixture_regression(
            Path.cwd(),
            output_root=Path(args.output_root),
            use_ghidra=not args.no_ghidra,
            wait_timeout_seconds=args.timeout,
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    parser.print_help()
    return 1


def _run_android_jadx_job(apk_path: Path, output_dir: Path, jobs: int) -> int:
    from .analyzers.android import AndroidAnalyzer
    from .utils import ensure_dir

    ensure_dir(output_dir)
    ensure_dir(output_dir / "sources")
    log_path = output_dir / "jadx.log"
    status_path = output_dir / "status.json"
    command = resolve_command([["jadx"], ["jadx.bat"]])
    if command is None:
        status_path.write_text(
            json.dumps(
                {
                    "state": "failed",
                    "started_at": datetime.utcnow().isoformat() + "Z",
                    "finished_at": datetime.utcnow().isoformat() + "Z",
                    "error": "jadx was not found on PATH or in the configured local tools directory.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return 1

    started_at = datetime.utcnow().isoformat() + "Z"
    status_path.write_text(
        json.dumps(
            {
                "state": "running",
                "started_at": started_at,
                "apk": str(apk_path),
                "output_dir": str(output_dir),
                "jobs": jobs,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    def _log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    jadx_command = AndroidAnalyzer._build_jadx_command(command, apk_path, output_dir / "sources", jobs)
    code, stdout, stderr = run_command_logged(
        jadx_command,
        cwd=apk_path.parent,
        timeout=4 * 3600,
        logger=_log,
        label="jadx",
    )
    java_files = list(output_dir.rglob("*.java"))
    kotlin_files = list(output_dir.rglob("*.kt"))
    status = {
        "state": "completed" if code == 0 and (java_files or kotlin_files) else "failed",
        "started_at": started_at,
        "finished_at": datetime.utcnow().isoformat() + "Z",
        "apk": str(apk_path),
        "output_dir": str(output_dir),
        "jobs": jobs,
        "java_files": len(java_files),
        "kotlin_files": len(kotlin_files),
        "exit_code": code,
    }
    message = stderr.strip() or stdout.strip()
    if message:
        status["message"] = message[:4000]
    status_path.write_text(json.dumps(status, indent=2), encoding="utf-8")
    return 0 if status["state"] == "completed" else 1


def _merge_value(cli_value, default_value, profile_value):
    if cli_value != default_value:
        return cli_value
    return profile_value if profile_value not in {None, ""} else default_value


def _mcp_launch_details_from_args(args, *, start: bool) -> dict:
    kwargs = {
        "workspace_root": Path(args.workspace_root).resolve(),
        "output_root": Path(args.output_root).resolve(),
        "tools_root": Path(args.tools_root).resolve(),
        "transport": args.transport,
        "host": args.host,
        "port": args.port,
        "plugin_dirs": [Path(path).resolve() for path in args.plugin_dir],
    }
    if start:
        return start_mcp_server_process(**kwargs)
    return build_mcp_launch_details(**kwargs)


def _load_profile_if_requested(identifier: str, profiles_root: str, *, expected_type: str) -> dict | None:
    if not identifier.strip():
        return None
    profile = load_profile(identifier, profiles_root=profiles_root)
    profile_type = str(profile.get("profile_type", "")).strip().lower()
    if profile_type != expected_type:
        raise ValueError(f"Expected a {expected_type} profile but got {profile_type or 'unknown'}")
    return profile


if __name__ == "__main__":
    raise SystemExit(main())
