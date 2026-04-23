from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .analysis_diff import compare_analysis_runs
from .dependency_installer import DependencyInstaller
from .engine import ReverseEngineeringEngine
from .llm_assist import run_llm_assist_job
from .mcp_server import main as mcp_server_main
from .models import LlmAssistSettings
from .models import RuntimeTraceSettings
from .tooling import resolve_command, run_command_logged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="re-pro", description="Reverse-engineering analysis workbench")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a file or directory")
    analyze.add_argument("target", help="Executable or app directory to analyze")
    analyze.add_argument("-o", "--output", default="analysis_output", help="Output root directory")
    analyze.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load (.py plugins)")
    analyze.add_argument("--json", action="store_true", help="Print the final JSON report to stdout")
    analyze.add_argument("--external-tools", action="store_true", help="Run installed rizin/radare2 export passes")
    analyze.add_argument("--ghidra", action="store_true", help="Run the slower Ghidra headless import/export step")
    analyze.add_argument("--llm", action="store_true", help="Run GPT-5.4-assisted reconstruction")
    analyze.add_argument("--llm-auto", action="store_true", help="Auto-trigger GPT-assisted reconstruction only when source recovery is weak")
    analyze.add_argument("--llm-model", default="gpt-5.4", help="Model ID for LLM-assisted reconstruction")
    analyze.add_argument("--llm-reasoning", default="high", help="Reasoning effort: none, low, medium, high, xhigh")
    analyze.add_argument("--llm-verbosity", default="medium", help="Text verbosity: low, medium, high")
    analyze.add_argument("--llm-background", action="store_true", help="Run the GPT-assisted reconstruction in a detached background job")
    analyze.add_argument("--llm-max-output", type=int, default=12000, help="Maximum output tokens for the GPT-assisted pass")
    analyze.add_argument("--llm-task", default="", help="Optional operator steering prompt for the GPT-assisted pass")
    analyze.add_argument("--llm-no-install", action="store_true", help="Disallow the GPT-assisted pass from installing missing dependencies in its recompile workspace")
    analyze.add_argument("--llm-no-build-checks", action="store_true", help="Disallow the GPT-assisted pass from running validation/recompile commands")
    analyze.add_argument("--runtime-trace", action="store_true", help="Run a bounded runtime observation pass")
    analyze.add_argument("--trace-seconds", type=int, default=8, help="Maximum runtime trace duration in seconds")
    analyze.add_argument("--trace-no-frida", action="store_true", help="Disable Frida-based runtime hooks during the runtime trace pass")

    install_tools = subparsers.add_parser("install-tools", help="Download portable reverse-engineering dependencies")
    install_tools.add_argument("--tools-root", default="tools", help="Installation root for downloaded tools")

    compare_runs = subparsers.add_parser("compare-runs", help="Compare two analysis run directories")
    compare_runs.add_argument("base_run", help="Base analysis run directory")
    compare_runs.add_argument("head_run", help="Head analysis run directory")
    compare_runs.add_argument("-o", "--output", default="", help="Optional output directory for diff artifacts")
    compare_runs.add_argument("--json", action="store_true", help="Print the diff JSON to stdout")

    mcp_server = subparsers.add_parser("mcp-server", help="Run the RE-Pro MCP server")
    mcp_server.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    mcp_server.add_argument("--host", default="127.0.0.1", help="Host for HTTP-based MCP transports")
    mcp_server.add_argument("--port", type=int, default=8000, help="Port for HTTP-based MCP transports")
    mcp_server.add_argument("--workspace-root", default=".", help="Workspace root exposed by the MCP server")
    mcp_server.add_argument("--output-root", default="analysis_output", help="Default analysis output root")
    mcp_server.add_argument("--tools-root", default="tools", help="Local tooling root")
    mcp_server.add_argument("--plugin-dir", action="append", default=[], help="Additional analyzer plugin directory to load (.py plugins)")

    android_jadx_job = subparsers.add_parser("android-jadx-job", help=argparse.SUPPRESS)
    android_jadx_job.add_argument("--apk", required=True, help="APK file to decompile with JADX")
    android_jadx_job.add_argument("--output", required=True, help="Output directory for JADX artifacts")
    android_jadx_job.add_argument("--jobs", type=int, default=4, help="JADX thread count")

    llm_job = subparsers.add_parser("llm-job", help=argparse.SUPPRESS)
    llm_job.add_argument("--request", required=True, help="Path to an LLM reconstruction request.json file")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        engine = ReverseEngineeringEngine(
            output_root=Path(args.output),
            logger=print,
            run_external_tools=args.external_tools or args.ghidra,
            run_ghidra=args.ghidra,
            plugin_dirs=args.plugin_dir,
            llm_settings=LlmAssistSettings(
                enabled=args.llm,
                auto=args.llm_auto,
                model=args.llm_model,
                reasoning_effort=args.llm_reasoning,
                verbosity=args.llm_verbosity,
                background=args.llm_background,
                max_output_tokens=args.llm_max_output,
                user_task=args.llm_task,
                allow_dependency_installs=not args.llm_no_install,
                run_recompile_checks=not args.llm_no_build_checks,
            ),
            runtime_trace_settings=RuntimeTraceSettings(
                enabled=args.runtime_trace,
                duration_seconds=max(1, args.trace_seconds),
                use_frida=not args.trace_no_frida,
            ),
        )
        report = engine.analyze(args.target)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"Analysis complete: {report.output_dir}")
        return 0
    if args.command == "install-tools":
        installer = DependencyInstaller(tools_root=Path(args.tools_root), logger=print)
        result = installer.install_all()
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "compare-runs":
        output_dir = Path(args.output).resolve() if args.output else None
        diff = compare_analysis_runs(Path(args.base_run), Path(args.head_run), output_dir)
        if args.json or output_dir is None:
            print(json.dumps(diff, indent=2))
        else:
            print(f"Analysis diff written to {output_dir}")
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
    if args.command == "android-jadx-job":
        return _run_android_jadx_job(Path(args.apk), Path(args.output), args.jobs)
    if args.command == "llm-job":
        result = run_llm_assist_job(Path(args.request), logger=print)
        print(json.dumps(result, indent=2))
        return 0

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


if __name__ == "__main__":
    raise SystemExit(main())
