from __future__ import annotations

import csv
from datetime import UTC, datetime
import io
import importlib.metadata
import json
import platform
import sysconfig
import sys
import subprocess
import time
from pathlib import Path

from ..tooling import resolve_tool_path, run_command
from ..utils import ensure_dir, sanitize_text
from .base import Analyzer


class RuntimeTraceAnalyzer(Analyzer):
    name = "Runtime tracing"

    def analyze(self, context, report) -> None:
        settings = context.runtime_trace_settings
        if not settings.enabled:
            return
        if not self._is_launchable_target(context):
            report.add_note("Runtime tracing is currently supported for launchable file targets only.")
            return

        trace_dir = ensure_dir(context.output_dir / "runtime_trace")
        observation = self._observe_process(context, trace_dir)
        observation_path = trace_dir / "observation.json"
        observation_path.write_text(json.dumps(observation, indent=2), encoding="utf-8")
        report.add_artifact(str(observation_path), "runtime", "Runtime observation manifest")

        if observation.get("stdout_path"):
            report.add_artifact(str(observation["stdout_path"]), "runtime", "Runtime stdout capture")
        if observation.get("stderr_path"):
            report.add_artifact(str(observation["stderr_path"]), "runtime", "Runtime stderr capture")

        self._index_observation(context, observation, observation_path)
        self._summarize_observation(report, observation)

        if settings.use_frida:
            frida_result = self._run_frida_trace(context, trace_dir)
            if frida_result is None:
                report.add_note("Install the Python `frida` and `frida-tools` packages to enable API-level runtime hook traces.")
            elif frida_result.get("ok") is False:
                message = str(frida_result.get("error") or "Frida helper failed")
                report.add_note(f"Frida runtime trace did not complete: {message}")
                if frida_result.get("status_path"):
                    report.add_artifact(str(frida_result["status_path"]), "runtime", "Frida helper status")
                if frida_result.get("stderr"):
                    stderr_path = trace_dir / "frida_stderr.txt"
                    stderr_path.write_text(str(frida_result["stderr"]), encoding="utf-8", errors="ignore")
                    report.add_artifact(str(stderr_path), "runtime", "Frida helper stderr")
            else:
                events_path = trace_dir / "frida_events.json"
                events_path.write_text(json.dumps(frida_result, indent=2), encoding="utf-8")
                report.add_artifact(str(events_path), "runtime", "Frida runtime hook events")
                if frida_result.get("status_path"):
                    report.add_artifact(str(frida_result["status_path"]), "runtime", "Frida helper status")
                self._index_frida_events(context, frida_result, events_path)
                self._summarize_frida(report, frida_result)

    @staticmethod
    def _is_launchable_target(context) -> bool:
        return context.target.is_file() and context.target.suffix.lower() in {".exe", ".com", ".bat", ".cmd"}

    def _observe_process(self, context, trace_dir: Path) -> dict[str, object]:
        started_at = _utc_now()
        command = [str(context.target)]
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process = subprocess.Popen(
            command,
            cwd=str(context.target.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            creationflags=creationflags,
        )
        context.log(f"Runtime trace launched PID {process.pid} for {context.target}")
        child_snapshots: list[dict[str, object]] = []
        observed_children: dict[int, dict[str, object]] = {}
        deadline = time.monotonic() + max(1, int(context.runtime_trace_settings.duration_seconds))
        while time.monotonic() < deadline and process.poll() is None:
            child_processes = self._query_child_processes(process.pid)
            snapshot = {
                "timestamp": _utc_now(),
                "children": child_processes,
            }
            child_snapshots.append(snapshot)
            for child in child_processes:
                pid = int(child.get("ProcessId", 0) or 0)
                if pid:
                    observed_children[pid] = child
            time.sleep(0.75)

        timed_out = process.poll() is None
        modules = self._query_modules(process.pid) if process.poll() is None else []
        connection_pids = [process.pid, *sorted(observed_children.keys())]
        connections = self._query_connections(connection_pids)
        if timed_out:
            self._kill_process_tree(process.pid)
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self._kill_process_tree(process.pid)
            stdout, stderr = process.communicate(timeout=3)
        ended_at = _utc_now()

        stdout_path = ""
        stderr_path = ""
        if stdout.strip():
            stdout_file = trace_dir / "stdout.txt"
            stdout_file.write_text(stdout, encoding="utf-8", errors="ignore")
            stdout_path = str(stdout_file)
        if stderr.strip():
            stderr_file = trace_dir / "stderr.txt"
            stderr_file.write_text(stderr, encoding="utf-8", errors="ignore")
            stderr_path = str(stderr_file)

        return {
            "target": str(context.target),
            "command": command,
            "pid": process.pid,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": int(context.runtime_trace_settings.duration_seconds),
            "timed_out": timed_out,
            "exit_code": process.returncode,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "child_snapshots": child_snapshots,
            "children": list(observed_children.values()),
            "modules": modules,
            "connections": connections,
        }

    @staticmethod
    def _query_child_processes(parent_pid: int) -> list[dict[str, object]]:
        code, stdout, _ = run_command(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-CimInstance Win32_Process -Filter \"ParentProcessId = {parent_pid}\" | "
                    "Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress"
                ),
            ],
            timeout=20,
        )
        if code != 0 or not stdout.strip():
            return []
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    @staticmethod
    def _query_modules(pid: int) -> list[dict[str, object]]:
        code, stdout, _ = run_command(
            ["tasklist", "/FI", f"PID eq {pid}", "/M", "/FO", "CSV", "/NH"],
            timeout=20,
        )
        if code != 0 or not stdout.strip():
            return []
        reader = csv.reader(io.StringIO(stdout))
        modules: list[dict[str, object]] = []
        for row in reader:
            if len(row) < 3:
                continue
            if row[0].startswith("INFO:"):
                continue
            module_names = [value.strip() for value in row[2].split(",") if value.strip()]
            modules.append(
                {
                    "image_name": row[0],
                    "pid": row[1],
                    "modules": module_names,
                }
            )
        return modules

    @staticmethod
    def _query_connections(pids: list[int]) -> list[dict[str, object]]:
        pid_set = {str(pid) for pid in pids if pid}
        if not pid_set:
            return []
        results: list[dict[str, object]] = []
        for protocol in ("tcp", "udp"):
            code, stdout, _ = run_command(["netstat", "-ano", "-p", protocol], timeout=20)
            if code != 0 or not stdout.strip():
                continue
            for line in stdout.splitlines():
                parts = line.split()
                if protocol == "tcp" and len(parts) >= 5 and parts[0].upper() == "TCP":
                    pid = parts[-1]
                    if pid not in pid_set:
                        continue
                    results.append(
                        {
                            "protocol": "tcp",
                            "local_address": parts[1],
                            "remote_address": parts[2],
                            "state": parts[3],
                            "pid": pid,
                        }
                    )
                elif protocol == "udp" and len(parts) >= 4 and parts[0].upper() == "UDP":
                    pid = parts[-1]
                    if pid not in pid_set:
                        continue
                    results.append(
                        {
                            "protocol": "udp",
                            "local_address": parts[1],
                            "remote_address": parts[2],
                            "pid": pid,
                        }
                    )
        return results

    @staticmethod
    def _kill_process_tree(pid: int) -> None:
        run_command(["taskkill", "/PID", str(pid), "/T", "/F"], timeout=30)

    def _run_frida_trace(self, context, trace_dir: Path) -> dict[str, object] | None:
        frida_info = _select_frida_runtime(context)
        if frida_info is None:
            return None
        output_path = trace_dir / "frida_events.json"
        status_path = trace_dir / "frida_status.json"
        helper_path = Path(__file__).resolve().parents[1] / "frida_runner.py"
        command = [
            frida_info["python"],
            str(helper_path),
            "--target",
            str(context.target),
            "--output",
            str(output_path),
            "--status",
            str(status_path),
            "--duration",
            str(max(1, int(context.runtime_trace_settings.duration_seconds))),
        ]
        context.log(f"Frida runtime trace using {frida_info['version']} via {frida_info['python']}")
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process = subprocess.Popen(
            command,
            cwd=str(context.target.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            creationflags=creationflags,
        )
        helper_timeout = min(15, max(8, int(context.runtime_trace_settings.duration_seconds) + 4))
        try:
            stdout, stderr = process.communicate(timeout=helper_timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            self._kill_process_tree(process.pid)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            status = _load_frida_status(status_path)
            phase = status.get("phase", "unknown")
            detail = status.get("detail", "")
            return {
                "ok": False,
                "exit_code": None,
                "stdout": stdout,
                "stderr": stderr,
                "command": command,
                "status_path": str(status_path) if status_path.exists() else "",
                "error": (
                    f"Frida helper timed out after {helper_timeout} seconds "
                    f"(last phase: {phase}{'; ' + detail if detail else ''})."
                ),
            }
        if code != 0:
            status = _load_frida_status(status_path)
            phase = status.get("phase", "unknown")
            return {
                "ok": False,
                "exit_code": code,
                "stdout": stdout,
                "stderr": stderr,
                "command": command,
                "status_path": str(status_path) if status_path.exists() else "",
                "error": f"Frida helper exited with code {code} during phase {phase}.",
            }
        if not output_path.exists():
            status = _load_frida_status(status_path)
            return {
                "ok": False,
                "exit_code": code,
                "stdout": stdout,
                "stderr": stderr,
                "command": command,
                "status_path": str(status_path) if status_path.exists() else "",
                "error": "Frida helper exited without producing an events file.",
            }
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "exit_code": code,
                "stdout": stdout,
                "stderr": stderr,
                "command": command,
                "status_path": str(status_path) if status_path.exists() else "",
                "error": f"Invalid Frida helper JSON: {exc}",
            }
        if isinstance(payload, dict):
            payload.setdefault("ok", True)
            payload.setdefault("command", command)
            payload.setdefault("status_path", str(status_path) if status_path.exists() else "")
            return payload
        return {
            "ok": False,
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
            "command": command,
            "status_path": str(status_path) if status_path.exists() else "",
            "error": "Frida helper returned a non-object payload.",
        }

    def _summarize_observation(self, report, observation: dict[str, object]) -> None:
        child_count = len(observation.get("children") or [])
        module_count = sum(len(item.get("modules") or []) for item in observation.get("modules") or [])
        connection_count = len(observation.get("connections") or [])
        report.add_finding(
            "Runtime observation captured",
            "RE-Pro launched the target in a bounded runtime trace session and recorded process, module, and connection metadata.",
            severity="info",
            details=f"children={child_count}; modules={module_count}; connections={connection_count}",
        )
        if child_count:
            names = ", ".join(
                sorted(
                    {
                        str(child.get("Name", ""))
                        for child in (observation.get("children") or [])
                        if child.get("Name")
                    }
                )[:8]
            )
            if names:
                report.add_note(f"Runtime trace observed child processes: {names}.")
        if connection_count:
            endpoints = ", ".join(
                f"{entry.get('protocol')} {entry.get('remote_address')}"
                for entry in (observation.get("connections") or [])[:8]
            )
            report.add_note(f"Runtime trace observed network activity: {endpoints}.")

    def _summarize_frida(self, report, frida_result: dict[str, object]) -> None:
        events = frida_result.get("events") or []
        file_events = [event for event in events if event.get("kind") == "file" and event.get("path")]
        registry_events = [event for event in events if event.get("kind") == "registry"]
        network_events = [event for event in events if event.get("kind") == "network"]
        process_events = [event for event in events if event.get("kind") == "process"]
        module_events = [event for event in events if event.get("kind") == "module"]
        report.add_finding(
            "Frida runtime hooks captured",
            "Frida captured runtime instrumentation events, including module discovery and selected API hook activity.",
            severity="info",
            details=(
                f"events={len(events)}; modules={len(module_events)}; files={len(file_events)}; registry={len(registry_events)}; "
                f"network={len(network_events)}; process={len(process_events)}"
            ),
        )
        if file_events:
            paths = ", ".join(
                sorted({sanitize_text(str(event.get("path", ""))) for event in file_events if event.get("path")})[:6]
            )
            if paths:
                report.add_note(f"Frida observed file API activity touching: {paths}.")

    def _index_observation(self, context, observation: dict[str, object], observation_path: Path) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        artifact_id = context.analysis_index.add_entity(
            "artifact",
            str(observation_path),
            observation_path.name,
            attributes={"path": str(observation_path), "category": "runtime"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        process_id = context.analysis_index.add_entity(
            "runtime_process",
            str(observation.get("pid")),
            f"PID {observation.get('pid')}",
            attributes={
                "pid": observation.get("pid"),
                "exit_code": observation.get("exit_code"),
                "timed_out": observation.get("timed_out"),
            },
        )
        context.analysis_index.add_relation(target_id, "spawned_runtime_process", process_id)
        context.analysis_index.add_relation(process_id, "originates_from_artifact", artifact_id)
        for child in observation.get("children") or []:
            child_id = context.analysis_index.add_entity(
                "runtime_process",
                str(child.get("ProcessId")),
                str(child.get("Name") or f"PID {child.get('ProcessId')}"),
                attributes={
                    "pid": child.get("ProcessId"),
                    "name": child.get("Name"),
                    "command_line": child.get("CommandLine"),
                },
            )
            context.analysis_index.add_relation(process_id, "spawned_child_process", child_id)
        for connection in observation.get("connections") or []:
            label = f"{connection.get('protocol')} {connection.get('remote_address') or connection.get('local_address')}"
            endpoint_id = context.analysis_index.add_entity(
                "runtime_endpoint",
                f"{connection.get('protocol')}:{connection.get('remote_address')}:{connection.get('local_address')}:{connection.get('pid')}",
                label,
                attributes=connection,
            )
            context.analysis_index.add_relation(process_id, "connected_to_endpoint", endpoint_id)

    def _index_frida_events(self, context, frida_result: dict[str, object], events_path: Path) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        artifact_id = context.analysis_index.add_entity(
            "artifact",
            str(events_path),
            events_path.name,
            attributes={"path": str(events_path), "category": "runtime"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        for index, event in enumerate(frida_result.get("events") or []):
            kind = str(event.get("kind", "event"))
            label = str(event.get("api") or event.get("path") or event.get("subKey") or event.get("valueName") or kind)
            key = f"{kind}:{index}:{label}"
            event_id = context.analysis_index.add_entity(
                "runtime_api",
                key,
                label,
                attributes=event,
            )
            context.analysis_index.add_relation(artifact_id, "records_runtime_event", event_id)
            context.analysis_index.add_relation(target_id, "observed_runtime_event", event_id)
            if kind == "file" and event.get("path"):
                path = sanitize_text(str(event.get("path")))
                file_id = context.analysis_index.add_entity("runtime_file", path.lower(), path, attributes={"path": path})
                context.analysis_index.add_relation(event_id, "touches_runtime_file", file_id)
            elif kind == "registry":
                path = sanitize_text(str(event.get("subKey") or event.get("valueName") or "registry"))
                reg_id = context.analysis_index.add_entity("runtime_registry", path.lower(), path, attributes={"path": path})
                context.analysis_index.add_relation(event_id, "touches_runtime_registry", reg_id)
            elif kind == "network":
                endpoint_id = context.analysis_index.add_entity("runtime_endpoint", f"frida:{index}", label, attributes=event)
                context.analysis_index.add_relation(event_id, "touches_runtime_endpoint", endpoint_id)


def _select_frida_runtime(context) -> dict[str, str] | None:
    host_machine = platform.machine().upper()
    current_platform = sysconfig.get_platform().lower()
    target_machine = str((context.pe_metadata or {}).get("machine", "")).upper()

    preferred_runtime = sys.executable
    if host_machine == "ARM64" and current_platform != "win-arm64":
        sidecar = resolve_tool_path("python-arm64", extra_patterns=["python-arm64/python.exe", "python-arm64*/python.exe"])
        if target_machine == "ARM64":
            if not sidecar:
                return None
            preferred_runtime = sidecar
        elif sidecar:
            preferred_runtime = sidecar

    return _probe_frida_runtime(preferred_runtime)


def _probe_frida_runtime(python_runtime: str) -> dict[str, str] | None:
    if python_runtime == sys.executable:
        try:
            version = importlib.metadata.version("frida")
        except Exception:
            return None
        return {"version": version, "python": python_runtime, "platform": sysconfig.get_platform()}
    command = [
        python_runtime,
        "-c",
        (
            "import importlib.metadata, json, sysconfig; "
            "print(json.dumps({'version': importlib.metadata.version('frida'), 'platform': sysconfig.get_platform()}))"
        ),
    ]
    process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
    if process.returncode != 0:
        return None
    try:
        payload = json.loads(process.stdout.strip())
    except json.JSONDecodeError:
        return None
    version = str(payload.get("version", "")).strip()
    platform_tag = str(payload.get("platform", "")).strip()
    if not version:
        return None
    return {"version": version, "python": python_runtime, "platform": platform_tag}


def _load_frida_status(status_path: Path) -> dict[str, object]:
    if not status_path.exists():
        return {}
    try:
        payload = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
