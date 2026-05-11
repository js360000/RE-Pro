from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from .background_launch import build_re_pro_background_command, build_re_pro_background_env
from .utils import ensure_dir


def build_mcp_launch_details(
    *,
    workspace_root: str | Path,
    output_root: str | Path,
    tools_root: str | Path,
    transport: str = "streamable-http",
    host: str = "127.0.0.1",
    port: int = 8000,
    plugin_dirs: list[str | Path] | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace_root).resolve()
    output = Path(output_root).resolve()
    tools = Path(tools_root).resolve()
    plugins = [str(Path(path).resolve()) for path in (plugin_dirs or [])]
    command = build_re_pro_background_command(
        "mcp-server",
        "--transport",
        transport,
        "--host",
        host,
        "--port",
        str(port),
        "--workspace-root",
        str(workspace),
        "--output-root",
        str(output),
        "--tools-root",
        str(tools),
    )
    for plugin_dir in plugins:
        command.extend(["--plugin-dir", plugin_dir])

    server_name = "re-pro"
    details: dict[str, Any] = {
        "server_name": server_name,
        "transport": transport,
        "host": host,
        "port": port,
        "workspace_root": str(workspace),
        "output_root": str(output),
        "tools_root": str(tools),
        "plugin_dirs": plugins,
        "command": command,
    }
    if transport == "stdio":
        server_config: dict[str, Any] = {
            "command": command[0],
            "args": command[1:],
        }
        if not getattr(sys, "frozen", False):
            server_config["env"] = {
                "PYTHONPATH": str((Path(__file__).resolve().parents[2] / "src").resolve()),
            }
        details["client_config"] = {
            "mcpServers": {
                server_name: server_config
            }
        }
        details["notes"] = [
            "Use this JSON in clients that launch MCP servers over stdio.",
            "Do not run stdio MCP servers in a terminal where stdout is used for human logs.",
        ]
    else:
        url_path = "/mcp" if transport == "streamable-http" else "/sse"
        details["url"] = f"http://{host}:{port}{url_path}"
        details["client_config"] = {
            "mcpServers": {
                server_name: {
                    "url": details["url"],
                    "transport": transport,
                }
            }
        }
        details["notes"] = [
            "Start the server first, then add this JSON or URL to the MCP-capable client.",
            "HTTP transports are preferred for launching from the GUI because logs stay separate from protocol traffic.",
        ]
    return details


def start_mcp_server_process(
    *,
    workspace_root: str | Path,
    output_root: str | Path,
    tools_root: str | Path,
    transport: str = "streamable-http",
    host: str = "127.0.0.1",
    port: int = 8000,
    plugin_dirs: list[str | Path] | None = None,
    log_dir: str | Path | None = None,
) -> dict[str, Any]:
    if transport == "stdio":
        raise ValueError("Detached MCP startup does not support stdio. Use streamable-http or sse for GUI/CLI background launch.")
    details = build_mcp_launch_details(
        workspace_root=workspace_root,
        output_root=output_root,
        tools_root=tools_root,
        transport=transport,
        host=host,
        port=port,
        plugin_dirs=plugin_dirs,
    )
    destination = ensure_dir(Path(log_dir).resolve() if log_dir else Path(output_root).resolve() / "mcp_server")
    log_path = destination / "mcp_server.log"
    config_path = destination / "mcp_client_config.json"
    config_path.write_text(json.dumps(details["client_config"], indent=2), encoding="utf-8")

    env = build_re_pro_background_env()
    log_handle = log_path.open("a", encoding="utf-8")
    process = subprocess.Popen(
        details["command"],
        cwd=str(Path(workspace_root).resolve()),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    log_handle.close()
    details.update(
        {
            "pid": process.pid,
            "log_path": str(log_path),
            "client_config_path": str(config_path),
            "state": "running",
        }
    )
    return details


def stop_mcp_server_process(pid: int) -> dict[str, Any]:
    if pid <= 0:
        return {"ok": False, "error": "Invalid MCP server PID."}
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return {
                "ok": result.returncode == 0,
                "pid": pid,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        os.kill(pid, signal.SIGTERM)
        return {"ok": True, "pid": pid}
    except Exception as exc:
        return {"ok": False, "pid": pid, "error": str(exc)}
