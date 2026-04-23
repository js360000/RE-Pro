from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import time
from pathlib import Path


FRIDA_TRACE_SCRIPT = r"""
function sendEvent(payload) {
  send(payload);
}

function ptrUtf16(value) {
  try {
    if (value.isNull()) return null;
    return value.readUtf16String();
  } catch (_) {
    return null;
  }
}

function ptrUtf8(value) {
  try {
    if (value.isNull()) return null;
    return value.readUtf8String();
  } catch (_) {
    return null;
  }
}

function hookExport(moduleName, exportName, callback) {
  try {
    const address = Module.getGlobalExportByName(exportName);
    Interceptor.attach(address, {
      onEnter(args) {
        try {
          callback.call(this, args);
        } catch (e) {
          sendEvent({ kind: "hook-error", api: exportName, message: String(e) });
        }
      }
    });
    sendEvent({ kind: "hook-installed", module: moduleName, api: exportName, address: address.toString() });
  } catch (e) {
    sendEvent({ kind: "hook-failed", module: moduleName, api: exportName, message: String(e) });
  }
}

sendEvent({ kind: "script-loaded" });

setImmediate(function () {
  try {
    Process.enumerateModules().slice(0, 256).forEach(function (module) {
      sendEvent({ kind: "module", name: module.name, base: module.base.toString() });
    });
  } catch (e) {
    sendEvent({ kind: "module-enumeration-failed", message: String(e) });
  }

  hookExport("kernel32.dll", "CreateFileW", function (args) {
    sendEvent({ kind: "file", api: "CreateFileW", path: ptrUtf16(args[0]) });
  });
  hookExport("kernel32.dll", "CreateFileA", function (args) {
    sendEvent({ kind: "file", api: "CreateFileA", path: ptrUtf8(args[0]) });
  });
  hookExport("kernel32.dll", "LoadLibraryW", function (args) {
    sendEvent({ kind: "library", api: "LoadLibraryW", path: ptrUtf16(args[0]) });
  });
  hookExport("kernel32.dll", "LoadLibraryExW", function (args) {
    sendEvent({ kind: "library", api: "LoadLibraryExW", path: ptrUtf16(args[0]) });
  });
  hookExport("kernel32.dll", "CreateProcessW", function (args) {
    sendEvent({
      kind: "process",
      api: "CreateProcessW",
      application: ptrUtf16(args[0]),
      commandLine: ptrUtf16(args[1]),
    });
  });
  hookExport("advapi32.dll", "RegOpenKeyExW", function (args) {
    sendEvent({ kind: "registry", api: "RegOpenKeyExW", subKey: ptrUtf16(args[1]) });
  });
  hookExport("advapi32.dll", "RegCreateKeyExW", function (args) {
    sendEvent({ kind: "registry", api: "RegCreateKeyExW", subKey: ptrUtf16(args[1]) });
  });
  hookExport("advapi32.dll", "RegSetValueExW", function (args) {
    sendEvent({ kind: "registry", api: "RegSetValueExW", valueName: ptrUtf16(args[1]) });
  });
  hookExport("ws2_32.dll", "connect", function (_) {
    sendEvent({ kind: "network", api: "connect" });
  });
  hookExport("ws2_32.dll", "WSAConnect", function (_) {
    sendEvent({ kind: "network", api: "WSAConnect" });
  });
});
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="re-pro-frida-runner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--status", required=False, default="")
    parser.add_argument("--duration", type=int, default=5)
    args = parser.parse_args(argv)

    target = Path(args.target).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    status = Path(args.status).resolve() if args.status else None
    if status is not None:
        status.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []

    def on_message(message, data) -> None:
        del data
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            events.append(message["payload"])
        else:
            errors.append({"message": message})

    try:
        _write_status(status, phase="importing", detail="Importing frida bindings")
        import frida  # type: ignore

        _write_status(status, phase="device", detail="Acquiring local Frida device")
        device = frida.get_local_device()
        _write_status(status, phase="spawn", detail=str(target))
        pid = device.spawn([str(target)])
        _write_status(status, phase="attach", detail=f"Attaching to PID {pid}")
        session = device.attach(pid)
        _write_status(status, phase="script", detail="Creating Frida script")
        script = session.create_script(FRIDA_TRACE_SCRIPT)
        script.on("message", on_message)
        started_at = _utc_now()
        _write_status(status, phase="load", detail="Loading Frida script")
        script.load()
        _write_status(status, phase="resume", detail=f"Resuming PID {pid}")
        device.resume(pid)
        _write_status(status, phase="observe", detail=f"Sleeping for {max(1, int(args.duration))} seconds")
        time.sleep(max(1, int(args.duration)))
        try:
            _write_status(status, phase="kill", detail=f"Stopping PID {pid}")
            device.kill(pid)
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        payload = {
            "target": str(target),
            "pid": pid,
            "started_at": started_at,
            "ended_at": _utc_now(),
            "events": events,
            "errors": errors,
        }
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _write_status(status, phase="completed", detail=f"Captured {len(events)} event(s)")
        return 0
    except Exception as exc:
        error_payload = {
            "target": str(target),
            "ok": False,
            "ended_at": _utc_now(),
            "events": events,
            "errors": errors + [{"message": str(exc)}],
        }
        output.write_text(json.dumps(error_payload, indent=2), encoding="utf-8")
        _write_status(status, phase="failed", detail=str(exc))
        return 1


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_status(path: Path | None, *, phase: str, detail: str = "") -> None:
    if path is None:
        return
    payload = {
        "updated_at": _utc_now(),
        "phase": phase,
        "detail": detail,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
