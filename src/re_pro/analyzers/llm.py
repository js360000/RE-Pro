from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from ..llm_auth import llm_auth_available
from ..llm_auth import llm_auth_missing_message
from ..llm_assist import run_llm_assist_job
from ..tooling import REPO_ROOT
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class LLMAssistAnalyzer(Analyzer):
    name = "LLM-assisted reconstruction"
    MAX_CONTEXT_ARTIFACTS = 24
    MAX_CONTEXT_CHARS = 16000
    MAX_CONTEXT_DIR_FILES = 16
    TOOL_WAIT_SECONDS = 180
    TOOL_WAIT_POLL_SECONDS = 1.0
    TOOL_TERMINAL_STATES = {"completed", "failed", "skipped", "cancelled", "timeout", "timed_out"}

    def analyze(self, context, report) -> None:
        settings = context.llm_settings
        if not settings.enabled and not settings.auto:
            return
        if not self._should_run(settings, report):
            return
        if not llm_auth_available(settings):
            report.add_note(llm_auth_missing_message(settings))
            return

        llm_dir = ensure_dir(context.output_dir / "llm_assist")
        reconstructed_root = ensure_dir(llm_dir / "reconstructed_src")
        if not settings.background:
            self._wait_for_async_tool_context(context)
        context_items = self._build_context_items(context, report, llm_dir)
        request_path = llm_dir / "request.json"
        status_path = llm_dir / "status.json"
        summary_path = llm_dir / "assistant_summary.md"
        log_path = llm_dir / "llm.log"
        request_payload = {
            "llm_dir": str(llm_dir),
            "reconstructed_root": str(reconstructed_root),
            "settings": {
                "model": settings.model,
                "auth_provider": settings.auth_provider,
                "codex_auth_path": settings.codex_auth_path,
                "reasoning_effort": settings.reasoning_effort,
                "verbosity": settings.verbosity,
                "background": settings.background,
                "max_output_tokens": settings.max_output_tokens,
                "user_task": settings.user_task,
                "allow_dependency_installs": settings.allow_dependency_installs,
                "run_recompile_checks": settings.run_recompile_checks,
                "porting_settings": context.porting_settings.to_dict(),
            },
            "report": report.to_dict(),
            "analysis_index": context.analysis_index.to_dict(),
            "context_items": context_items,
        }
        request_path.write_text(json.dumps(request_payload, indent=2), encoding="utf-8")
        report.add_artifact(str(request_path), "metadata", "LLM reconstruction request")
        report.add_artifact(str(status_path), "metadata", "LLM reconstruction status")
        report.add_artifact(str(log_path), "log", "LLM reconstruction log")
        report.add_artifact(str(reconstructed_root), "directory", "LLM reconstructed source directory")

        if settings.background:
            self._spawn_background_job(request_path, context)
            status_path.write_text(
                json.dumps(
                    {
                        "state": "queued",
                        "request_path": str(request_path),
                        "llm_dir": str(llm_dir),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            report.add_finding(
                "LLM reconstruction job started",
                f"{settings.model} reconstruction was queued in a detached background job. Monitor the status and summary artifacts for completion.",
                severity="info",
            )
            report.add_note(f"LLM reconstruction is running in the background. Status: {status_path}")
            return

        try:
            result = run_llm_assist_job(request_path, logger=context.log)
        except Exception as exc:
            report.add_finding(
                "LLM reconstruction failed",
                f"{settings.model} reconstruction failed. See the LLM log and status artifacts for details.",
                severity="warning",
                details=str(exc),
            )
            report.add_note(f"LLM reconstruction failed; status: {status_path}; log: {log_path}")
            context.log(f"LLM reconstruction failed; continuing analysis output generation: {exc}")
            if summary_path.exists():
                report.add_artifact(str(summary_path), "report", "LLM reconstruction summary")
            return

        report.add_artifact(str(summary_path), "report", "LLM reconstruction summary")
        report.add_finding(
            "LLM reconstruction completed",
            f"{settings.model} wrote {len(result.get('written_files') or [])} reconstructed file(s).",
            severity="info",
        )
        report.add_note(f"LLM reconstruction summary written to {summary_path}.")

    @staticmethod
    def _should_run(settings, report) -> bool:
        if settings.enabled:
            return True
        if not settings.auto:
            return False
        if report.recovered_sources:
            return False
        if report.target_type in {"android-package", "android-package-set", "portable-executable", "mach-o", "exe", "dll"}:
            return True
        return any(
            marker in framework.lower()
            for framework in report.frameworks
            for marker in ("native", "mach-o", "portable executable", "rust", "c/c++", "qt", ".net")
        )

    def _build_context_items(self, context, report, llm_dir: Path) -> list[dict[str, object]]:
        context_dir = ensure_dir(llm_dir / "context")
        items: list[dict[str, object]] = []

        def add_item(name: str, content: str, summary: str) -> None:
            filename = f"{safe_slug(name)}.txt" if not name.endswith(".json") else safe_slug(name)
            if not filename.endswith((".txt", ".json", ".md")):
                filename += ".txt"
            destination = context_dir / filename
            destination.write_text(content, encoding="utf-8")
            items.append(
                {
                    "name": name,
                    "path": str(destination),
                    "summary": summary,
                    "chars": len(content),
                }
            )

        add_item(
            "analysis_report.json",
            json.dumps(report.to_dict(), indent=2),
            "Current RE-Pro analysis report snapshot.",
        )
        add_item(
            "binary_context.json",
            json.dumps(
                {
                    "target": str(context.target),
                    "pe_metadata": context.pe_metadata,
                    "pe_sections": context.pe_sections,
                    "pe_imports": context.pe_imports,
                    "version_info": context.version_info,
                    "probable_binary": context.probable_binary,
                },
                indent=2,
            ),
            "Binary metadata, imports, sections, and version info.",
        )
        add_item(
            "analysis_index.json",
            json.dumps(context.analysis_index.to_dict(), indent=2),
            "Unified analysis index snapshot with normalized entities and relations collected so far.",
        )
        add_item(
            "naming_hints.json",
            json.dumps(self._build_naming_hints(context, report), indent=2),
            "Preferred filenames, classes, functions, and namespaces inferred from RTTI, symbols, recovered sources, and debug metadata.",
        )
        if context.ascii_strings:
            add_item(
                "ascii_strings_sample.txt",
                "\n".join(context.ascii_strings[:1600]),
                "Sample of extracted ASCII strings from the target binary or package head.",
            )

        added_artifacts = 0
        ordered_artifacts = sorted(enumerate(report.artifacts), key=lambda item: (self._artifact_priority(item[1]), item[0]))
        for _, artifact in ordered_artifacts:
            path = Path(artifact.path)
            if not path.exists():
                continue
            if path.is_dir():
                added_artifacts += self._add_directory_snapshot(
                    add_item,
                    path,
                    artifact.description,
                    added_artifacts,
                    max(0, self.MAX_CONTEXT_ARTIFACTS - added_artifacts),
                )
                if added_artifacts >= self.MAX_CONTEXT_ARTIFACTS:
                    break
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".txt", ".md", ".json", ".xml", ".js", ".ts", ".tsx", ".css", ".html", ".log"}:
                continue
            if added_artifacts >= self.MAX_CONTEXT_ARTIFACTS:
                break
            try:
                payload = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            add_item(
                f"artifact_{added_artifacts}_{path.name}",
                payload[: self.MAX_CONTEXT_CHARS],
                f"Artifact snapshot: {artifact.description}",
            )
            added_artifacts += 1

        index_path = llm_dir / "context_index.json"
        index_path.write_text(json.dumps(items, indent=2), encoding="utf-8")
        return items

    def _wait_for_async_tool_context(self, context) -> None:
        wait_seconds = self._tool_wait_seconds()
        if wait_seconds <= 0:
            return
        status_paths = [
            context.output_dir / "ghidra" / "status.json",
            context.output_dir / "pe_tools" / "status.json",
        ]
        pending = [path for path in status_paths if self._status_path_is_pending(path)]
        if not pending:
            return
        context.log(
            "Foreground LLM reconstruction is waiting for async RE context: "
            + ", ".join(str(path) for path in pending)
        )
        deadline = time.monotonic() + wait_seconds
        while pending and time.monotonic() < deadline:
            time.sleep(self.TOOL_WAIT_POLL_SECONDS)
            pending = [path for path in pending if self._status_path_is_pending(path)]
        if pending:
            context.log(
                "Foreground LLM reconstruction context wait timed out; continuing with available artifacts: "
                + ", ".join(str(path) for path in pending)
            )

    @classmethod
    def _tool_wait_seconds(cls) -> float:
        raw = os.environ.get("RE_PRO_LLM_CONTEXT_WAIT_SECONDS", "").strip()
        if not raw:
            return float(cls.TOOL_WAIT_SECONDS)
        try:
            return max(0.0, float(raw))
        except ValueError:
            return float(cls.TOOL_WAIT_SECONDS)

    @classmethod
    def _status_path_is_pending(cls, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            return False
        state = str(payload.get("state") or "").strip().lower()
        return state not in cls.TOOL_TERMINAL_STATES

    @staticmethod
    def _artifact_priority(artifact) -> int:
        text = f"{artifact.description} {artifact.path}".lower()
        path = Path(artifact.path)
        name = path.name.lower()
        if path.is_dir():
            if "class_pseudo_cpp" in text or "class-scoped" in text:
                return 2
            if "pseudo_cpp" in text or "pseudo-c++" in text:
                return 3
            if "pseudo_code" in text or "pseudo-code" in text:
                return 8
        priority_markers = [
            ("targeted_decompilation", 0),
            ("targeted pseudo-code", 0),
            ("enriched_class_manifest", 1),
            ("enriched class manifest", 1),
            ("class_pseudo_cpp", 2),
            ("class-scoped pseudo", 2),
            ("pseudo_code", 3),
            ("pseudo-code", 3),
            ("msvc rtti class manifest", 4),
            ("pdb", 5),
            ("pseudo-c++", 6),
            ("function list", 7),
            ("strings export", 8),
            ("status", 90),
            ("log", 95),
        ]
        for marker, priority in priority_markers:
            if marker in text:
                return priority
        return 50

    def _add_directory_snapshot(
        self,
        add_item,
        path: Path,
        description: str,
        artifact_index: int,
        slots_remaining: int,
    ) -> int:
        if slots_remaining <= 0 or not self._should_snapshot_directory(path, description):
            return 0
        source_suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".rs", ".js", ".ts", ".tsx", ".jsx", ".md", ".json"}
        candidates = [
            candidate
            for candidate in sorted(path.rglob("*"))
            if candidate.is_file() and candidate.suffix.lower() in source_suffixes
        ]
        added = 0
        for candidate in candidates[: min(self.MAX_CONTEXT_DIR_FILES, slots_remaining)]:
            try:
                payload = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            try:
                rel = candidate.relative_to(path).as_posix()
            except ValueError:
                rel = candidate.name
            add_item(
                f"artifact_{artifact_index + added}_{path.name}_{rel}",
                payload[: self.MAX_CONTEXT_CHARS],
                f"Directory artifact snapshot: {description}; file {rel}",
            )
            added += 1
        return added

    @staticmethod
    def _should_snapshot_directory(path: Path, description: str) -> bool:
        text = f"{description} {path}".lower()
        return any(
            marker in text
            for marker in (
                "pseudo_cpp",
                "pseudo-c++",
                "pseudo-code",
                "pseudo_code",
                "recovered source",
                "class-scoped",
                "ghidra",
            )
        )

    @staticmethod
    def _build_naming_hints(context, report) -> dict[str, object]:
        analysis_index = context.analysis_index.to_dict()
        hints: dict[str, object] = {
            "preferred_source_paths": [],
            "class_names": [],
            "function_names": [],
            "field_names": [],
            "class_layouts": [],
            "recovery_capabilities": [],
            "namespaces": [],
            "debug_references": [],
        }
        preferred_source_paths: list[str] = []
        class_names: list[str] = []
        function_names: list[str] = []
        field_names: list[str] = []
        class_layouts: list[dict[str, object]] = []
        recovery_capabilities: list[str] = []
        namespaces: list[str] = []
        debug_references: list[str] = []

        for source in report.recovered_sources[:256]:
            original_path = str(source.original_path or "").replace("\\", "/").strip()
            if original_path and original_path not in preferred_source_paths:
                preferred_source_paths.append(original_path)
            LLMAssistAnalyzer._add_names_from_recovered_source_path(
                original_path,
                class_names=class_names,
                namespaces=namespaces,
            )

        for entity in analysis_index.get("entities") or []:
            kind = str(entity.get("kind", "")).strip().lower()
            label = str(entity.get("label", "")).strip()
            attributes = entity.get("attributes") or {}
            if kind == "class" and label and label not in class_names:
                class_names.append(label)
                layout = {
                    "class_name": label,
                    "estimated_object_size": attributes.get("estimated_object_size"),
                    "subobjects": attributes.get("subobjects"),
                    "constructor_phases": attributes.get("constructor_phases"),
                    "field_count": len([
                        entity
                        for entity in analysis_index.get("entities") or []
                        if str(entity.get("kind", "")).lower() == "field"
                        and str((entity.get("attributes") or {}).get("class_name") or "") == label
                    ]),
                    "symbol_recovery": attributes.get("symbol_recovery"),
                }
                if any(value for value in layout.values()):
                    class_layouts.append(layout)
                for capability in attributes.get("recovery_capabilities") or []:
                    capability_text = str(capability or "").strip()
                    if capability_text and capability_text not in recovery_capabilities:
                        recovery_capabilities.append(capability_text)
                if "::" in label:
                    namespace = "::".join(label.split("::")[:-1]).strip(":")
                    if namespace and namespace not in namespaces:
                        namespaces.append(namespace)
            elif kind == "function" and label and label not in function_names:
                if "::" in label or not label.lower().startswith(("sub_", "fcn.", "vf_")):
                    function_names.append(label)
                namespace = str(attributes.get("namespace", "")).strip()
                if namespace and namespace not in namespaces:
                    namespaces.append(namespace)
            elif kind == "field" and label and label not in field_names:
                field_names.append(label)
            elif kind == "debug_reference" and label and label not in debug_references:
                debug_references.append(label.replace("\\", "/"))

        hints["preferred_source_paths"] = preferred_source_paths[:256]
        hints["class_names"] = class_names[:256]
        hints["function_names"] = function_names[:512]
        hints["field_names"] = field_names[:512]
        hints["class_layouts"] = class_layouts[:128]
        hints["recovery_capabilities"] = recovery_capabilities[:64]
        hints["namespaces"] = namespaces[:128]
        hints["debug_references"] = debug_references[:128]
        return hints

    @staticmethod
    def _add_names_from_recovered_source_path(
        original_path: str,
        *,
        class_names: list[str],
        namespaces: list[str],
    ) -> None:
        if not original_path:
            return
        if original_path.lower().startswith("ddl/"):
            return
        stem = Path(original_path.replace("::", "/")).stem
        if not stem or stem.lower() in {"source", "recovered", "pseudo"}:
            return
        if "::" in original_path:
            namespace_parts = [part for part in original_path.rsplit("::", 1)[0].split("::") if part and part != "msvc_rtti"]
            class_name = "::".join(namespace_parts + [stem]) if namespace_parts else stem
        else:
            class_name = stem
        if class_name and class_name not in class_names:
            class_names.append(class_name)
        if "::" in class_name:
            namespace = "::".join(class_name.split("::")[:-1]).strip(":")
            if namespace and namespace not in namespaces:
                namespaces.append(namespace)

    @staticmethod
    def _spawn_background_job(request_path: Path, context) -> None:
        launcher = [
            sys.executable,
            "-m",
            "re_pro.cli",
            "llm-job",
            "--request",
            str(request_path),
        ]
        env = os.environ.copy()
        src_root = str((REPO_ROOT / "src").resolve())
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = src_root if not existing_pythonpath else src_root + os.pathsep + existing_pythonpath
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        subprocess.Popen(
            launcher,
            cwd=str(REPO_ROOT),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
        )
        context.log(f"Spawned background LLM reconstruction job from {request_path}")
