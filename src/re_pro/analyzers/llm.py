from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from ..llm_assist import run_llm_assist_job
from ..tooling import REPO_ROOT
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class LLMAssistAnalyzer(Analyzer):
    name = "LLM-assisted reconstruction"
    MAX_CONTEXT_ARTIFACTS = 12
    MAX_CONTEXT_CHARS = 16000

    def analyze(self, context, report) -> None:
        settings = context.llm_settings
        if not settings.enabled and not settings.auto:
            return
        if not self._should_run(settings, report):
            return
        if not os.environ.get("OPENAI_API_KEY"):
            report.add_note("LLM-assisted reconstruction was requested, but OPENAI_API_KEY is not set.")
            return

        llm_dir = ensure_dir(context.output_dir / "llm_assist")
        reconstructed_root = ensure_dir(llm_dir / "reconstructed_src")
        context_items = self._build_context_items(context, report, llm_dir)
        request_path = llm_dir / "request.json"
        status_path = llm_dir / "status.json"
        summary_path = llm_dir / "assistant_summary.md"
        request_payload = {
            "llm_dir": str(llm_dir),
            "reconstructed_root": str(reconstructed_root),
            "settings": {
                "model": settings.model,
                "reasoning_effort": settings.reasoning_effort,
                "verbosity": settings.verbosity,
                "background": settings.background,
                "max_output_tokens": settings.max_output_tokens,
                "user_task": settings.user_task,
                "allow_dependency_installs": settings.allow_dependency_installs,
                "run_recompile_checks": settings.run_recompile_checks,
            },
            "report": report.to_dict(),
            "analysis_index": context.analysis_index.to_dict(),
            "context_items": context_items,
        }
        request_path.write_text(json.dumps(request_payload, indent=2), encoding="utf-8")
        report.add_artifact(str(request_path), "metadata", "LLM reconstruction request")
        report.add_artifact(str(status_path), "metadata", "LLM reconstruction status")
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
                "GPT-5.4 reconstruction was queued in a detached background job. Monitor the status and summary artifacts for completion.",
                severity="info",
            )
            report.add_note(f"LLM reconstruction is running in the background. Status: {status_path}")
            return

        result = run_llm_assist_job(request_path, logger=context.log)
        report.add_artifact(str(summary_path), "report", "LLM reconstruction summary")
        report.add_finding(
            "LLM reconstruction completed",
            f"GPT-5.4 wrote {len(result.get('written_files') or [])} reconstructed file(s).",
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
        if context.ascii_strings:
            add_item(
                "ascii_strings_sample.txt",
                "\n".join(context.ascii_strings[:1600]),
                "Sample of extracted ASCII strings from the target binary or package head.",
            )

        added_artifacts = 0
        for artifact in report.artifacts:
            path = Path(artifact.path)
            if not path.exists() or not path.is_file():
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
