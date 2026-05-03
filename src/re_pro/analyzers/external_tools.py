from __future__ import annotations

import os
import json
import subprocess
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..api_semantics import refine_targeted_decompilation
from ..msvc_pseudo_cpp import enrich_recovered_classes, write_pseudo_class_sources
from ..tooling import REPO_ROOT, get_ghidra_install_root, list_ghidra_languages, resolve_command, run_command_logged
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class ExternalToolAnalyzer(Analyzer):
    name = "External RE tool adapters"
    GHIDRA_ANALYSIS_TIMEOUT_SECONDS = 120
    GHIDRA_TARGETED_DECOMPILATION_LIMIT = 96
    GHIDRA_TARGETED_DECOMPILATION_TIMEOUT_SECONDS = 8
    PE_TOOL_METADATA_TIMEOUT_SECONDS = 60
    PE_TOOL_DEEP_EXPORT_TIMEOUT_SECONDS = 120
    PE_TOOL_TOTAL_TIMEOUT_SECONDS = 240

    def analyze(self, context, report) -> None:
        if context.target.suffix.lower() in {".apk", ".apks", ".xapk", ".zip", ".jar", ".aar", ".aab"}:
            return
        if not context.target.is_file() or (not context.probable_binary and context.pe_metadata is None):
            return

        ran_any = False
        ghidra_available = resolve_command([["analyzeHeadless"], ["analyzeHeadless.bat"]]) is not None
        rizin_available = resolve_command([["rizin"]]) is not None or resolve_command([["rz-bin"]]) is not None
        radare2_available = resolve_command([["r2"], ["radare2"]]) is not None or resolve_command([["rabin2"]]) is not None
        any_available = ghidra_available or rizin_available or radare2_available
        force_ghidra = ghidra_available and context.run_external_tools and self._should_force_ghidra(context, report)

        if ghidra_available and not context.run_ghidra and not force_ghidra:
            report.add_note("Ghidra is installed locally but skipped for this run. Enable the Ghidra option for a slower headless import/export pass.")
        elif context.run_ghidra or force_ghidra:
            if force_ghidra and not context.run_ghidra:
                report.add_note("Probable PS2/MIPS ELF detected, so RE-Pro automatically enabled the Ghidra headless pass for a richer console-oriented export.")
            ran_any |= self._run_ghidra(context, report)

        if context.run_external_tools:
            ran_any |= self._run_pe_tools(context, report)
        elif rizin_available or radare2_available:
            report.add_note("rizin/radare2 are installed locally but skipped for this run. Enable external tools for deeper export artifacts.")

        if not ran_any and not any_available:
            report.add_note("No external reverse-engineering suites were detected. Install Ghidra, rizin, or radare2 for deeper analysis exports.")

    def _run_ghidra(self, context, report) -> bool:
        command = resolve_command([["analyzeHeadless"], ["analyzeHeadless.bat"]])
        if command is None:
            return False

        project_root = ensure_dir(context.output_dir / "ghidra")
        project_name = safe_slug(context.target.stem)
        export_dir = ensure_dir(project_root / "exports")
        script_dir = self._stage_ghidra_script()
        if script_dir is None:
            report.add_note("RE-Pro could not stage its Ghidra export script into the local Ghidra install.")
            return False
        log_path = project_root / "ghidra_headless.log"
        script_log_path = project_root / "ghidra_script.log"
        profile = self._choose_ghidra_profile(context, report)
        status_path = project_root / "status.json"
        request_path = project_root / "request.json"
        rtti_manifest_path = context.output_dir / "native" / "msvc_rtti_classes.json"
        targeted_decompilation_path = export_dir / "targeted_decompilation.json"
        targeted_pseudocode_dir = export_dir / "pseudo_code"
        class_pseudocode_dir = export_dir / "class_pseudo_cpp"
        native_pseudocode_dir = context.output_dir / "native" / "pseudo_cpp"
        enriched_manifest_path = export_dir / "enriched_class_manifest.json"
        targeted_method_count = self._count_rtti_methods(rtti_manifest_path) if rtti_manifest_path.exists() else 0
        started_at = self._utcnow()
        request_path.write_text(
            json.dumps(
                {
                    "job_type": "ghidra",
                    "target": str(context.target),
                    "project_root": str(project_root),
                    "project_name": project_name,
                    "export_dir": str(export_dir),
                    "log_path": str(log_path),
                    "script_log_path": str(script_log_path),
                    "analysis_timeout_seconds": self.GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
                    "language_id": profile.get("language_id"),
                    "compiler_id": profile.get("compiler_id"),
                    "rtti_manifest_path": str(rtti_manifest_path) if rtti_manifest_path.exists() else "",
                    "targeted_decompilation_path": str(targeted_decompilation_path),
                    "targeted_pseudocode_dir": str(targeted_pseudocode_dir),
                    "class_pseudocode_dir": str(class_pseudocode_dir),
                    "native_class_pseudocode_dir": str(native_pseudocode_dir),
                    "enriched_manifest_path": str(enriched_manifest_path),
                    "targeted_decompilation_limit": self.GHIDRA_TARGETED_DECOMPILATION_LIMIT,
                    "targeted_decompilation_timeout_seconds": self.GHIDRA_TARGETED_DECOMPILATION_TIMEOUT_SECONDS,
                    "targeted_method_count": targeted_method_count,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self._write_status(
            status_path,
            {
                "state": "queued",
                "started_at": started_at,
                "target": str(context.target),
                "request_path": str(request_path),
                "project_root": str(project_root),
                "analysis_timeout_seconds": self.GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
                "targeted_method_count": targeted_method_count,
            },
        )
        self._spawn_background_job(request_path, context, label="ghidra")
        self._record_tool_execution(context, "ghidra", str(log_path), "Ghidra headless analysis")
        report.add_artifact(str(project_root), "ghidra", "Ghidra headless project")
        report.add_artifact(str(export_dir), "directory", "Ghidra export output directory")
        report.add_artifact(str(log_path), "log", "Ghidra headless log")
        report.add_artifact(str(script_log_path), "log", "Ghidra script log")
        report.add_artifact(str(status_path), "metadata", "Ghidra headless status")
        report.add_artifact(str(targeted_decompilation_path), "json", "Ghidra targeted pseudo-code export")
        report.add_artifact(str(targeted_pseudocode_dir), "directory", "Ghidra targeted pseudo-code directory")
        report.add_artifact(str(class_pseudocode_dir), "directory", "Ghidra class-scoped pseudo-C++ directory")
        report.add_artifact(str(enriched_manifest_path), "json", "Ghidra enriched class manifest")
        report.add_finding(
            "Ghidra analysis started",
            "Ghidra headless was detached into a background job so the main analysis pipeline could continue without blocking.",
            severity="info",
        )
        report.add_note(
            f"Ghidra is running in the background. Status: {status_path}. "
            f"Headless analysis is capped at {self.GHIDRA_ANALYSIS_TIMEOUT_SECONDS}s per file to limit long decompiler stalls."
        )
        if profile.get("note"):
            report.add_note(str(profile["note"]))
        if targeted_method_count:
            report.add_note(
                f"Ghidra queued targeted decompilation for up to {min(targeted_method_count, self.GHIDRA_TARGETED_DECOMPILATION_LIMIT)} "
                f"RTTI-derived method candidate(s) into {targeted_decompilation_path}."
            )
        context.log(f"Spawned background Ghidra job for {context.target.name} into {project_root}")
        return True

    @staticmethod
    def _stage_ghidra_script() -> Path | None:
        ghidra_root = get_ghidra_install_root()
        if ghidra_root is None:
            return None
        source_path = Path(__file__).resolve().parents[1] / "ghidra_scripts" / "REProExport.py"
        if not source_path.exists():
            return None
        target_dir = ghidra_root / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
        ensure_dir(target_dir)
        target_path = target_dir / source_path.name
        if not target_path.exists() or target_path.read_text(encoding="utf-8") != source_path.read_text(encoding="utf-8"):
            shutil.copyfile(source_path, target_path)
        return target_dir

    def _run_pe_tools(self, context, report) -> bool:
        r2 = resolve_command([["r2"], ["radare2"]])
        rabin2 = resolve_command([["rabin2"]])
        rizin = resolve_command([["rizin"]])
        rz_bin = resolve_command([["rz-bin"]])
        if rizin is None and rz_bin is None and r2 is None and rabin2 is None:
            return False

        output_root = ensure_dir(context.output_dir / "pe_tools")
        rizin_dir = ensure_dir(context.output_dir / "rizin")
        radare2_dir = ensure_dir(context.output_dir / "radare2")
        log_path = output_root / "pe_tools.log"
        status_path = output_root / "status.json"
        request_path = output_root / "request.json"
        started_at = self._utcnow()
        request_path.write_text(
            json.dumps(
                {
                    "job_type": "pe_tools",
                    "target": str(context.target),
                    "output_root": str(output_root),
                    "log_path": str(log_path),
                    "status_path": str(status_path),
                    "rizin_dir": str(rizin_dir),
                    "radare2_dir": str(radare2_dir),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self._write_status(
            status_path,
            {
                "state": "queued",
                "started_at": started_at,
                "target": str(context.target),
                "request_path": str(request_path),
                "output_root": str(output_root),
            },
        )
        self._spawn_background_job(request_path, context, label="pe-tools")
        report.add_artifact(str(output_root), "directory", "PE tools background output directory")
        report.add_artifact(str(log_path), "log", "PE tools background log")
        report.add_artifact(str(status_path), "metadata", "PE tools background status")
        report.add_artifact(str(rizin_dir), "directory", "rizin export output directory")
        report.add_artifact(str(radare2_dir), "directory", "radare2 export output directory")
        report.add_finding(
            "PE tool exports started",
            "rizin/radare2 exports were detached into a background job so the main analysis pipeline could continue without blocking.",
            severity="info",
        )
        report.add_note(f"PE tool exports are running in the background. Status: {status_path}")
        context.log(f"Spawned background PE tool job for {context.target.name} into {output_root}")
        return True

    @staticmethod
    def _capture_to_file(command, destination: Path, category: str, description: str, context, report) -> bool:
        code, stdout, stderr = run_command_logged(command, cwd=context.target.parent, timeout=1800, label=Path(command[0]).stem)
        if code != 0 or not stdout.strip():
            if stderr.strip():
                report.add_note(f"{description} failed: {stderr.strip()}")
            return False
        destination.write_text(stdout, encoding="utf-8", errors="ignore")
        report.add_artifact(str(destination), category, description)
        ExternalToolAnalyzer._record_tool_execution(context, Path(command[0]).stem.lower(), str(destination), description)
        context.log(f"Wrote {description} to {destination}")
        return True

    @staticmethod
    def _record_tool_execution(context, tool_name: str, output_path: str, description: str) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        tool_id = context.analysis_index.add_entity("tool", tool_name, tool_name, attributes={"kind": "external_re_tool"})
        output_id = context.analysis_index.add_entity(
            "artifact",
            output_path,
            description,
            attributes={"path": output_path, "category": "tool_output", "description": description},
        )
        context.analysis_index.add_relation(target_id, "analyzed_with", tool_id)
        context.analysis_index.add_relation(tool_id, "produced_artifact", output_id)

    @staticmethod
    def _should_force_ghidra(context, report) -> bool:
        return bool(context.elf_metadata is not None and "PlayStation 2 ELF" in report.frameworks)

    @classmethod
    def _choose_ghidra_profile(cls, context, report) -> dict[str, str | None]:
        if context.elf_metadata is None or str(context.elf_metadata.get("machine")) != "MIPS":
            return {"language_id": None, "compiler_id": None, "note": None}

        endianness = str(context.elf_metadata.get("endianness", "little"))
        is_ps2 = "PlayStation 2 ELF" in report.frameworks
        languages = list_ghidra_languages()
        if is_ps2:
            plugin_language = cls._find_matching_ghidra_language(
                languages,
                keywords=("emotion", "r5900", "ps2"),
                endian=endianness,
            )
            if plugin_language is not None:
                compiler_id = cls._choose_compiler_id(plugin_language, preferred=("o32", "default"))
                return {
                    "language_id": str(plugin_language.get("id") or ""),
                    "compiler_id": compiler_id,
                    "note": f"Ghidra selected plugin-backed PS2/MIPS language {plugin_language.get('id')} for the headless import.",
                }

            built_in = cls._find_matching_ghidra_language(
                languages,
                exact_id=f"MIPS:{'LE' if endianness == 'little' else 'BE'}:64:64-32addr",
            )
            if built_in is not None:
                compiler_id = cls._choose_compiler_id(built_in, preferred=("o32", "default"))
                return {
                    "language_id": str(built_in.get("id") or ""),
                    "compiler_id": compiler_id,
                    "note": f"Ghidra used {built_in.get('id')} for this PS2-style ELF, matching the Emotion Engine's 64-bit MIPS ISA with 32-bit addressing.",
                }

        generic = cls._find_matching_ghidra_language(
            languages,
            exact_id=f"MIPS:{'LE' if endianness == 'little' else 'BE'}:{context.elf_metadata.get('bits')}:default",
        )
        if generic is not None:
            return {
                "language_id": str(generic.get("id") or ""),
                "compiler_id": cls._choose_compiler_id(generic, preferred=("default",)),
                "note": f"Ghidra used {generic.get('id')} for the MIPS headless import.",
            }
        return {"language_id": None, "compiler_id": None, "note": None}

    @staticmethod
    def _find_matching_ghidra_language(
        languages: list[dict[str, object]],
        *,
        exact_id: str | None = None,
        keywords: tuple[str, ...] = (),
        endian: str | None = None,
    ) -> dict[str, object] | None:
        if exact_id:
            for language in languages:
                if str(language.get("id")) == exact_id:
                    return language
        if not keywords:
            return None
        lowered_keywords = tuple(keyword.lower() for keyword in keywords)
        best_language: dict[str, object] | None = None
        best_score = -1
        for language in languages:
            haystack = " ".join(
                [
                    str(language.get("id", "")),
                    str(language.get("description", "")),
                    str(language.get("variant", "")),
                ]
            ).lower()
            score = sum(1 for keyword in lowered_keywords if keyword in haystack)
            if endian and str(language.get("endian", "")).lower() != endian.lower():
                continue
            if score > best_score:
                best_score = score
                best_language = language
        return best_language if best_score > 0 else None

    @staticmethod
    def _choose_compiler_id(language: dict[str, object], preferred: tuple[str, ...]) -> str | None:
        compiler_ids = [str(value) for value in language.get("compiler_ids", []) if value]
        for compiler_id in preferred:
            if compiler_id in compiler_ids:
                return compiler_id
        return compiler_ids[0] if compiler_ids else None

    @staticmethod
    def _collect_ghidra_exports(export_dir: Path, report) -> int:
        if not export_dir.exists():
            return 0
        descriptions = {
            "program_info.json": ("json", "Ghidra program metadata export"),
            "functions.json": ("json", "Ghidra function export"),
            "strings.json": ("json", "Ghidra strings export"),
            "targeted_decompilation.json": ("json", "Ghidra targeted pseudo-code export"),
            "enriched_class_manifest.json": ("json", "Ghidra enriched class manifest"),
        }
        count = 0
        for filename, (category, description) in descriptions.items():
            path = export_dir / filename
            if path.exists():
                report.add_artifact(str(path), category, description)
                count += 1
        pseudo_code_dir = export_dir / "pseudo_code"
        if pseudo_code_dir.exists() and pseudo_code_dir.is_dir():
            report.add_artifact(str(pseudo_code_dir), "directory", "Ghidra targeted pseudo-code directory")
            count += 1
        class_pseudo_cpp_dir = export_dir / "class_pseudo_cpp"
        if class_pseudo_cpp_dir.exists() and class_pseudo_cpp_dir.is_dir():
            report.add_artifact(str(class_pseudo_cpp_dir), "directory", "Ghidra class-scoped pseudo-C++ directory")
            count += 1
        program_info_path = export_dir / "program_info.json"
        if program_info_path.exists():
            try:
                payload = json.loads(program_info_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return count
            language_id = payload.get("language_id")
            if language_id:
                report.add_note(f"Ghidra imported the program as {language_id}.")
        return count

    @classmethod
    def run_background_job(cls, request_path: Path) -> int:
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        job_type = str(payload.get("job_type", "")).strip().lower()
        if job_type == "ghidra":
            return cls._run_ghidra_job(payload)
        if job_type == "pe_tools":
            return cls._run_pe_tools_job(payload)
        raise ValueError("Unknown external tool job type: %s" % job_type)

    @classmethod
    def _run_ghidra_job(cls, payload: dict[str, object]) -> int:
        project_root = ensure_dir(Path(str(payload["project_root"])))
        export_dir = ensure_dir(Path(str(payload["export_dir"])))
        log_path = Path(str(payload["log_path"]))
        script_log_path = Path(str(payload["script_log_path"]))
        status_path = project_root / "status.json"
        target = Path(str(payload["target"]))
        command = resolve_command([["analyzeHeadless"], ["analyzeHeadless.bat"]])
        script_dir = cls._stage_ghidra_script()
        started_at = cls._utcnow()
        if command is None or script_dir is None:
            cls._write_status(
                status_path,
                {
                    "state": "failed",
                    "started_at": started_at,
                    "finished_at": cls._utcnow(),
                    "target": str(target),
                    "error": "Ghidra analyzeHeadless or the staged RE-Pro export script was unavailable.",
                },
            )
            return 1

        def _log(message: str) -> None:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(message + "\n")

        cls._write_status(
            status_path,
            {
                "state": "running",
                "started_at": started_at,
                "target": str(target),
                "project_root": str(project_root),
                "export_dir": str(export_dir),
                "log_path": str(log_path),
                "script_log_path": str(script_log_path),
                "analysis_timeout_seconds": int(payload.get("analysis_timeout_seconds") or cls.GHIDRA_ANALYSIS_TIMEOUT_SECONDS),
                "targeted_method_count": int(payload.get("targeted_method_count") or 0),
            },
        )

        full_command = command + [
            str(project_root),
            str(payload["project_name"]),
            "-import",
            str(target),
            "-overwrite",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "REProExport.py",
            str(export_dir),
            str(payload.get("rtti_manifest_path") or ""),
            str(payload.get("targeted_decompilation_path") or ""),
            "-scriptlog",
            str(script_log_path),
            "-log",
            str(log_path),
            "-analysisTimeoutPerFile",
            str(int(payload.get("analysis_timeout_seconds") or cls.GHIDRA_ANALYSIS_TIMEOUT_SECONDS)),
        ]
        language_id = str(payload.get("language_id") or "").strip()
        compiler_id = str(payload.get("compiler_id") or "").strip()
        if language_id:
            full_command += ["-processor", language_id]
            if compiler_id:
                full_command += ["-cspec", compiler_id]

        code, stdout, stderr = run_command_logged(
            full_command,
            cwd=target.parent,
            timeout=4 * 3600,
            logger=_log,
            label="ghidra",
            heartbeat_seconds=20,
        )
        if not log_path.exists():
            log_path.write_text((stdout or "") + ("\n" + stderr if stderr else ""), encoding="utf-8", errors="ignore")

        program_info = cls._read_json(export_dir / "program_info.json")
        targeted_decompilation_path = Path(str(payload.get("targeted_decompilation_path") or ""))
        targeted_decompilation = cls._read_json_list(targeted_decompilation_path)
        if targeted_decompilation:
            targeted_decompilation = refine_targeted_decompilation(targeted_decompilation)
            targeted_decompilation_path.write_text(json.dumps(targeted_decompilation, indent=2), encoding="utf-8")
        targeted_pseudocode_dir = Path(str(payload.get("targeted_pseudocode_dir") or export_dir / "pseudo_code"))
        class_pseudocode_dir = Path(str(payload.get("class_pseudocode_dir") or export_dir / "class_pseudo_cpp"))
        native_class_pseudocode_dir = Path(str(payload.get("native_class_pseudocode_dir") or ""))
        enriched_manifest_path = Path(str(payload.get("enriched_manifest_path") or export_dir / "enriched_class_manifest.json"))
        class_source_count = cls._synthesize_class_pseudocode(
            payload,
            targeted_decompilation,
            class_pseudocode_dir,
            enriched_manifest_path,
            native_class_pseudocode_dir=native_class_pseudocode_dir,
        )
        exports = [
            str(path)
            for path in [
                export_dir / "program_info.json",
                export_dir / "functions.json",
                export_dir / "strings.json",
                Path(str(payload.get("targeted_decompilation_path") or export_dir / "targeted_decompilation.json")),
                enriched_manifest_path,
            ]
            if path.exists()
        ]
        if targeted_pseudocode_dir.exists():
            exports.append(str(targeted_pseudocode_dir))
        if class_pseudocode_dir.exists():
            exports.append(str(class_pseudocode_dir))
        warning_counts = cls._summarize_ghidra_log(log_path)
        status = {
            "state": "completed" if code == 0 else "failed",
            "started_at": started_at,
            "finished_at": cls._utcnow(),
            "target": str(target),
            "project_root": str(project_root),
            "export_dir": str(export_dir),
            "exit_code": code,
            "exports": exports,
            "warning_counts": warning_counts,
            "analysis_timed_out": bool((program_info or {}).get("analysis_timed_out", False)),
            "language_id": (program_info or {}).get("language_id"),
            "targeted_method_count": int(payload.get("targeted_method_count") or 0),
            "decompiled_function_count": len(targeted_decompilation),
            "class_source_count": class_source_count,
        }
        message = stderr.strip() or stdout.strip()
        if message:
            status["message"] = message[:4000]
        cls._write_status(status_path, status)
        return 0 if status["state"] == "completed" else 1

    @classmethod
    def _run_pe_tools_job(cls, payload: dict[str, object]) -> int:
        output_root = ensure_dir(Path(str(payload["output_root"])))
        rizin_dir = ensure_dir(Path(str(payload["rizin_dir"])))
        radare2_dir = ensure_dir(Path(str(payload["radare2_dir"])))
        log_path = Path(str(payload["log_path"]))
        status_path = Path(str(payload["status_path"]))
        target = Path(str(payload["target"]))
        started_at = cls._utcnow()
        started_monotonic = time.monotonic()

        def _log(message: str) -> None:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(message + "\n")

        cls._write_status(
            status_path,
            {
                "state": "running",
                "started_at": started_at,
                "target": str(target),
                "output_root": str(output_root),
                "log_path": str(log_path),
            },
        )

        outputs: list[dict[str, str]] = []
        errors: list[str] = []
        rizin = resolve_command([["rizin"]])
        rz_bin = resolve_command([["rz-bin"]])
        r2 = resolve_command([["r2"], ["radare2"]])
        rabin2 = resolve_command([["rabin2"]])

        def _remaining_timeout(requested: int) -> int:
            remaining = int(cls.PE_TOOL_TOTAL_TIMEOUT_SECONDS - (time.monotonic() - started_monotonic))
            return max(1, min(requested, remaining))

        def _budget_available(description: str) -> bool:
            elapsed = time.monotonic() - started_monotonic
            if elapsed < cls.PE_TOOL_TOTAL_TIMEOUT_SECONDS:
                return True
            message = f"{description}: skipped because PE tool budget was exhausted after {int(elapsed)} seconds"
            errors.append(message)
            _log(message)
            return False

        def _capture(
            command: list[str],
            destination: Path,
            description: str,
            *,
            timeout: int,
        ) -> bool:
            if not _budget_available(description):
                return False
            before = len(errors)
            ok = cls._capture_to_file_logged(
                command,
                destination,
                target.parent,
                _log,
                outputs,
                errors,
                description,
                timeout=_remaining_timeout(timeout),
            )
            if not ok and any("Timed out after" in error for error in errors[before:]):
                _log(f"{description} timed out; remaining deep PE exports may be skipped.")
            return ok

        if rz_bin is not None:
            _capture(rz_bin + ["-I", str(target)], rizin_dir / "binary_info.txt", "rizin binary metadata", timeout=cls.PE_TOOL_METADATA_TIMEOUT_SECONDS)
            _capture(rz_bin + ["-S", str(target)], rizin_dir / "sections.txt", "rizin section listing", timeout=cls.PE_TOOL_METADATA_TIMEOUT_SECONDS)
        deep_export_ok = True
        if rizin is not None:
            deep_export_ok = _capture(rizin + ["-A", "-q", "-c", "aflj", str(target)], rizin_dir / "functions.json", "rizin function list", timeout=cls.PE_TOOL_DEEP_EXPORT_TIMEOUT_SECONDS)
            if deep_export_ok:
                _capture(rizin + ["-A", "-q", "-c", "izj", str(target)], rizin_dir / "strings.json", "rizin strings export", timeout=cls.PE_TOOL_DEEP_EXPORT_TIMEOUT_SECONDS)
        if rabin2 is not None:
            _capture(rabin2 + ["-I", str(target)], radare2_dir / "binary_info.txt", "radare2 binary metadata", timeout=cls.PE_TOOL_METADATA_TIMEOUT_SECONDS)
            _capture(rabin2 + ["-S", str(target)], radare2_dir / "sections.txt", "radare2 section listing", timeout=cls.PE_TOOL_METADATA_TIMEOUT_SECONDS)
        if r2 is not None and deep_export_ok:
            radare_deep_ok = _capture(r2 + ["-A", "-q", "-c", "aflj", str(target)], radare2_dir / "functions.json", "radare2 function list", timeout=cls.PE_TOOL_DEEP_EXPORT_TIMEOUT_SECONDS)
            if radare_deep_ok:
                _capture(r2 + ["-A", "-q", "-c", "izj", str(target)], radare2_dir / "strings.json", "radare2 strings export", timeout=cls.PE_TOOL_DEEP_EXPORT_TIMEOUT_SECONDS)
        elif r2 is not None:
            message = "radare2 deep exports skipped because rizin deep export timed out or failed"
            errors.append(message)
            _log(message)

        status = {
            "state": "completed" if outputs else "failed",
            "started_at": started_at,
            "finished_at": cls._utcnow(),
            "target": str(target),
            "output_root": str(output_root),
            "log_path": str(log_path),
            "outputs": outputs,
            "errors": errors[:80],
        }
        cls._write_status(status_path, status)
        return 0 if outputs else 1

    @classmethod
    def _spawn_background_job(cls, request_path: Path, context, *, label: str) -> None:
        launcher = [
            sys.executable,
            "-m",
            "re_pro.cli",
            "external-tool-job",
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
        context.log(f"Spawned background {label} job from {request_path}")

    @staticmethod
    def _capture_to_file_logged(
        command: list[str],
        destination: Path,
        cwd: Path,
        logger,
        outputs: list[dict[str, str]],
        errors: list[str],
        description: str,
        *,
        timeout: int = 300,
    ) -> bool:
        code, stdout, stderr = run_command_logged(
            command,
            cwd=cwd,
            timeout=timeout,
            logger=logger,
            label=Path(command[0]).stem.lower(),
        )
        if code != 0 or not stdout.strip():
            message = stderr.strip() or stdout.strip() or f"{description} failed with exit code {code}"
            errors.append(f"{description}: {message}")
            logger(f"{description} failed: {message}")
            return False
        destination.write_text(stdout, encoding="utf-8", errors="ignore")
        outputs.append({"path": str(destination), "description": description})
        logger(f"Wrote {description} to {destination}")
        return True

    @staticmethod
    def _summarize_ghidra_log(log_path: Path) -> dict[str, int]:
        if not log_path.exists():
            return {}
        try:
            text = log_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return {}
        return {
            "decompile_callback_total": text.count("(DecompileCallback)"),
            "unable_to_read_bytes": text.count("Unable to read bytes"),
            "unable_to_resolve_constructor": text.count("Unable to resolve constructor"),
            "bad_disassembly_flow": text.count("Could not follow disassembly flow into non-existing memory"),
            "function_body_repairs": text.count("function body repair failed due to overlap"),
        }

    @staticmethod
    def _read_json(path: Path) -> dict[str, object] | None:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _read_json_list(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    @staticmethod
    def _count_rtti_methods(path: Path) -> int:
        payload = ExternalToolAnalyzer._read_json(path)
        if not payload:
            return 0
        return sum(len(entry.get("methods") or []) for entry in payload.get("classes") or [])

    @staticmethod
    def _synthesize_class_pseudocode(
        payload: dict[str, object],
        targeted_decompilation: list[dict[str, object]],
        output_dir: Path,
        enriched_manifest_path: Path,
        *,
        native_class_pseudocode_dir: Path | None = None,
    ) -> int:
        manifest_path = Path(str(payload.get("rtti_manifest_path") or ""))
        if not manifest_path.exists() or not targeted_decompilation:
            return 0
        recovered = ExternalToolAnalyzer._read_json(manifest_path)
        if not recovered:
            return 0
        enriched = enrich_recovered_classes(recovered, decompiled_entries=targeted_decompilation)
        enriched_manifest_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
        generated = write_pseudo_class_sources(output_dir, enriched, decompiled_entries=targeted_decompilation)
        if native_class_pseudocode_dir is not None and str(native_class_pseudocode_dir):
            generated.extend(
                write_pseudo_class_sources(
                    native_class_pseudocode_dir,
                    enriched,
                    decompiled_entries=targeted_decompilation,
                )
            )
        return len(generated)

    @staticmethod
    def _write_status(path: Path, payload: dict[str, object]) -> None:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
