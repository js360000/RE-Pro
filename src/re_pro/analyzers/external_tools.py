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
        target_selection_path = export_dir / "target_selection.json"
        class_callgraph_path = export_dir / "class_callgraph_manifest.json"
        targeted_method_count = self._count_rtti_methods(rtti_manifest_path) if rtti_manifest_path.exists() else 0
        target_selection = self._build_ghidra_target_selection(
            rtti_manifest_path,
            target_selection_path,
            limit=self.GHIDRA_TARGETED_DECOMPILATION_LIMIT,
            source_hints=self._class_source_hints(report),
        )
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
                    "target_selection_path": str(target_selection_path) if target_selection_path.exists() else "",
                    "class_callgraph_path": str(class_callgraph_path),
                    "targeted_decompilation_limit": self.GHIDRA_TARGETED_DECOMPILATION_LIMIT,
                    "targeted_decompilation_timeout_seconds": self.GHIDRA_TARGETED_DECOMPILATION_TIMEOUT_SECONDS,
                    "targeted_method_count": targeted_method_count,
                    "target_selection_count": len(target_selection.get("targets", [])) if target_selection else 0,
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
                "target_selection_count": len(target_selection.get("targets", [])) if target_selection else 0,
            },
        )
        self._spawn_background_job(request_path, context, label="ghidra")
        self._record_tool_execution(context, "ghidra", str(log_path), "Ghidra headless analysis")
        report.add_artifact(str(project_root), "ghidra", "Ghidra headless project")
        report.add_artifact(str(export_dir), "directory", "Ghidra export output directory")
        report.add_artifact(str(log_path), "log", "Ghidra headless log")
        report.add_artifact(str(script_log_path), "log", "Ghidra script log")
        report.add_artifact(str(status_path), "metadata", "Ghidra headless status")
        report.add_artifact(str(target_selection_path), "json", "Ghidra ranked target selection")
        report.add_artifact(str(targeted_decompilation_path), "json", "Ghidra targeted pseudo-code export")
        report.add_artifact(str(targeted_pseudocode_dir), "directory", "Ghidra targeted pseudo-code directory")
        report.add_artifact(str(class_pseudocode_dir), "directory", "Ghidra class-scoped pseudo-C++ directory")
        report.add_artifact(str(enriched_manifest_path), "json", "Ghidra enriched class manifest")
        report.add_artifact(str(class_callgraph_path), "json", "Ghidra class callgraph manifest")
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
                f"Ghidra queued targeted decompilation for {len(target_selection.get('targets', [])) if target_selection else min(targeted_method_count, self.GHIDRA_TARGETED_DECOMPILATION_LIMIT)} "
                f"ranked RTTI-derived method candidate(s) into {targeted_decompilation_path}."
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
            "target_selection.json": ("json", "Ghidra ranked target selection"),
            "targeted_decompilation.json": ("json", "Ghidra targeted pseudo-code export"),
            "enriched_class_manifest.json": ("json", "Ghidra enriched class manifest"),
            "class_callgraph_manifest.json": ("json", "Ghidra class callgraph manifest"),
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

    @staticmethod
    def _build_ghidra_target_selection(
        manifest_path: Path,
        output_path: Path,
        *,
        limit: int,
        source_hints: dict[str, str] | None = None,
    ) -> dict[str, object]:
        payload = ExternalToolAnalyzer._read_json(manifest_path)
        if not payload:
            return {"targets": [], "total_candidates": 0, "limit": limit}

        source_hints = source_hints or {}
        classes = [entry for entry in payload.get("classes") or [] if isinstance(entry, dict)]
        address_counts: dict[str, int] = {}
        for class_entry in classes:
            for method in class_entry.get("methods") or []:
                if not isinstance(method, dict):
                    continue
                address = ExternalToolAnalyzer._normalize_target_address(method.get("address") or method.get("entry_point"))
                if address:
                    address_counts[address] = address_counts.get(address, 0) + 1

        candidates: list[dict[str, object]] = []
        for class_index, class_entry in enumerate(classes):
            class_name = str(class_entry.get("name") or "").strip()
            if not class_name:
                continue
            hinted_source_path = ExternalToolAnalyzer._source_hint_for_class(class_name, source_hints)
            class_score, class_reasons = ExternalToolAnalyzer._score_target_class(class_entry, hinted_source_path=hinted_source_path)
            methods = [method for method in class_entry.get("methods") or [] if isinstance(method, dict)]
            for method_index, method in enumerate(methods):
                address = ExternalToolAnalyzer._normalize_target_address(method.get("address") or method.get("entry_point"))
                if not address:
                    continue
                method_score, method_reasons = ExternalToolAnalyzer._score_target_method(method, address_counts.get(address, 0))
                display_name = str(method.get("display_name") or method.get("name") or f"fn_{address[2:]}").strip()
                candidates.append(
                    {
                        "address": address,
                        "class_name": class_name,
                        "qualified_name": str(method.get("qualified_name") or f"{class_name}::{display_name}"),
                        "method_name": display_name,
                        "slot": method.get("slot"),
                        "vtable_rva": method.get("vtable_rva"),
                        "method_kind": method.get("method_kind"),
                        "semantic_alias": method.get("semantic_alias"),
                        "source_path": class_entry.get("source_path") or class_entry.get("debug_source_path") or hinted_source_path,
                        "score": class_score + method_score,
                        "reasons": class_reasons + method_reasons,
                        "class_index": class_index,
                        "method_index": method_index,
                        "shared_vtable_target_count": address_counts.get(address, 1),
                    }
                )

        candidates.sort(key=lambda item: (-int(item.get("score") or 0), int(item.get("class_index") or 0), int(item.get("method_index") or 0)))
        selected: list[dict[str, object]] = []
        by_address: dict[str, dict[str, object]] = {}
        for candidate in candidates:
            address = str(candidate.get("address") or "")
            existing = by_address.get(address)
            if existing is not None:
                existing.setdefault("class_candidates", []).append(
                    {
                        "class_name": candidate.get("class_name"),
                        "qualified_name": candidate.get("qualified_name"),
                        "slot": candidate.get("slot"),
                        "vtable_rva": candidate.get("vtable_rva"),
                    }
                )
                continue
            candidate["rank"] = len(selected) + 1
            candidate["class_candidates"] = [
                {
                    "class_name": candidate.get("class_name"),
                    "qualified_name": candidate.get("qualified_name"),
                    "slot": candidate.get("slot"),
                    "vtable_rva": candidate.get("vtable_rva"),
                }
            ]
            selected.append(candidate)
            by_address[address] = candidate
            if len(selected) >= max(0, limit):
                break

        result = {
            "artifact_type": "ghidra_target_selection",
            "strategy": "ranked_msvc_rtti_vtable_methods",
            "limit": limit,
            "total_candidates": len(candidates),
            "selected_count": len(selected),
            "targets": selected,
        }
        ensure_dir(output_path.parent)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    @staticmethod
    def _normalize_target_address(value: object) -> str | None:
        text = str(value or "").strip().lower()
        if not text:
            return None
        if text.startswith("ram:"):
            text = text.split(":", 1)[1]
        if text.startswith("0x"):
            raw = text[2:]
        else:
            raw = text
        try:
            return f"0x{int(raw, 16):x}"
        except ValueError:
            return None

    @staticmethod
    def _score_target_class(class_entry: dict[str, object], hinted_source_path: str | None = None) -> tuple[int, list[str]]:
        class_name = str(class_entry.get("name") or "").strip()
        lowered = class_name.lower()
        score = 20
        reasons = ["rtti_class"]
        if class_entry.get("source_path") or class_entry.get("debug_source_path") or hinted_source_path:
            score += 45
            reasons.append("has_source_path")
        if class_entry.get("members"):
            score += 15
            reasons.append("has_recovered_members")
        if class_entry.get("base_classes"):
            score += 10
            reasons.append("has_inheritance")
        if lowered.startswith(("std::", "__std::", "type_info", "__crt", "atl::", "wil::")):
            score -= 35
            reasons.append("runtime_library_class")
        elif class_name:
            score += 20
            reasons.append("named_application_or_library_class")
        return score, reasons

    @staticmethod
    def _class_source_hints(report) -> dict[str, str]:
        hints: dict[str, str] = {}
        def remember(key: str, value: str) -> None:
            existing = hints.get(key)
            if existing is None or (existing.lower().endswith((".h", ".hh", ".hpp", ".hxx")) and value.lower().endswith((".c", ".cc", ".cpp", ".cxx"))):
                hints[key] = value

        for source in getattr(report, "recovered_sources", []) or []:
            original_path = str(getattr(source, "original_path", "") or "").replace("\\", "/").strip()
            if not original_path:
                continue
            canonical = original_path.replace("/", "::")
            if "::" in canonical:
                without_extension = canonical.rsplit(".", 1)[0]
                parts = [part for part in without_extension.split("::") if part]
                for index in range(len(parts)):
                    remember("::".join(parts[index:]).lower(), original_path)
                if parts:
                    remember(parts[-1].lower(), original_path)
            stem = Path(original_path).stem.strip()
            if not stem:
                continue
            remember(stem.lower(), original_path)
            parts = [part for part in original_path.split("/") if part]
            if len(parts) >= 2:
                namespace_key = "::".join([Path(part).stem if index == len(parts) - 1 else part for index, part in enumerate(parts[-3:])])
                remember(namespace_key.lower(), original_path)
        return hints

    @staticmethod
    def _source_hint_for_class(class_name: str, source_hints: dict[str, str]) -> str | None:
        lowered = class_name.lower()
        short = class_name.split("::")[-1].lower()
        if lowered in source_hints:
            return source_hints[lowered]
        if short in source_hints:
            return source_hints[short]
        return None

    @staticmethod
    def _score_target_method(method: dict[str, object], address_count: int | None) -> tuple[int, list[str]]:
        score = 10
        reasons = ["vtable_method"]
        name = str(method.get("display_name") or method.get("name") or "").strip()
        lowered = name.lower()
        kind = str(method.get("method_kind") or "").strip()
        if kind:
            score += 25
            reasons.append(f"method_kind:{kind}")
        if method.get("semantic_alias"):
            score += 20
            reasons.append("semantic_alias")
        if method.get("caller_count"):
            score += min(30, int(method.get("caller_count") or 0) * 5)
            reasons.append("has_callers")
        if method.get("params") or method.get("return_type"):
            score += 10
            reasons.append("typed_signature")
        if lowered and not lowered.startswith(("vf_", "sub_", "fun_", "thunk_")):
            score += 15
            reasons.append("semantic_name")
        shared_count = int(address_count or 1)
        if shared_count > 1:
            score -= min(40, (shared_count - 1) * 8)
            reasons.append("shared_vtable_target")
        else:
            score += 12
            reasons.append("unique_vtable_target")
        return score, reasons

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
            str(payload.get("target_selection_path") or ""),
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
        class_callgraph_path = Path(str(payload.get("class_callgraph_path") or export_dir / "class_callgraph_manifest.json"))
        class_callgraph = cls._write_class_callgraph_manifest(
            payload,
            targeted_decompilation,
            enriched_manifest_path,
            class_callgraph_path,
        )
        exports = [
            str(path)
            for path in [
                export_dir / "program_info.json",
                export_dir / "functions.json",
                export_dir / "strings.json",
                Path(str(payload.get("target_selection_path") or export_dir / "target_selection.json")),
                Path(str(payload.get("targeted_decompilation_path") or export_dir / "targeted_decompilation.json")),
                enriched_manifest_path,
                class_callgraph_path,
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
            "target_selection_count": int(payload.get("target_selection_count") or 0),
            "decompiled_function_count": len(targeted_decompilation),
            "class_source_count": class_source_count,
            "class_callgraph_class_count": len(class_callgraph.get("classes", [])) if class_callgraph else 0,
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
    def _write_class_callgraph_manifest(
        payload: dict[str, object],
        targeted_decompilation: list[dict[str, object]],
        enriched_manifest_path: Path,
        output_path: Path,
    ) -> dict[str, object]:
        manifest_path = enriched_manifest_path
        if not manifest_path.exists():
            manifest_path = Path(str(payload.get("rtti_manifest_path") or ""))
        recovered = ExternalToolAnalyzer._read_json(manifest_path)
        if not recovered:
            return {}
        decompiled_by_address = {
            ExternalToolAnalyzer._normalize_target_address(entry.get("entry_point") or entry.get("requested_address")): entry
            for entry in targeted_decompilation
            if isinstance(entry, dict)
            and ExternalToolAnalyzer._normalize_target_address(entry.get("entry_point") or entry.get("requested_address"))
        }
        classes: list[dict[str, object]] = []
        functions: list[dict[str, object]] = []
        for class_entry in recovered.get("classes") or []:
            if not isinstance(class_entry, dict):
                continue
            class_name = str(class_entry.get("name") or "").strip()
            if not class_name:
                continue
            methods: list[dict[str, object]] = []
            class_edges: list[dict[str, object]] = []
            for method in class_entry.get("methods") or []:
                if not isinstance(method, dict):
                    continue
                address = ExternalToolAnalyzer._normalize_target_address(method.get("address") or method.get("entry_point"))
                if not address:
                    continue
                decompiled = decompiled_by_address.get(address, {})
                call_edges = list(method.get("class_call_edges") or [])
                for callee in decompiled.get("callees") or []:
                    if not isinstance(callee, dict):
                        continue
                    target_address = ExternalToolAnalyzer._normalize_target_address(callee.get("entry_point") or callee.get("to_address"))
                    edge = {
                        "target": callee.get("name") or target_address,
                        "target_address": target_address,
                        "callsite": ExternalToolAnalyzer._normalize_target_address(callee.get("from_address")),
                        "ref_type": callee.get("ref_type"),
                    }
                    if edge not in call_edges:
                        call_edges.append(edge)
                method_context = {
                    "class_name": class_name,
                    "name": method.get("display_name") or method.get("name"),
                    "qualified_name": method.get("qualified_name") or f"{class_name}::{method.get('display_name') or method.get('name') or address}",
                    "address": address,
                    "slot": method.get("slot"),
                    "vtable_rva": method.get("vtable_rva"),
                    "method_kind": method.get("method_kind"),
                    "semantic_alias": method.get("semantic_alias"),
                    "name_inference_source": method.get("name_inference_source"),
                    "name_inference_evidence": method.get("name_inference_evidence"),
                    "original_vtable_name": method.get("original_vtable_name"),
                    "return_type": method.get("return_type") or decompiled.get("return_type"),
                    "params": method.get("params") or decompiled.get("parameters"),
                    "decompiler": {
                        "tool": "ghidra",
                        "success": decompiled.get("decompile_success"),
                        "name": decompiled.get("name"),
                        "signature": decompiled.get("signature"),
                        "pseudo_path": decompiled.get("pseudo_path"),
                        "target_selection": decompiled.get("target_selection"),
                    },
                    "callers": decompiled.get("callers") or method.get("caller_names") or [],
                    "callees": decompiled.get("callees") or [],
                    "call_edges": call_edges,
                    "llm_priority": ExternalToolAnalyzer._llm_method_priority(method, decompiled),
                    "evidence": ExternalToolAnalyzer._method_context_evidence(method, decompiled),
                }
                methods.append(method_context)
                functions.append(method_context)
                for edge in call_edges:
                    if isinstance(edge, dict):
                        class_edges.append({"source": method_context["qualified_name"], **edge})
            if methods:
                methods.sort(key=lambda item: (-int(item.get("llm_priority") or 0), str(item.get("qualified_name") or "")))
                classes.append(
                    {
                        "name": class_name,
                        "source_path": class_entry.get("source_path"),
                        "base_classes": class_entry.get("base_classes"),
                        "estimated_object_size": class_entry.get("estimated_object_size"),
                        "methods": methods,
                        "call_edges": class_edges[:512],
                        "recovery_capabilities": class_entry.get("recovery_capabilities"),
                    }
                )
        result = {
            "artifact_type": "ghidra_class_callgraph_manifest",
            "strategy": "msvc_rtti_vtable_methods_linked_to_ghidra_decompilation_and_calls",
            "class_count": len(classes),
            "function_count": len(functions),
            "classes": classes,
            "functions": sorted(functions, key=lambda item: (-int(item.get("llm_priority") or 0), str(item.get("qualified_name") or ""))),
        }
        ensure_dir(output_path.parent)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    @staticmethod
    def _llm_method_priority(method: dict[str, object], decompiled: dict[str, object]) -> int:
        score = 20
        if decompiled.get("decompile_success"):
            score += 50
        if method.get("method_kind"):
            score += 15
        if method.get("semantic_alias"):
            score += 10
        if decompiled.get("callees"):
            score += min(25, len(decompiled.get("callees") or []) * 5)
        if decompiled.get("callers"):
            score += min(25, len(decompiled.get("callers") or []) * 5)
        return score

    @staticmethod
    def _method_context_evidence(method: dict[str, object], decompiled: dict[str, object]) -> list[str]:
        evidence = ["msvc_rtti_vtable"]
        if method.get("semantic_alias"):
            evidence.append("semantic_alias")
        if method.get("method_kind"):
            evidence.append("method_kind")
        if decompiled.get("decompile_success"):
            evidence.append("ghidra_decompiled_body")
        if decompiled.get("target_selection"):
            evidence.append("ranked_target_selection")
        if decompiled.get("callees"):
            evidence.append("ghidra_call_edges")
        if decompiled.get("callers"):
            evidence.append("ghidra_callers")
        return evidence

    @staticmethod
    def _write_status(path: Path, payload: dict[str, object]) -> None:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
