from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..tooling import get_ghidra_install_root, list_ghidra_languages, resolve_command, run_command, run_command_logged
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class ExternalToolAnalyzer(Analyzer):
    name = "External RE tool adapters"

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
            ran_any |= self._run_rizin(context, report)
            ran_any |= self._run_radare2(context, report)
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
        full_command = command + [
            str(project_root),
            project_name,
            "-import",
            str(context.target),
            "-overwrite",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "REProExport.py",
            str(export_dir),
            "-scriptlog",
            str(script_log_path),
            "-log",
            str(log_path),
        ]

        profile = self._choose_ghidra_profile(context, report)
        if profile.get("language_id"):
            full_command += ["-processor", str(profile["language_id"])]
            if profile.get("compiler_id"):
                full_command += ["-cspec", str(profile["compiler_id"])]
        code, stdout, stderr = run_command_logged(
            full_command,
            cwd=context.target.parent,
            timeout=1800,
            logger=context.logger,
            label="ghidra",
            heartbeat_seconds=20,
        )
        if not log_path.exists():
            log_path.write_text((stdout or "") + ("\n" + stderr if stderr else ""), encoding="utf-8", errors="ignore")
        if code == 0:
            self._record_tool_execution(context, "ghidra", str(log_path), "Ghidra headless analysis")
            report.add_artifact(str(project_root), "ghidra", "Ghidra headless project")
            report.add_artifact(str(log_path), "log", "Ghidra headless log")
            if script_log_path.exists():
                report.add_artifact(str(script_log_path), "log", "Ghidra script log")
            export_count = self._collect_ghidra_exports(export_dir, report)
            report.add_finding(
                "Ghidra analysis completed",
                "Ghidra headless imported and analyzed the target binary.",
                severity="info",
            )
            if profile.get("note"):
                report.add_note(str(profile["note"]))
            if export_count == 0:
                report.add_note("Ghidra completed but the RE-Pro post-script did not produce structured exports.")
            context.log(f"Ghidra headless project written to {project_root}")
            return True

        report.add_note(f"Ghidra headless failed: {stderr.strip() or 'unknown error'}")
        return False

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

    def _run_rizin(self, context, report) -> bool:
        rizin = resolve_command([["rizin"]])
        rz_bin = resolve_command([["rz-bin"]])
        if rizin is None and rz_bin is None:
            return False

        output_dir = ensure_dir(context.output_dir / "rizin")
        ran = False
        if rz_bin is not None:
            ran |= self._capture_to_file(
                rz_bin + ["-I", str(context.target)],
                output_dir / "binary_info.txt",
                "text",
                "rizin binary metadata",
                context,
                report,
            )
            ran |= self._capture_to_file(
                rz_bin + ["-S", str(context.target)],
                output_dir / "sections.txt",
                "text",
                "rizin section listing",
                context,
                report,
            )
        if rizin is not None:
            ran |= self._capture_to_file(
                rizin + ["-A", "-q", "-c", "aflj", str(context.target)],
                output_dir / "functions.json",
                "json",
                "rizin function list",
                context,
                report,
            )
            ran |= self._capture_to_file(
                rizin + ["-A", "-q", "-c", "izj", str(context.target)],
                output_dir / "strings.json",
                "json",
                "rizin strings export",
                context,
                report,
            )
        return ran

    def _run_radare2(self, context, report) -> bool:
        r2 = resolve_command([["r2"], ["radare2"]])
        rabin2 = resolve_command([["rabin2"]])
        if r2 is None and rabin2 is None:
            return False

        output_dir = ensure_dir(context.output_dir / "radare2")
        ran = False
        if rabin2 is not None:
            ran |= self._capture_to_file(
                rabin2 + ["-I", str(context.target)],
                output_dir / "binary_info.txt",
                "text",
                "radare2 binary metadata",
                context,
                report,
            )
            ran |= self._capture_to_file(
                rabin2 + ["-S", str(context.target)],
                output_dir / "sections.txt",
                "text",
                "radare2 section listing",
                context,
                report,
            )
        if r2 is not None:
            ran |= self._capture_to_file(
                r2 + ["-A", "-q", "-c", "aflj", str(context.target)],
                output_dir / "functions.json",
                "json",
                "radare2 function list",
                context,
                report,
            )
            ran |= self._capture_to_file(
                r2 + ["-A", "-q", "-c", "izj", str(context.target)],
                output_dir / "strings.json",
                "json",
                "radare2 strings export",
                context,
                report,
            )
        return ran

    @staticmethod
    def _capture_to_file(command, destination: Path, category: str, description: str, context, report) -> bool:
        code, stdout, stderr = run_command(command, cwd=context.target.parent, timeout=1800)
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
        }
        count = 0
        for filename, (category, description) in descriptions.items():
            path = export_dir / filename
            if path.exists():
                report.add_artifact(str(path), category, description)
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
