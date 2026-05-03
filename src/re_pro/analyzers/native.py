from __future__ import annotations

import json
from pathlib import Path

from ..elf import elf_virtual_address_to_offset
from ..msvc_pseudo_cpp import class_output_paths, render_class_header, render_class_source, write_pseudo_class_sources
from ..msvc_rtti import recover_msvc_rtti
from ..symbolic_source import synthesize_symbolic_source_tree
from ..tooling import resolve_command, run_command
from ..utils import ensure_dir
from .base import Analyzer


class NativeLanguageAnalyzer(Analyzer):
    name = "Native language heuristics"
    CPP_IMPORT_MARKERS = ("msvcp", "vcruntime", "msvcprt", "libstdc++", "msvcrt")
    CPP_STRING_MARKERS = (
        "type_info",
        "std::",
        "class std::",
        "__cxxframehandler",
        "__cxxthrowexception",
        "__rtdynamiccast",
        "__gxx_personality_v0",
        "__cxa_throw",
        "__clang_call_terminate",
        "__cxxabiv1",
        "??_7",
        ".?av",
    )
    PACKER_SIGNATURES = {
        "Packed executable: UPX": {
            "sections": {"upx0", "upx1", "upx2"},
            "strings": ("upx!",),
        },
        "Packed executable: MPRESS": {
            "sections": {"mpress1", "mpress2"},
            "strings": (),
        },
        "Packed executable: ASPack": {
            "sections": {"aspack", ".aspack", "adata"},
            "strings": ("aspack",),
        },
        "Packed executable: PECompact": {
            "sections": {"pec1", "pec2", "pec3"},
            "strings": ("pecompact",),
        },
        "Protected executable: Themida/WinLicense": {
            "sections": {".themida", ".winlice", ".vlizer"},
            "strings": ("themida", "winlicense"),
        },
        "Protected executable: VMProtect": {
            "sections": {"vmp0", "vmp1", "vmp2"},
            "strings": ("vmprotect",),
        },
    }

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or (
            not context.probable_binary and context.pe_metadata is None and context.elf_metadata is None
        ):
            return

        strings_lower = [value.lower() for value in context.ascii_strings]
        imports_lower = [value.lower() for value in context.pe_imports] + [
            value.lower() for value in context.elf_needed_libraries
        ]
        sibling_names = {path.name.lower() for path in context.target.parent.iterdir()} if context.target.parent.exists() else set()
        section_names = {
            str(section.get("name", "")).lower() for section in [*context.pe_sections, *context.elf_sections]
        }
        detected_native = False
        detected_non_native = any(
            framework.startswith(prefix)
            for framework in report.frameworks
            for prefix in (".NET", "Python", "Electron", "Tauri", "Go native binary", "Rust native binary")
        )

        if context.elf_metadata is not None:
            report.add_framework("ELF")
            elf_machine = context.elf_metadata.get("machine", "unknown")
            elf_type = context.elf_metadata.get("type", "unknown")
            elf_sections = ", ".join(str(section.get("name", "")) for section in context.elf_sections if section.get("name")) or "none"
            section_names = {str(section.get("name", "")).lower() for section in context.elf_sections if section.get("name")}
            linux_style = bool(
                context.elf_interpreter
                or context.elf_needed_libraries
                or section_names.intersection({".dynamic", ".dynsym", ".dynstr", ".gnu.version", ".gnu.hash", ".interp"})
            )
            report.add_note(
                f"ELF {elf_type} for {elf_machine} ({context.elf_metadata.get('bits')}-bit, {context.elf_metadata.get('endianness')} endian) with sections: {elf_sections}."
            )
            if context.elf_program_headers:
                segment_summary = ", ".join(
                    f"{segment.get('type_name')}@0x{int(segment.get('virtual_address', 0)):x}/{int(segment.get('file_size', 0))}B"
                    for segment in context.elf_program_headers[:8]
                )
                report.add_note(f"ELF program headers: {segment_summary}")
            if elf_type == "executable":
                if linux_style:
                    report.add_framework("Linux ELF executable")
                else:
                    report.add_framework("Static ELF executable")
            elif elf_type == "shared-object":
                if context.elf_interpreter or ".so" not in context.target.name:
                    if linux_style:
                        report.add_framework("Linux ELF position-independent executable")
                        report.add_note("The ELF header is ET_DYN, which commonly indicates a PIE executable rather than a shared library.")
                    else:
                        report.add_framework("Static ELF position-independent executable")
                else:
                    report.add_framework("ELF shared object")
            if context.elf_interpreter:
                report.add_note(f"ELF interpreter: {context.elf_interpreter}")
            if context.elf_needed_libraries:
                report.add_note(f"ELF needed libraries: {', '.join(context.elf_needed_libraries[:20])}")
            self._add_mips_elf_heuristics(context, report)
            self._write_elf_artifacts(context, report)
            detected_native = True

        if any(marker in value for value in strings_lower for marker in ("rustc/", "cargo", "panic_bounds_check", "std::rt::lang_start")):
            report.add_framework("Rust native binary")
            report.add_finding(
                "Rust markers detected",
                "The executable contains strings commonly emitted by Rust toolchains or runtimes.",
                severity="info",
            )
            detected_native = True

        if any(marker in value for value in strings_lower for marker in ("go build id", "gopclntab", "command-line-arguments", "runtime.main")):
            report.add_framework("Go native binary")
            report.add_finding(
                "Go markers detected",
                "The executable contains Go runtime fingerprints.",
                severity="info",
            )
            detected_native = True

        for framework, signature in self.PACKER_SIGNATURES.items():
            matched = bool(section_names.intersection(signature["sections"])) or any(
                marker in value for value in strings_lower for marker in signature["strings"]
            )
            if not matched:
                continue
            report.add_framework(framework)
            report.add_finding(
                framework.replace(": ", " detected: "),
                f"The PE sections or strings indicate the executable matches {framework.split(': ', 1)[1]}.",
                severity="info",
            )
            if framework == "Packed executable: UPX":
                self._attempt_upx_unpack(context, report)
            elif framework.startswith("Packed executable:"):
                self._attempt_7z_unpack(context, report, framework)
            detected_native = True

        qt_sibling = any("qt5" in name or "qt6" in name for name in sibling_names)
        qt_import = any("qt5" in name or "qt6" in name for name in imports_lower)
        if qt_sibling or qt_import or (context.target.parent / "platforms" / "qwindows.dll").exists():
            report.add_framework("Qt application")
            report.add_finding(
                "Qt framework detected",
                "The executable imports or ships with Qt runtime libraries.",
                severity="info",
            )
            detected_native = True

        cpp_runtime_detected = any(
            marker in name for name in sibling_names for marker in ("vcruntime140", "msvcp140", "concrt140")
        ) or any(marker in value for value in imports_lower for marker in self.CPP_IMPORT_MARKERS)
        cpp_rtti_detected = any(marker in value for value in strings_lower for marker in self.CPP_STRING_MARKERS)
        if cpp_runtime_detected or cpp_rtti_detected:
            report.add_framework("Native C/C++ application")
            if cpp_rtti_detected:
                report.add_note("C++ RTTI, exception, or standard-library markers were detected in the binary strings.")
            detected_native = True

        if not detected_non_native and context.pe_metadata is not None and any(
            dll in imports_lower for dll in ("user32.dll", "gdi32.dll", "comctl32.dll", "shell32.dll", "ole32.dll")
        ):
            report.add_framework("Native Windows application")
            detected_native = True

        if context.pe_metadata is not None:
            rtti_recovery = self._recover_msvc_rtti(context, report)
            if rtti_recovery:
                report.add_framework("MSVC RTTI")
                report.add_framework("Native C/C++ application")
                detected_native = True

        if not detected_native:
            return

        report.add_note(
            "Native binaries usually require disassembly/decompiler tooling and cannot reliably restore original file names unless debug paths, PDBs, or embedded assets are present."
        )
        self._attempt_symbol_dump(context, report)
        self._attempt_capstone_disassembly(context, report)
        self._attempt_disassembly(context, report)

    @staticmethod
    def _recover_msvc_rtti(context, report) -> dict[str, object] | None:
        recovered = recover_msvc_rtti(context.target, context.pe_metadata, context.pe_sections)
        if not recovered:
            return None

        output_dir = ensure_dir(context.output_dir / "native")
        manifest_path = output_dir / "msvc_rtti_classes.json"
        manifest_path.write_text(json.dumps(recovered, indent=2), encoding="utf-8")
        report.add_artifact(str(manifest_path), "json", "MSVC RTTI class manifest")

        classes_dir = ensure_dir(output_dir / "pseudo_cpp")
        generated = NativeLanguageAnalyzer._write_pseudo_class_sources(classes_dir, recovered)
        if generated:
            report.add_artifact(str(classes_dir), "directory", "Pseudo-C++ classes recovered from MSVC RTTI")
            for original_path, restored_path in generated:
                report.add_recovered_source(original_path, restored_path, "msvc_rtti")

        class_count = int(recovered.get("class_count", 0) or 0)
        vtable_count = int(recovered.get("vtable_count", 0) or 0)
        method_count = sum(len(entry.get("methods", [])) for entry in recovered.get("classes", []))
        report.add_finding(
            "MSVC RTTI classes recovered",
            "RE-Pro reconstructed class, vtable, and virtual-method candidates from MSVC RTTI data embedded in the PE image.",
            severity="info",
            details=f"classes={class_count}; vtables={vtable_count}; methods={method_count}",
        )
        report.add_note(
            f"MSVC RTTI recovery found {class_count} class candidate(s), {vtable_count} vtable(s), and {method_count} virtual method address(es)."
        )
        if generated:
            report.add_note("RE-Pro synthesized pseudo-C++ headers and source stubs from recovered RTTI/vtable metadata.")
        return recovered

    @staticmethod
    def _write_pseudo_class_sources(output_dir: Path, recovered: dict[str, object]) -> list[tuple[str, str]]:
        return write_pseudo_class_sources(output_dir, recovered)

    @staticmethod
    def _class_output_paths(output_dir: Path, class_name: str) -> tuple[Path, Path]:
        return class_output_paths(output_dir, class_name)

    @staticmethod
    def _render_class_header(class_entry: dict[str, object]) -> str:
        return render_class_header(class_entry)

    @staticmethod
    def _render_class_source(class_entry: dict[str, object], header_name: str) -> str:
        return render_class_source(class_entry, header_name)

    @staticmethod
    def _render_base_clause(base_classes: list[str]) -> str:
        if not base_classes:
            return ""
        rendered = ", ".join(f"public {value}" for value in base_classes)
        return f" : {rendered}"

    @staticmethod
    def _write_elf_artifacts(context, report) -> None:
        if context.elf_metadata is None:
            return
        output_dir = ensure_dir(context.output_dir / "elf")
        metadata_path = output_dir / "metadata.json"
        metadata_payload = {
            "metadata": context.elf_metadata,
            "program_headers": context.elf_program_headers,
            "interpreter": context.elf_interpreter,
            "needed_libraries": context.elf_needed_libraries,
        }
        metadata_path.write_text(json.dumps(metadata_payload, indent=2), encoding="utf-8")
        report.add_artifact(str(metadata_path), "manifest", "ELF metadata manifest")

        if context.elf_program_headers:
            segments_path = output_dir / "program_headers.json"
            segments_path.write_text(json.dumps(context.elf_program_headers, indent=2), encoding="utf-8")
            report.add_artifact(str(segments_path), "json", "ELF program-header listing")
        if context.elf_sections:
            sections_path = output_dir / "sections.json"
            sections_path.write_text(json.dumps(context.elf_sections, indent=2), encoding="utf-8")
            report.add_artifact(str(sections_path), "json", "ELF section listing")
        if context.elf_symbols:
            symbols_path = output_dir / "symbols.json"
            symbols_path.write_text(json.dumps(context.elf_symbols, indent=2), encoding="utf-8")
            report.add_artifact(str(symbols_path), "json", "ELF symbol listing")

    @classmethod
    def _attempt_capstone_disassembly(cls, context, report) -> None:
        if context.elf_metadata is None:
            return
        capstone = cls._load_capstone()
        if capstone is None:
            report.add_note("Install the Python `capstone` package to enable fast entry-point disassembly previews for ELF binaries.")
            return

        region = cls._select_elf_executable_region(context)
        if region is None:
            report.add_note("No executable ELF section or load segment was found for Capstone preview disassembly.")
            return

        mode = cls._capstone_mode(capstone, context.elf_metadata)
        if mode is None:
            report.add_note(f"Capstone preview is not configured for ELF machine {context.elf_metadata.get('machine')}.")
            return

        try:
            disassembler = capstone.Cs(mode[0], mode[1])
            disassembler.detail = False
        except Exception as exc:
            report.add_note(f"Capstone initialization failed: {exc}")
            return

        try:
            data = context.target.read_bytes()
        except OSError as exc:
            report.add_note(f"Capstone could not read the ELF binary: {exc}")
            return

        offset = int(region.get("offset", 0))
        size = int(region.get("size", 0))
        address = int(region.get("address", 0))
        if offset < 0 or size <= 0 or offset >= len(data):
            return

        preview = data[offset : min(offset + min(size, 768), len(data))]
        try:
            instructions = list(disassembler.disasm(preview, address))
        except Exception as exc:
            report.add_note(f"Capstone disassembly failed: {exc}")
            return
        if not instructions:
            report.add_note("Capstone did not yield any ELF instructions from the selected executable region.")
            return

        output_dir = ensure_dir(context.output_dir / "elf")
        preview_path = output_dir / "capstone_preview.txt"
        lines = [
            f"; region={region.get('name') or '<unnamed>'} address=0x{address:x} size={size}",
        ]
        for instruction in instructions[:64]:
            operand_text = instruction.op_str.strip()
            lines.append(
                f"0x{instruction.address:x}:\t{instruction.mnemonic}"
                + (f"\t{operand_text}" if operand_text else "")
            )
        preview_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report.add_artifact(str(preview_path), "text", "Capstone ELF entry/text preview")
        report.add_note(
            f"Capstone recovered a fast preview of {min(len(instructions), 64)} instruction(s) from ELF region {region.get('name') or '<unnamed>'}."
        )
        if str(context.elf_metadata.get("machine")) == "MIPS" and "PlayStation 2 ELF" in report.frameworks:
            report.add_note("Capstone uses generic MIPS decoding here; PS2 Emotion Engine extensions may require a specialist decompiler or Ghidra plugin for full fidelity.")

    @staticmethod
    def _load_capstone():
        try:
            import capstone  # type: ignore
        except ImportError:
            return None
        return capstone

    @staticmethod
    def _select_elf_executable_region(context):
        entry_point = int(context.elf_metadata.get("entry_point", 0)) if context.elf_metadata else 0
        if entry_point > 0:
            entry_offset = elf_virtual_address_to_offset(entry_point, context.elf_sections, context.elf_program_headers)
            if entry_offset is not None:
                for section in context.elf_sections:
                    section_address = int(section.get("address", 0))
                    section_size = int(section.get("size", 0))
                    if section_address <= entry_point < section_address + max(section_size, int(section.get("entry_size", 0))):
                        return {
                            "name": f"{str(section.get('name') or '<unnamed-section>')}@entry",
                            "offset": entry_offset,
                            "size": max(section_size - (entry_point - section_address), 0),
                            "address": entry_point,
                        }
                for program_header in context.elf_program_headers:
                    virtual_address = int(program_header.get("virtual_address", 0))
                    file_size = int(program_header.get("file_size", 0))
                    if virtual_address <= entry_point < virtual_address + file_size and "EXECUTE" in program_header.get("flag_names", []):
                        return {
                            "name": f"entry:{program_header.get('type_name', 'LOAD').lower()}[{program_header.get('index', 0)}]",
                            "offset": entry_offset,
                            "size": max(file_size - (entry_point - virtual_address), 0),
                            "address": entry_point,
                        }
        for preferred in (".text", ".init", ".plt"):
            for section in context.elf_sections:
                if str(section.get("name")) == preferred:
                    return {
                        "name": str(section.get("name") or "<unnamed-section>"),
                        "offset": int(section.get("offset", 0)),
                        "size": int(section.get("size", 0)),
                        "address": int(section.get("address", 0)),
                    }
        for section in context.elf_sections:
            if "EXECINSTR" in section.get("flag_names", []):
                return {
                    "name": str(section.get("name") or "<unnamed-section>"),
                    "offset": int(section.get("offset", 0)),
                    "size": int(section.get("size", 0)),
                    "address": int(section.get("address", 0)),
                }
        for program_header in context.elf_program_headers:
            if "EXECUTE" in program_header.get("flag_names", []) and int(program_header.get("file_size", 0)) > 0:
                return {
                    "name": f"segment:{program_header.get('type_name', 'LOAD').lower()}[{program_header.get('index', 0)}]",
                    "offset": int(program_header.get("offset", 0)),
                    "size": int(program_header.get("file_size", 0)),
                    "address": int(program_header.get("virtual_address", 0)),
                }
        return None

    @staticmethod
    def _capstone_mode(capstone, elf_metadata):
        machine = str(elf_metadata.get("machine", ""))
        bits = int(elf_metadata.get("bits", 0))
        endianness = str(elf_metadata.get("endianness", "little"))
        endian_flag = capstone.CS_MODE_BIG_ENDIAN if endianness == "big" else capstone.CS_MODE_LITTLE_ENDIAN

        if machine == "x86":
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_32 | endian_flag)
        if machine == "x86_64":
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_64 | endian_flag)
        if machine == "ARM":
            return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian_flag)
        if machine == "ARM64":
            return (capstone.CS_ARCH_ARM64, endian_flag)
        if machine == "MIPS":
            return (capstone.CS_ARCH_MIPS, (capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32) | endian_flag)
        return None

    @staticmethod
    def _add_mips_elf_heuristics(context, report) -> None:
        if context.elf_metadata is None or str(context.elf_metadata.get("machine")) != "MIPS":
            return

        endianness = str(context.elf_metadata.get("endianness", "little"))
        bits = int(context.elf_metadata.get("bits", 0))
        report.add_framework("MIPS ELF")
        report.add_framework(f"MIPS {endianness}-endian ELF")

        mips_flags = context.elf_metadata.get("mips_flags")
        if isinstance(mips_flags, dict):
            details = []
            if mips_flags.get("arch"):
                details.append(f"arch={mips_flags['arch']}")
            if mips_flags.get("machine_variant"):
                details.append(f"machine={mips_flags['machine_variant']}")
            if mips_flags.get("abi"):
                details.append(f"abi={mips_flags['abi']}")
            if mips_flags.get("flags"):
                details.append(f"flags={', '.join(str(value) for value in mips_flags['flags'])}")
            if details:
                report.add_note(f"MIPS ELF flags: {'; '.join(details)}")

        if not context.elf_sections and context.elf_program_headers:
            report.add_framework("Sectionless ELF")
            report.add_note("This ELF omits a section table and only exposes program headers, which is common in stripped or console-style binaries.")

        section_names = {str(section.get("name", "")).lower() for section in context.elf_sections if section.get("name")}
        ps2_filename_markers = ("ps2", "slus_", "scus_", "sles_", "slps_", "scps_")
        ps2_string_markers = ("ps2sdk", "ps2dev", "rom0:", "mc0:", "host:", "cdvd", "sif", "padman", "iop")
        strings_lower = [value.lower() for value in context.ascii_strings]
        mips_machine_variant = str(mips_flags.get("machine_variant", "")) if isinstance(mips_flags, dict) else ""
        filename_lower = context.target.name.lower()

        ps2_confidence = 0
        if bits == 32 and endianness == "little" and str(context.elf_metadata.get("type")) == "executable":
            ps2_confidence += 1
        if "r5900" in mips_machine_variant.lower():
            ps2_confidence += 3
        if any(marker in filename_lower for marker in ps2_filename_markers):
            ps2_confidence += 2
        if any(marker in value for value in strings_lower for marker in ps2_string_markers):
            ps2_confidence += 2
        if not context.elf_interpreter and not context.elf_needed_libraries and not context.elf_sections and context.elf_program_headers:
            ps2_confidence += 1
        if {".mdebug", ".reginfo"}.intersection(section_names):
            ps2_confidence += 1

        if ps2_confidence >= 3:
            report.add_framework("PlayStation 2 ELF")
            report.add_note("The ELF matches a PS2-style MIPS executable profile based on its MIPS format, static layout, and PS2-oriented markers.")
            if {".mdebug", ".reginfo"}.intersection(section_names):
                report.add_note("PS2/MIPS debug-related sections such as .mdebug or .reginfo are present and may help downstream symbol recovery.")

    @staticmethod
    def _attempt_disassembly(context, report) -> None:
        command = resolve_command([["llvm-objdump"], ["objdump"]])
        if command is None:
            report.add_note("Install `llvm-objdump` or `objdump` to enable automatic disassembly output.")
            return

        output_dir = ensure_dir(context.output_dir / "native")
        disassembly_path = output_dir / "disassembly.txt"
        if context.elf_metadata is not None and Path(command[0]).name.lower().startswith("llvm-objdump"):
            full_command = command + ["--disassemble", str(context.target)]
        else:
            full_command = command + ["-d", str(context.target)]
        code, stdout, stderr = run_command(full_command, cwd=context.target.parent, timeout=600)
        if code != 0 or not stdout.strip():
            report.add_note(f"Disassembly command failed: {stderr.strip() or 'unknown error'}")
            return

        disassembly_path.write_text(stdout, encoding="utf-8", errors="ignore")
        report.add_artifact(str(disassembly_path), "text", f"Disassembly produced by {' '.join(command)}")

    @staticmethod
    def _attempt_symbol_dump(context, report) -> None:
        output_dir = ensure_dir(context.output_dir / "native")
        symbol_path = output_dir / "symbols.txt"

        if context.elf_symbols:
            output_dir = ensure_dir(context.output_dir / "elf")
            symbol_path = output_dir / "symbols.txt"
            rendered = []
            for symbol in context.elf_symbols[:512]:
                rendered.append(
                    f"{symbol.get('value', 0):016x} {symbol.get('binding', '?'):>6} {symbol.get('type', '?'):>7} "
                    f"{symbol.get('section_name', ''):>16} {symbol.get('name', '')}"
                )
            symbol_path.write_text("\n".join(rendered) + "\n", encoding="utf-8")
            report.add_artifact(str(symbol_path), "text", "ELF symbol listing (parsed)")
            if any(str(symbol.get("type")) == "FUNC" for symbol in context.elf_symbols):
                report.add_note("Recovered ELF function symbols from .symtab/.dynsym.")
                generated = synthesize_symbolic_source_tree(
                    ensure_dir(output_dir / "recovered_src"),
                    origin_label="ELF function symbols",
                    function_names=[str(symbol.get("name", "")) for symbol in context.elf_symbols if str(symbol.get("type")) == "FUNC"],
                )
                if generated:
                    report.add_artifact(str(output_dir / "recovered_src"), "directory", "Pseudo-source tree synthesized from ELF symbols")
                    for original_path, restored_path in generated:
                        report.add_recovered_source(original_path, restored_path, "elf_symbols")
            return

        nm_command = resolve_command([["llvm-nm"], ["nm"]])
        if nm_command is not None:
            full_command = nm_command + ["--demangle", "--numeric-sort", str(context.target)]
            code, stdout, stderr = run_command(full_command, cwd=context.target.parent, timeout=600)
            if code == 0 and stdout.strip():
                symbol_path.write_text(stdout, encoding="utf-8", errors="ignore")
                report.add_artifact(str(symbol_path), "text", f"Native symbol listing produced by {' '.join(nm_command)}")
                generated = synthesize_symbolic_source_tree(
                    ensure_dir(output_dir / "recovered_src"),
                    origin_label=f"native symbols via {' '.join(nm_command)}",
                    function_names=[line.strip().split()[-1] for line in stdout.splitlines() if line.strip() and len(line.strip().split()) >= 3],
                )
                if generated:
                    report.add_artifact(str(output_dir / "recovered_src"), "directory", "Pseudo-source tree synthesized from native symbols")
                    for original_path, restored_path in generated:
                        report.add_recovered_source(original_path, restored_path, "native_symbols")
                return
            message = stderr.strip() or stdout.strip()
            if message:
                report.add_note(f"Symbol listing command failed: {message}")
            return

        objdump_command = resolve_command([["llvm-objdump"], ["objdump"]])
        if objdump_command is not None:
            full_command = objdump_command + ["-C", "-t", str(context.target)]
            code, stdout, stderr = run_command(full_command, cwd=context.target.parent, timeout=600)
            if code == 0 and stdout.strip():
                symbol_path.write_text(stdout, encoding="utf-8", errors="ignore")
                report.add_artifact(str(symbol_path), "text", f"Native symbol table produced by {' '.join(objdump_command)}")
                return
            message = stderr.strip() or stdout.strip()
            if message:
                report.add_note(f"Symbol table extraction failed: {message}")
            return

        report.add_note("Install `llvm-nm`, `nm`, or `objdump` to export native symbol listings when symbols are present.")

    @staticmethod
    def _attempt_upx_unpack(context, report) -> None:
        command = resolve_command([["upx"]])
        if command is None:
            report.add_note("Install `upx` to enable automatic unpacking of UPX-packed executables.")
            return

        output_dir = ensure_dir(context.output_dir / "native")
        unpacked_path = output_dir / f"{context.target.stem}.unpacked{context.target.suffix}"
        full_command = command + ["-d", "-o", str(unpacked_path), str(context.target)]
        code, stdout, stderr = run_command(full_command, cwd=context.target.parent, timeout=1200)
        if code == 0 and unpacked_path.exists():
            report.add_artifact(str(unpacked_path), "binary", "UPX-unpacked executable")
            report.add_finding(
                "UPX unpacking succeeded",
                "UPX produced an unpacked copy of the executable for deeper analysis.",
                severity="info",
            )
            context.log(f"UPX unpacked executable written to {unpacked_path}")
            return
        message = stderr.strip() or stdout.strip() or "unknown error"
        report.add_note(f"UPX unpacking failed: {message}")

    @staticmethod
    def _attempt_7z_unpack(context, report, framework: str) -> None:
        command = resolve_command([["7z", "x", "-y", f"-o{context.output_dir / 'native' / '7z_extract'}", str(context.target)]])
        if command is None:
            report.add_note(f"Install `7z` to try generic extraction for {framework.split(': ', 1)[1]}.")
            return
        code, stdout, stderr = run_command(command, cwd=context.target.parent, timeout=1200)
        destination = context.output_dir / "native" / "7z_extract"
        extracted_files = [path for path in destination.rglob("*") if path.is_file()] if destination.exists() else []
        if code == 0 and extracted_files:
            report.add_artifact(str(destination), "directory", f"7-Zip extraction output for {framework}")
            report.add_note(f"7-Zip extracted {len(extracted_files)} files while probing {framework.split(': ', 1)[1]}.")
            return
        message = stderr.strip() or stdout.strip()
        if message:
            report.add_note(f"7-Zip extraction probe for {framework.split(': ', 1)[1]} did not yield files: {message}")
