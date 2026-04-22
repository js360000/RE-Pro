from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ..sourcemap import restore_sources_from_map
from ..tooling import resolve_command, run_command
from ..utils import ensure_dir, extract_ascii_strings, parse_macho_metadata, parse_plist
from .base import Analyzer


class AppleAnalyzer(Analyzer):
    name = "Apple package recovery"

    def analyze(self, context, report) -> None:
        target = context.target
        if target.is_dir() and self._looks_like_app_bundle(target):
            self._analyze_app_bundle(target, report, context)
            return
        if not target.is_file():
            return

        suffix = target.suffix.lower()
        if suffix in {".dmg", ".pkg"}:
            self._analyze_archive(target, report, context)
            return

        metadata = parse_macho_metadata(target)
        if metadata:
            self._record_macho(target, metadata, report)
            self._run_macos_external_tools(target, report, context)

    def _analyze_app_bundle(self, bundle_dir: Path, report, context) -> None:
        contents_dir = bundle_dir / "Contents"
        resources_dir = contents_dir / "Resources"
        frameworks_dir = contents_dir / "Frameworks"
        info_path = contents_dir / "Info.plist"

        report.target_type = "macos-app-bundle"
        report.add_framework("Apple app bundle (.app)")
        report.add_artifact(str(bundle_dir), "directory", "Apple app bundle")

        info = parse_plist(info_path) if info_path.exists() else None
        executable_path: Path | None = None
        if info:
            report.add_artifact(str(info_path), "manifest", "Info.plist")
            bundle_id = info.get("CFBundleIdentifier")
            bundle_name = info.get("CFBundleName") or info.get("CFBundleDisplayName")
            bundle_version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            executable_name = info.get("CFBundleExecutable")
            if bundle_id or bundle_name or bundle_version:
                report.add_note(
                    "Info.plist: "
                    + ", ".join(
                        part
                        for part in (
                            f"bundle_id={bundle_id}" if bundle_id else "",
                            f"name={bundle_name}" if bundle_name else "",
                            f"version={bundle_version}" if bundle_version else "",
                        )
                        if part
                    )
                )
            if executable_name:
                executable_path = contents_dir / "MacOS" / str(executable_name)
        if executable_path is None:
            executables = sorted((contents_dir / "MacOS").glob("*")) if (contents_dir / "MacOS").exists() else []
            executable_path = executables[0] if executables else None

        strings: list[str] = []
        if executable_path and executable_path.exists():
            report.add_artifact(str(executable_path), "binary", "Primary macOS executable")
            metadata = parse_macho_metadata(executable_path)
            if metadata:
                self._record_macho(executable_path, metadata, report, preserve_target_type=True)
            try:
                strings = extract_ascii_strings(executable_path.read_bytes()[:2_000_000])
            except OSError:
                strings = []
            self._run_macos_external_tools(executable_path, report, context)

        if frameworks_dir.exists() and any(path.name.startswith("Electron Framework") for path in frameworks_dir.iterdir()):
            report.add_framework("Electron")
        if resources_dir.exists():
            self._inspect_macos_resources(resources_dir, report, context, strings)

    def _analyze_archive(self, target: Path, report, context) -> None:
        family = "Apple disk image (.dmg)" if target.suffix.lower() == ".dmg" else "Apple installer package (.pkg)"
        report.add_framework(family)
        report.add_finding(
            "Apple archive detected",
            "The target appears to be an Apple packaging wrapper that should be extracted before deeper analysis.",
            severity="info",
        )
        extracted_dir = self._extract_with_7z(target, context, report)
        if extracted_dir is None:
            report.add_note("Automatic Apple archive extraction requires 7-Zip on this system.")
            return
        report.add_artifact(str(extracted_dir), "directory", f"Extracted {target.suffix.lower()} contents")
        app_bundles = sorted(path for path in extracted_dir.rglob("*.app") if path.is_dir())
        if app_bundles:
            report.add_note(f"Recovered {len(app_bundles)} app bundle(s) from the archive.")
            self._analyze_app_bundle(app_bundles[0], report, context)

    def _inspect_macos_resources(self, resources_dir: Path, report, context, strings: list[str]) -> None:
        app_dir = resources_dir / "app"
        unpacked_dir = resources_dir / "app.asar.unpacked"
        asar_path = resources_dir / "app.asar"

        search_roots: list[Path] = []
        if app_dir.exists():
            search_roots.append(app_dir)
            report.add_framework("Electron")
            report.add_artifact(str(app_dir), "directory", "Unpacked Electron app resources")
        if unpacked_dir.exists():
            search_roots.append(unpacked_dir)
            report.add_framework("Electron")
            report.add_artifact(str(unpacked_dir), "directory", "Electron unpacked asar resources")
        if asar_path.exists():
            report.add_framework("Electron")
            report.add_artifact(str(asar_path), "archive", "Electron app.asar archive")
            extracted_dir = self._extract_asar(asar_path, context)
            if extracted_dir:
                search_roots.append(extracted_dir)
                report.add_artifact(str(extracted_dir), "directory", "Extracted macOS app.asar contents")

        if any(value.startswith("/_next/static/") for value in self._collect_embedded_like_paths(resources_dir)):
            report.add_framework("Web framework: Next.js")
        if self._find_first(resources_dir, "index.html") and any(marker in value.lower() for value in strings for marker in ("__tauri", "tauri://", "wry", "tao::")):
            report.add_framework("Tauri")
            report.add_framework("Rust native binary")

        if search_roots:
            package_json = self._find_first_in_roots(search_roots, "package.json") or self._find_first(resources_dir, "package.json")
            if package_json:
                report.add_artifact(str(package_json), "manifest", "Recovered package.json")
                self._record_package_metadata(package_json, report)
        map_files = self._collect_files_in_roots(search_roots or [resources_dir], "*.map")
        self._restore_source_maps(map_files, report, context)

    def _restore_source_maps(self, map_files: list[Path], report, context) -> None:
        if not map_files:
            return
        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        restored_total = 0
        for map_file in map_files:
            restored_sources, notes = restore_sources_from_map(map_file, recovered_root)
            for source in restored_sources:
                report.add_recovered_source(
                    original_path=source.original_path,
                    restored_path=source.restored_path,
                    source_map=source.source_map,
                )
            restored_total += len(restored_sources)
            report.notes.extend(notes)
        if restored_total:
            report.add_finding(
                "macOS source map restoration succeeded",
                f"Recovered {restored_total} original source files from macOS packaged web assets.",
                severity="info",
            )
            report.add_note(f"Recovered {restored_total} original source files from packaged macOS web assets.")

    def _run_macos_external_tools(self, binary_path: Path, report, context) -> None:
        llvm_objdump = resolve_command([["llvm-objdump"]])
        llvm_nm = resolve_command([["llvm-nm"]])
        rizin = resolve_command([["rizin"]])
        rz_bin = resolve_command([["rz-bin"]])
        r2 = resolve_command([["r2"], ["radare2"]])
        rabin2 = resolve_command([["rabin2"]])
        any_available = any(tool is not None for tool in (llvm_objdump, llvm_nm, rizin, rz_bin, r2, rabin2))

        if not context.run_external_tools:
            if any_available:
                report.add_note("Mach-O external tooling is installed locally but skipped for this run. Enable external tools for symbol, header, and disassembly exports.")
            return

        output_dir = ensure_dir(context.output_dir / "macos")
        if llvm_objdump is not None:
            self._capture_output(
                llvm_objdump + ["--macho", "--private-headers", str(binary_path)],
                output_dir / "headers.txt",
                "text",
                "Mach-O headers via llvm-objdump",
                report,
                context,
            )
            self._capture_output(
                llvm_objdump + ["--macho", "-d", str(binary_path)],
                output_dir / "disassembly.txt",
                "text",
                "Mach-O disassembly via llvm-objdump",
                report,
                context,
            )
        else:
            report.add_note("Install `llvm-objdump` to export Mach-O headers and disassembly.")

        if llvm_nm is not None:
            self._capture_output(
                llvm_nm + ["--demangle", str(binary_path)],
                output_dir / "symbols.txt",
                "text",
                "Mach-O symbols via llvm-nm",
                report,
                context,
            )
        else:
            report.add_note("Install `llvm-nm` to export Mach-O symbol listings.")

        if rz_bin is not None:
            self._capture_output(
                rz_bin + ["-I", str(binary_path)],
                output_dir / "rizin_binary_info.txt",
                "text",
                "rizin Mach-O metadata",
                report,
                context,
            )
        if rizin is not None:
            self._capture_output(
                rizin + ["-A", "-q", "-c", "aflj", str(binary_path)],
                output_dir / "rizin_functions.json",
                "json",
                "rizin Mach-O function list",
                report,
                context,
            )
        if rabin2 is not None:
            self._capture_output(
                rabin2 + ["-I", str(binary_path)],
                output_dir / "radare2_binary_info.txt",
                "text",
                "radare2 Mach-O metadata",
                report,
                context,
            )
        if r2 is not None:
            self._capture_output(
                r2 + ["-A", "-q", "-c", "aflj", str(binary_path)],
                output_dir / "radare2_functions.json",
                "json",
                "radare2 Mach-O function list",
                report,
                context,
            )

    @staticmethod
    def _record_macho(target: Path, metadata: dict[str, object], report, *, preserve_target_type: bool = False) -> None:
        if not preserve_target_type or report.target_type == "unknown":
            report.target_type = "mach-o"
        report.add_framework("Mach-O")
        for key, value in metadata.items():
            report.fingerprints.setdefault(key, value)
        if metadata.get("format") == "mach-o-fat":
            report.add_note(
                f"Mach-O universal/fat binary with {metadata.get('architectures')} architecture entries."
            )
        else:
            report.add_note(
                f"Mach-O {metadata.get('bits')}-bit {metadata.get('cpu_type')} {metadata.get('file_type')} with {metadata.get('load_commands')} load commands."
            )
        report.add_artifact(str(target), "binary", "Mach-O binary")

    @staticmethod
    def _looks_like_app_bundle(path: Path) -> bool:
        return path.suffix.lower() == ".app" and (path / "Contents").exists()

    @staticmethod
    def _extract_with_7z(target: Path, context, report) -> Path | None:
        destination = ensure_dir(context.output_dir / "apple_extract")
        log_path = context.output_dir / "apple_extract.log"
        command = resolve_command([["7z", "x", "-y", f"-o{destination}", str(target)]])
        if command is None:
            return None
        code, stdout, stderr = run_command(command, cwd=target.parent, timeout=1800)
        log_path.write_text((stdout or "") + ("\n" + stderr if stderr else ""), encoding="utf-8", errors="ignore")
        report.add_artifact(str(log_path), "log", "7-Zip Apple archive extraction log")
        if code == 0:
            return destination
        if any(destination.iterdir()):
            if stderr.strip():
                report.add_note("7-Zip extracted the Apple archive with Windows symlink errors, but the recovered files appear usable.")
            context.log(f"7-Zip extraction returned {code}, continuing with partially extracted Apple archive at {destination}")
            return destination
        context.log(f"7-Zip extraction failed for Apple archive: {stderr.strip()}")
        return None

    @staticmethod
    def _extract_asar(asar_path: Path, context) -> Path | None:
        destination = ensure_dir(context.output_dir / "macos_extracted_asar")
        command = resolve_command(
            [
                ["asar", "extract", str(asar_path), str(destination)],
                ["npx", "-y", "@electron/asar", "extract", str(asar_path), str(destination)],
            ]
        )
        if command is None:
            return None
        code, _, stderr = run_command(command, cwd=asar_path.parent, timeout=300)
        if code == 0:
            return destination
        context.log(f"asar extraction failed: {stderr.strip()}")
        return None

    @staticmethod
    def _find_first(root: Path, name: str) -> Path | None:
        for candidate in root.rglob(name):
            return candidate
        return None

    @staticmethod
    def _find_first_in_roots(roots: list[Path], name: str) -> Path | None:
        for root in roots:
            if root.is_file() and root.name == name:
                return root
            if not root.exists() or not root.is_dir():
                continue
            direct = root / name
            if direct.exists():
                return direct
            nested = AppleAnalyzer._find_first(root, name)
            if nested:
                return nested
        return None

    @staticmethod
    def _collect_files_in_roots(roots: list[Path], pattern: str) -> list[Path]:
        seen: set[Path] = set()
        results: list[Path] = []
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for candidate in root.rglob(pattern):
                if candidate in seen:
                    continue
                seen.add(candidate)
                results.append(candidate)
        return sorted(results)

    @staticmethod
    def _collect_embedded_like_paths(root: Path) -> list[str]:
        results: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = "/" + path.relative_to(root).as_posix()
            results.append(relative)
        return results

    @staticmethod
    def _record_package_metadata(package_json: Path, report) -> None:
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        name = payload.get("name")
        version = payload.get("version")
        if name or version:
            report.add_note(f"package.json name={name or 'unknown'} version={version or 'unknown'}.")

    @staticmethod
    def _capture_output(command: list[str], destination: Path, category: str, description: str, report, context) -> bool:
        code, stdout, stderr = run_command(command, cwd=Path(command[-1]).parent if command else None, timeout=1800)
        if code != 0 or not stdout.strip():
            if stderr.strip():
                report.add_note(f"{description} failed: {stderr.strip()}")
            return False
        destination.write_text(stdout, encoding="utf-8", errors="ignore")
        report.add_artifact(str(destination), category, description)
        context.log(f"Wrote {description} to {destination}")
        return True
