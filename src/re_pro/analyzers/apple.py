from __future__ import annotations

import json
import plistlib
import zipfile
from pathlib import Path

from ..asar_tools import extract_asar_archive
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
        if suffix == ".ipa":
            self._analyze_ipa(target, report, context)
            return
        if suffix in {".dmg", ".pkg"}:
            self._analyze_archive(target, report, context)
            return

        metadata = parse_macho_metadata(target)
        if metadata:
            self._record_macho(target, metadata, report)
            self._run_macos_external_tools(target, report, context)

    def _analyze_ipa(self, target: Path, report, context) -> None:
        extracted_dir = ensure_dir(context.output_dir / "ipa_extract")
        context.log(f"Extracting iOS IPA {target.name} to {extracted_dir}")
        with zipfile.ZipFile(target) as archive:
            archive.extractall(extracted_dir)
            members = archive.namelist()

        report.target_type = "ios-ipa"
        report.add_framework("iOS application archive (.ipa)")
        report.add_artifact(str(extracted_dir), "directory", "Extracted iOS IPA")
        report.add_note(f"IPA extraction produced {len(members)} archive members.")

        payload_apps = sorted(path for path in (extracted_dir / "Payload").glob("*.app") if path.is_dir()) if (extracted_dir / "Payload").exists() else []
        if not payload_apps:
            report.add_note("No iOS app bundle was found under Payload/ inside the IPA.")
            return
        report.add_note(f"Recovered {len(payload_apps)} iOS app bundle(s) from the IPA.")
        self._analyze_ios_app_bundle(payload_apps[0], report, context)

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

    def _analyze_ios_app_bundle(self, bundle_dir: Path, report, context) -> None:
        info_path = bundle_dir / "Info.plist"
        frameworks_dir = bundle_dir / "Frameworks"
        plugins_dir = bundle_dir / "PlugIns"

        report.target_type = "ios-app-bundle"
        report.add_framework("iOS app bundle (.app)")
        report.add_artifact(str(bundle_dir), "directory", "iOS app bundle")

        info = parse_plist(info_path) if info_path.exists() else None
        executable_path: Path | None = None
        if info:
            report.add_artifact(str(info_path), "manifest", "iOS Info.plist")
            bundle_id = info.get("CFBundleIdentifier")
            bundle_name = info.get("CFBundleName") or info.get("CFBundleDisplayName")
            bundle_version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            executable_name = info.get("CFBundleExecutable")
            minimum_os = info.get("MinimumOSVersion")
            if bundle_id or bundle_name or bundle_version or minimum_os:
                report.add_note(
                    "iOS Info.plist: "
                    + ", ".join(
                        part
                        for part in (
                            f"bundle_id={bundle_id}" if bundle_id else "",
                            f"name={bundle_name}" if bundle_name else "",
                            f"version={bundle_version}" if bundle_version else "",
                            f"minimum_os={minimum_os}" if minimum_os else "",
                        )
                        if part
                    )
                )
            if executable_name:
                executable_path = bundle_dir / str(executable_name)
        if executable_path is None:
            executables = sorted(path for path in bundle_dir.iterdir() if path.is_file() and not path.suffix)
            executable_path = executables[0] if executables else None

        strings: list[str] = []
        if executable_path and executable_path.exists():
            report.add_artifact(str(executable_path), "binary", "Primary iOS executable")
            metadata = parse_macho_metadata(executable_path)
            if metadata:
                self._record_macho(executable_path, metadata, report, preserve_target_type=True)
            try:
                strings = extract_ascii_strings(executable_path.read_bytes()[:2_000_000])
            except OSError:
                strings = []
            self._run_macos_external_tools(executable_path, report, context)

        if frameworks_dir.exists():
            self._record_ios_framework_hints(frameworks_dir, report)
        self._record_ios_signing_metadata(bundle_dir, report)
        if plugins_dir.exists():
            self._record_ios_extensions(plugins_dir, report)

        self._inspect_ios_resources(bundle_dir, report, context, strings)

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

    def _inspect_ios_resources(self, bundle_dir: Path, report, context, strings: list[str]) -> None:
        search_roots: list[Path] = []
        for relative in [
            Path("Resources"),
            Path("assets"),
            Path("www"),
            Path("flutter_assets"),
        ]:
            candidate = bundle_dir / relative
            if candidate.exists():
                search_roots.append(candidate)
                report.add_artifact(str(candidate), "directory", f"iOS resource root: {relative.as_posix()}")

        app_dir = bundle_dir / "app"
        unpacked_dir = bundle_dir / "app.asar.unpacked"
        asar_path = bundle_dir / "app.asar"
        if app_dir.exists():
            search_roots.append(app_dir)
            report.add_framework("Electron")
            report.add_artifact(str(app_dir), "directory", "Unpacked Electron iOS app resources")
        if unpacked_dir.exists():
            search_roots.append(unpacked_dir)
            report.add_framework("Electron")
            report.add_artifact(str(unpacked_dir), "directory", "Electron iOS unpacked asar resources")
        if asar_path.exists():
            report.add_framework("Electron")
            report.add_artifact(str(asar_path), "archive", "Electron iOS app.asar archive")
            extracted_dir = self._extract_asar(asar_path, context)
            if extracted_dir:
                search_roots.append(extracted_dir)
                report.add_artifact(str(extracted_dir), "directory", "Extracted iOS app.asar contents")

        if any(path.name == "main.jsbundle" for path in bundle_dir.rglob("*")):
            report.add_framework("iOS framework: React Native")
        if (bundle_dir / "flutter_assets").exists():
            report.add_framework("iOS framework: Flutter")
        if any(value.startswith("/_next/static/") for value in self._collect_embedded_like_paths(bundle_dir)):
            report.add_framework("Web framework: Next.js")
        if self._find_first(bundle_dir, "index.html") and any(marker in value.lower() for value in strings for marker in ("__tauri", "tauri://", "wry", "tao::")):
            report.add_framework("Tauri")
            report.add_framework("Rust native binary")

        if search_roots:
            package_json = self._find_first_in_roots(search_roots, "package.json") or self._find_first(bundle_dir, "package.json")
            if package_json:
                report.add_artifact(str(package_json), "manifest", "Recovered package.json")
                self._record_package_metadata(package_json, report)
        map_files = self._collect_files_in_roots(search_roots or [bundle_dir], "*.map")
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
        destination, error = extract_asar_archive(asar_path, context.output_dir / "macos_extracted_asar", cwd=asar_path.parent)
        if destination is not None:
            return destination
        context.log(f"asar extraction failed: {error}")
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
    def _record_ios_framework_hints(frameworks_dir: Path, report) -> None:
        framework_names = [path.name for path in frameworks_dir.iterdir()]
        if any(name.startswith("Flutter.framework") for name in framework_names):
            report.add_framework("iOS framework: Flutter")
        if any(name.startswith("React") or name.startswith("Hermes") for name in framework_names):
            report.add_framework("iOS framework: React Native")
        if any(name.startswith("UnityFramework.framework") for name in framework_names):
            report.add_framework("iOS framework: Unity")
        if any(name.startswith("libswift") or name.endswith(".swiftmodule") for name in framework_names):
            report.add_framework("iOS language/runtime: Swift")

    def _record_ios_signing_metadata(self, bundle_dir: Path, report) -> None:
        mobileprovision_path = bundle_dir / "embedded.mobileprovision"
        if mobileprovision_path.exists():
            report.add_artifact(str(mobileprovision_path), "manifest", "iOS embedded provisioning profile")
            payload = self._parse_mobileprovision(mobileprovision_path)
            if payload:
                name = payload.get("Name")
                team_name = payload.get("TeamName")
                uuid = payload.get("UUID")
                expiration = payload.get("ExpirationDate")
                team_ids = payload.get("TeamIdentifier") or []
                if isinstance(team_ids, str):
                    team_ids = [team_ids]
                report.add_note(
                    "Provisioning profile: "
                    + ", ".join(
                        part
                        for part in (
                            f"name={name}" if name else "",
                            f"team={team_name}" if team_name else "",
                            f"uuid={uuid}" if uuid else "",
                            f"expires={expiration}" if expiration else "",
                            f"team_ids={','.join(team_ids)}" if team_ids else "",
                        )
                        if part
                    )
                )
                device_count = len(payload.get("ProvisionedDevices") or [])
                if device_count:
                    report.add_note(f"Provisioning profile includes {device_count} provisioned device(s).")
                entitlements = payload.get("Entitlements")
                if isinstance(entitlements, dict):
                    self._record_entitlements_summary(entitlements, report, "Provisioned entitlements")

        for xcent_path in sorted(bundle_dir.glob("*.xcent")):
            payload = parse_plist(xcent_path)
            if isinstance(payload, dict):
                report.add_artifact(str(xcent_path), "manifest", "iOS entitlements (.xcent)")
                self._record_entitlements_summary(payload, report, f"Entitlements {xcent_path.name}")

    def _record_ios_extensions(self, plugins_dir: Path, report) -> None:
        appex_dirs = sorted(path for path in plugins_dir.glob("*.appex") if path.is_dir())
        if not appex_dirs:
            return
        report.add_framework("iOS app extensions")
        report.add_note(f"Recovered {len(appex_dirs)} iOS extension bundle(s).")
        for appex_dir in appex_dirs[:12]:
            report.add_artifact(str(appex_dir), "directory", f"iOS extension bundle: {appex_dir.name}")
            info = parse_plist(appex_dir / "Info.plist")
            if not isinstance(info, dict):
                continue
            bundle_id = info.get("CFBundleIdentifier")
            extension = info.get("NSExtension")
            extension_point = extension.get("NSExtensionPointIdentifier") if isinstance(extension, dict) else None
            if bundle_id or extension_point:
                report.add_note(
                    "iOS extension: "
                    + ", ".join(
                        part
                        for part in (
                            f"bundle_id={bundle_id}" if bundle_id else "",
                            f"point={extension_point}" if extension_point else "",
                        )
                        if part
                    )
                )

    @staticmethod
    def _record_entitlements_summary(payload: dict[str, object], report, label: str) -> None:
        application_identifier = payload.get("application-identifier")
        aps_environment = payload.get("aps-environment")
        get_task_allow = payload.get("get-task-allow")
        team_identifier = payload.get("com.apple.developer.team-identifier")
        values = [
            f"application_identifier={application_identifier}" if application_identifier else "",
            f"aps_environment={aps_environment}" if aps_environment else "",
            f"get_task_allow={get_task_allow}" if get_task_allow is not None else "",
            f"team_identifier={team_identifier}" if team_identifier else "",
        ]
        rendered = ", ".join(value for value in values if value)
        if rendered:
            report.add_note(f"{label}: {rendered}")

    @staticmethod
    def _parse_mobileprovision(path: Path) -> dict[str, object] | None:
        try:
            payload = path.read_bytes()
        except OSError:
            return None
        xml_start = payload.find(b"<?xml")
        xml_end = payload.find(b"</plist>")
        if xml_start != -1 and xml_end != -1:
            xml_payload = payload[xml_start : xml_end + len(b"</plist>")]
            try:
                parsed = plistlib.loads(xml_payload)
            except (plistlib.InvalidFileException, ValueError):
                return None
            return parsed if isinstance(parsed, dict) else None
        binary_start = payload.find(b"bplist00")
        if binary_start != -1:
            try:
                parsed = plistlib.loads(payload[binary_start:])
            except (plistlib.InvalidFileException, ValueError):
                return None
            return parsed if isinstance(parsed, dict) else None
        return None

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
