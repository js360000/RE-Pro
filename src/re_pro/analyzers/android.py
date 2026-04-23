from __future__ import annotations

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from ..dex import is_dex_file, parse_dex_metadata
from ..sourcemap import restore_sources_from_map
from ..tooling import REPO_ROOT
from ..tooling import resolve_command, resolve_tool_path, run_command_logged
from ..utils import ensure_dir
from .base import Analyzer


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class AndroidAnalyzer(Analyzer):
    name = "Android package recovery"
    JADX_BACKGROUND_THRESHOLD_BYTES = 25 * 1024 * 1024

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return

        suffix = context.target.suffix.lower()
        if suffix == ".dex" or is_dex_file(context.target):
            self._analyze_raw_dex(context.target, report, context)
            return
        if suffix not in {".apk", ".apks", ".xapk", ".aab"}:
            return
        if not zipfile.is_zipfile(context.target):
            return

        if suffix == ".apk":
            self._analyze_single_apk(context.target, ensure_dir(context.output_dir / "apk_extract"), report, context)
            return
        if suffix == ".aab":
            self._analyze_app_bundle(context.target, report, context)
            return

        self._analyze_package_set(context.target, report, context)

    def _analyze_raw_dex(self, target: Path, report, context) -> None:
        metadata = parse_dex_metadata(target)
        if metadata is None:
            return

        ensure_dir(context.output_dir)
        report.target_type = "android-dex"
        report.add_framework("Android DEX bytecode")
        metadata_path = context.output_dir / "dex_metadata.json"
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        report.add_artifact(str(metadata_path), "metadata", "DEX metadata")
        report.add_artifact(str(target), "binary", "Standalone DEX file")
        report.add_finding(
            "DEX bytecode parsed",
            "RE-Pro parsed the DEX header, strings, types, and class descriptors from the standalone bytecode file.",
            severity="info",
            details=(
                f"strings={metadata.get('string_count', 0)}; "
                f"types={metadata.get('type_count', 0)}; "
                f"methods={metadata.get('method_count', 0)}; "
                f"classes={metadata.get('class_count', 0)}"
            ),
        )
        package_names = metadata.get("package_names") or []
        if package_names:
            report.add_note(f"DEX package namespaces: {', '.join(package_names[:10])}")
        class_descriptors = metadata.get("class_descriptors") or []
        if class_descriptors:
            report.add_note(f"DEX class descriptors recovered: {', '.join(class_descriptors[:8])}")
        self._index_raw_dex(context, metadata, metadata_path)
        if context.run_external_tools:
            self._run_jadx_on_bytecode(target, report, context)

    def _analyze_app_bundle(self, target: Path, report, context) -> None:
        extracted_dir = ensure_dir(context.output_dir / "aab_extract")
        context.log(f"Extracting Android App Bundle {target.name} to {extracted_dir}")
        with zipfile.ZipFile(target) as archive:
            archive.extractall(extracted_dir)
            members = archive.namelist()

        report.target_type = "android-app-bundle"
        report.add_framework("Android App Bundle (.aab)")
        report.add_artifact(str(extracted_dir), "directory", "Extracted Android App Bundle")
        report.add_note(f"Android App Bundle extraction produced {len(members)} archive members.")

        modules = self._discover_bundle_modules(extracted_dir)
        if not modules:
            report.add_note("No Android App Bundle modules were found inside the extracted archive.")
            return

        report.add_note(f"Recovered {len(modules)} Android App Bundle module(s): {', '.join(module.name for module in modules[:8])}")
        for module_dir in modules[:12]:
            report.add_artifact(str(module_dir), "directory", f"Android App Bundle module: {module_dir.name}")

        primary_module = next((module for module in modules if module.name == "base"), modules[0])
        self._inspect_bundle_module(primary_module, report, context)
        if context.run_external_tools:
            report.add_note(
                "AAB inputs are inspected directly, but automated JADX/apktool passes currently target APKs. "
                "Build or extract a base APK from the bundle for full Android decompilation."
            )

    def _analyze_single_apk(
        self,
        target: Path,
        extracted_dir: Path,
        report,
        context,
        *,
        run_external_tools: bool = True,
    ) -> None:
        context.log(f"Extracting Android archive {target.name} to {extracted_dir}")
        with zipfile.ZipFile(target) as archive:
            archive.extractall(extracted_dir)
            members = archive.namelist()

        report.target_type = "android-package"
        report.add_framework("Android APK")
        report.add_artifact(str(extracted_dir), "directory", "Extracted Android package")
        report.add_note(f"APK extraction produced {len(members)} archive members.")
        context.log(f"APK extraction completed with {len(members)} members")

        dex_files = sorted(path.name for path in extracted_dir.glob("classes*.dex"))
        native_libs = sorted({path.parent.name for path in extracted_dir.glob("lib/*/*.so")})
        context.log(f"Detected {len(dex_files)} DEX file(s) and {len(native_libs)} native ABI folder(s)")
        if dex_files:
            report.add_note(f"DEX bytecode files present: {', '.join(dex_files[:5])}")
        if native_libs:
            report.add_note(f"Native library architectures present: {', '.join(native_libs)}")

        manifest_path = extracted_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            report.add_artifact(str(manifest_path), "manifest", "Android manifest")
            self._record_manifest(manifest_path, report)

        if (extracted_dir / "resources.arsc").exists():
            report.add_note("resources.arsc is present; resource names may require APK-specific tooling when the manifest is binary AXML.")

        self._record_android_frameworks(extracted_dir, report)

        package_json = self._find_first(extracted_dir, "package.json")
        if package_json:
            report.add_artifact(str(package_json), "manifest", "Recovered package.json")
            self._record_package_metadata(package_json, report)

        self._restore_source_maps(extracted_dir, report, context)
        if run_external_tools:
            self._run_external_android_tools(target, report, context)

    def _analyze_package_set(self, target: Path, report, context) -> None:
        extracted_dir = ensure_dir(context.output_dir / "apks_extract")
        with zipfile.ZipFile(target) as archive:
            archive.extractall(extracted_dir)
            members = archive.namelist()

        report.target_type = "android-package-set"
        report.add_framework("Android package set (.apks/.xapk)")
        report.add_artifact(str(extracted_dir), "directory", "Extracted Android package set")
        report.add_note(f"Package-set extraction produced {len(members)} archive members.")

        apk_members = sorted(path for path in extracted_dir.rglob("*.apk"))
        if not apk_members:
            report.add_note("No nested APKs were found inside the package set.")
            return

        report.add_note(f"Recovered {len(apk_members)} nested APK files from the package set.")
        for apk_path in apk_members[:12]:
            report.add_artifact(str(apk_path), "payload", f"Nested APK: {apk_path.name}")

        base_apk = next((path for path in apk_members if path.name == "base.apk"), apk_members[0])
        base_extract = ensure_dir(context.output_dir / "base_apk_extract")
        self._analyze_single_apk(base_apk, base_extract, report, context, run_external_tools=False)
        self._run_external_android_tools(base_apk, report, context)

    def _inspect_bundle_module(self, module_dir: Path, report, context) -> None:
        context.log(f"Inspecting Android App Bundle module {module_dir.name} under {module_dir}")
        if module_dir.name == "base":
            report.add_note("Using the base module as the primary analysis target inside the Android App Bundle.")

        dex_dir = module_dir / "dex"
        lib_dir = module_dir / "lib"
        dex_files = sorted(path.name for path in dex_dir.glob("classes*.dex"))
        native_libs = sorted({path.parent.name for path in lib_dir.glob("*/*.so")})
        context.log(f"Detected {len(dex_files)} DEX file(s) and {len(native_libs)} native ABI folder(s) in bundle module {module_dir.name}")
        if dex_files:
            report.add_note(f"{module_dir.name} module DEX files present: {', '.join(dex_files[:5])}")
        if native_libs:
            report.add_note(f"{module_dir.name} module native library architectures present: {', '.join(native_libs)}")

        manifest_path = module_dir / "manifest" / "AndroidManifest.xml"
        if manifest_path.exists():
            report.add_artifact(str(manifest_path), "manifest", f"Android app bundle manifest ({module_dir.name} module)")
            self._record_manifest(manifest_path, report)

        resources_pb = module_dir / "resources.pb"
        if resources_pb.exists():
            report.add_note(
                f"{module_dir.name} module uses resources.pb; bundletool or aapt2 may be needed for richer resource names."
            )

        self._record_android_frameworks(module_dir, report)

        package_json = self._find_first(module_dir, "package.json")
        if package_json:
            report.add_artifact(str(package_json), "manifest", "Recovered package.json")
            self._record_package_metadata(package_json, report)

        self._restore_source_maps(module_dir, report, context)

    def _record_manifest(self, manifest_path: Path, report) -> None:
        try:
            payload = manifest_path.read_bytes()
        except OSError as exc:
            report.add_note(f"Failed to read AndroidManifest.xml: {exc}")
            return

        if payload.lstrip().startswith(b"<"):
            try:
                root = ET.fromstring(payload)
            except ET.ParseError as exc:
                report.add_note(f"AndroidManifest.xml looked textual but failed to parse: {exc}")
                return
            package_name = root.attrib.get("package")
            application = root.find("application")
            application_name = application.attrib.get(f"{ANDROID_NS}name") if application is not None else None
            label = application.attrib.get(f"{ANDROID_NS}label") if application is not None else None
            if package_name:
                report.add_note(f"Android package name: {package_name}")
            if application_name:
                report.add_note(f"Application class: {application_name}")
            if label:
                report.add_note(f"Application label: {label}")
            return

        report.add_note("AndroidManifest.xml appears to be binary AXML. Install `apkanalyzer`, `aapt`, or `jadx` for decoded manifest output.")

    def _run_external_android_tools(self, apk_target: Path, report, context) -> None:
        jadx_command = resolve_command([["jadx"], ["jadx.bat"]])
        apktool_command = self._resolve_apktool_command()
        any_available = jadx_command is not None or apktool_command is not None
        context.log(
            "Android external tool availability: "
            f"apktool={'yes' if apktool_command else 'no'}, jadx={'yes' if jadx_command else 'no'}"
        )

        if not context.run_external_tools:
            if any_available:
                report.add_note("jadx/apktool are installed locally but skipped for this run. Enable external tools for Android decompilation and decoded resources.")
            return

        if apktool_command is not None:
            self._run_apktool(apktool_command, apk_target, report, context)
        else:
            report.add_note("Install `apktool` to decode binary Android manifests and resource tables.")

        if jadx_command is not None:
            self._run_jadx(jadx_command, apk_target, report, context)
        else:
            report.add_note("Install `jadx` to decompile DEX bytecode into Java/Kotlin-like source output.")

    def _run_jadx_on_bytecode(self, bytecode_target: Path, report, context) -> None:
        jadx_command = resolve_command([["jadx"], ["jadx.bat"]])
        if jadx_command is None:
            report.add_note("Install `jadx` to decompile standalone DEX bytecode into Java/Kotlin-like source output.")
            return
        output_dir = ensure_dir(context.output_dir / "jadx")
        source_output_dir = ensure_dir(output_dir / "sources")
        log_path = output_dir / "jadx.log"
        full_command = self._build_jadx_command(jadx_command, bytecode_target, source_output_dir, self._parallel_jobs(max_jobs=8))
        report.add_artifact(str(log_path), "log", "jadx verbose log")
        code, stdout, stderr = run_command_logged(
            full_command,
            cwd=bytecode_target.parent,
            timeout=1800,
            logger=self._make_step_logger(log_path, context),
            label="jadx",
        )
        java_files = list(output_dir.rglob("*.java"))
        kotlin_files = list(output_dir.rglob("*.kt"))
        if code == 0 and (java_files or kotlin_files):
            report.add_artifact(str(output_dir), "directory", "jadx decompiled Android bytecode sources")
            report.add_finding(
                "jadx decompilation succeeded",
                f"jadx recovered {len(java_files)} Java files and {len(kotlin_files)} Kotlin files from standalone DEX input.",
                severity="info",
            )
            return
        message = stderr.strip() or stdout.strip()
        if message:
            report.add_note(f"jadx decompilation failed: {message}")

    def _run_apktool(self, command: list[str], apk_target: Path, report, context) -> None:
        output_dir = ensure_dir(context.output_dir / "apktool_decode")
        log_path = context.output_dir / "apktool.log"
        jobs = self._parallel_jobs()
        full_command = command + ["d", "-f", "--no-assets", "-j", str(jobs), "-o", str(output_dir), str(apk_target)]
        context.log(f"Starting apktool decode into {output_dir} with {jobs} job(s)")
        report.add_artifact(str(log_path), "log", "apktool verbose log")
        code, stdout, stderr = run_command_logged(
            full_command,
            cwd=apk_target.parent,
            timeout=1800,
            logger=self._make_step_logger(log_path, context),
            label="apktool",
        )
        decoded_manifest = output_dir / "AndroidManifest.xml"
        if code == 0 and decoded_manifest.exists():
            report.add_artifact(str(output_dir), "directory", "apktool decoded Android resources")
            report.add_artifact(str(decoded_manifest), "manifest", "Decoded Android manifest")
            report.add_finding(
                "apktool decode succeeded",
                "apktool produced a decoded Android project with textual resources and manifest output.",
                severity="info",
            )
            self._record_manifest(decoded_manifest, report)
            public_xml = output_dir / "res" / "values" / "public.xml"
            if public_xml.exists():
                report.add_artifact(str(public_xml), "manifest", "Decoded Android public resources")
            return
        message = stderr.strip() or stdout.strip()
        if message:
            report.add_note(f"apktool decode failed: {message}")

    def _run_jadx(self, command: list[str], apk_target: Path, report, context) -> None:
        output_dir = ensure_dir(context.output_dir / "jadx")
        source_output_dir = ensure_dir(output_dir / "sources")
        log_path = output_dir / "jadx.log"
        status_path = output_dir / "status.json"
        jobs = self._parallel_jobs(max_jobs=8)
        full_command = self._build_jadx_command(command, apk_target, source_output_dir, jobs)
        report.add_artifact(str(log_path), "log", "jadx verbose log")
        report.add_artifact(str(status_path), "metadata", "jadx decompilation status")

        if self._should_background_jadx(apk_target):
            self._start_background_jadx_job(
                command=command,
                apk_target=apk_target,
                output_dir=output_dir,
                jobs=jobs,
                context=context,
            )
            report.add_artifact(str(source_output_dir), "directory", "jadx background output directory")
            report.add_finding(
                "jadx background decompilation started",
                "A large Android package triggered detached full-source decompilation. See the jadx log and status artifacts while the background job runs.",
                severity="info",
            )
            report.add_note(f"jadx is running in the background for {apk_target.name}; monitor {status_path} and {log_path}.")
            return

        context.log(f"Starting JADX decompilation into {source_output_dir} with {jobs} thread(s)")
        code, stdout, stderr = run_command_logged(
            full_command,
            cwd=apk_target.parent,
            timeout=1800,
            logger=self._make_step_logger(log_path, context),
            label="jadx",
        )
        java_files = list(output_dir.rglob("*.java"))
        kotlin_files = list(output_dir.rglob("*.kt"))
        if code == 0 and (java_files or kotlin_files):
            report.add_artifact(str(output_dir), "directory", "jadx decompiled Android sources")
            report.add_finding(
                "jadx decompilation succeeded",
                f"jadx recovered {len(java_files)} Java files and {len(kotlin_files)} Kotlin files.",
                severity="info",
            )
            return
        message = stderr.strip() or stdout.strip()
        if message:
            report.add_note(f"jadx decompilation failed: {message}")

    @staticmethod
    def _resolve_apktool_command() -> list[str] | None:
        command = resolve_command([["apktool"], ["apktool.bat"]])
        if command is not None:
            return command
        jar_path = resolve_tool_path("apktool.jar", extra_patterns=["apktool*/apktool*.jar", "apktool*.jar"])
        if jar_path:
            return ["java", "-jar", jar_path]
        return None

    def _restore_source_maps(self, root: Path, report, context) -> None:
        map_files = sorted(root.rglob("*.map"))
        context.log(f"Scanning Android assets for source maps under {root}")
        if not map_files:
            context.log("No Android source maps were found in extracted assets")
            return

        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        context.log(f"Found {len(map_files)} Android source map file(s); restoring into {recovered_root}")
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
                "Android source map restoration succeeded",
                f"Recovered {restored_total} original source files from shipped Android/web source maps.",
                severity="info",
            )
            report.add_note(f"Recovered {restored_total} original source files from packaged Android web assets.")

    @staticmethod
    def _parallel_jobs(*, max_jobs: int = 12) -> int:
        cpu_total = os.cpu_count() or 4
        return max(2, min(cpu_total, max_jobs))

    @staticmethod
    def _build_jadx_command(command: list[str], apk_target: Path, source_output_dir: Path, jobs: int) -> list[str]:
        return command + ["--no-res", "-j", str(jobs), "-ds", str(source_output_dir), str(apk_target)]

    def _should_background_jadx(self, apk_target: Path) -> bool:
        try:
            return apk_target.stat().st_size >= self.JADX_BACKGROUND_THRESHOLD_BYTES
        except OSError:
            return False

    def _start_background_jadx_job(self, *, command: list[str], apk_target: Path, output_dir: Path, jobs: int, context) -> None:
        command_path = output_dir / "jadx_command.json"
        command_path.write_text(
            json.dumps(
                {
                    "apk": str(apk_target),
                    "output_dir": str(output_dir),
                    "jobs": jobs,
                    "jadx_command": command,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        launcher = [
            sys.executable,
            "-m",
            "re_pro.cli",
            "android-jadx-job",
            "--apk",
            str(apk_target),
            "--output",
            str(output_dir),
            "--jobs",
            str(jobs),
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
        context.log(f"Spawned background JADX job for {apk_target.name} into {output_dir}")

    @staticmethod
    def _make_step_logger(log_path: Path, context):
        ensure_dir(log_path.parent)
        log_path.write_text("", encoding="utf-8")

        def _logger(message: str) -> None:
            timestamped = message
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(timestamped + "\n")
            context.log(timestamped)

        return _logger

    @staticmethod
    def _find_first(root: Path, name: str) -> Path | None:
        for candidate in root.rglob(name):
            return candidate
        return None

    @staticmethod
    def _discover_bundle_modules(extracted_dir: Path) -> list[Path]:
        modules: list[Path] = []
        for candidate in sorted(extracted_dir.iterdir()):
            if not candidate.is_dir():
                continue
            if (
                (candidate / "manifest" / "AndroidManifest.xml").exists()
                or (candidate / "dex").exists()
                or (candidate / "assets").exists()
                or (candidate / "lib").exists()
            ):
                modules.append(candidate)
        return modules

    @staticmethod
    def _record_android_frameworks(root: Path, report) -> None:
        if (root / "assets" / "flutter_assets").exists() or list(root.glob("lib/*/libflutter.so")):
            report.add_framework("Android framework: Flutter")
        if list(root.glob("assets/*.bundle")) or (root / "assets" / "index.android.bundle").exists():
            report.add_framework("Android framework: React Native")
        if (root / "assets" / "www").exists():
            report.add_framework("Android framework: WebView bundle")
            if (root / "assets" / "www" / "cordova.js").exists():
                report.add_framework("Android framework: Cordova")

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
    def _index_raw_dex(context, metadata: dict[str, object], metadata_path: Path) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        dex_id = context.analysis_index.add_entity(
            "format",
            f"dex:{context.target.name}",
            "DEX bytecode",
            attributes={
                "version": metadata.get("version"),
                "string_count": metadata.get("string_count"),
                "class_count": metadata.get("class_count"),
                "method_count": metadata.get("method_count"),
            },
        )
        context.analysis_index.add_relation(target_id, "has_format", dex_id)
        artifact_id = context.analysis_index.add_entity(
            "artifact",
            str(metadata_path),
            metadata_path.name,
            attributes={"path": str(metadata_path), "category": "metadata"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        for class_descriptor in metadata.get("class_descriptors") or []:
            class_id = context.analysis_index.add_entity(
                "java_class",
                str(class_descriptor).lower(),
                str(class_descriptor),
                attributes={"descriptor": class_descriptor},
            )
            context.analysis_index.add_relation(target_id, "contains_class", class_id)
