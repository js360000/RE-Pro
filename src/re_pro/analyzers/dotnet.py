from __future__ import annotations

import json
from pathlib import Path

from ..dotnet_bundle import extract_dotnet_single_file_bundle, parse_dotnet_single_file_bundle
from ..dotnet_resources import decompile_baml_to_xaml, extract_managed_resources
from ..tooling import resolve_command, resolve_tool_path, run_command
from ..utils import ensure_dir, parse_pe_cli_metadata, safe_slug
from .base import Analyzer


class DotNetAnalyzer(Analyzer):
    name = ".NET decompilation"
    UI_SIGNATURES = {
        "WinForms": ("system.windows.forms", "application.run", "windows forms"),
        "WPF": ("presentationframework", "presentationcore", "windowsbase", ".baml", ".xaml"),
        "Avalonia": ("avalonia", ".axaml"),
        "MAUI": ("microsoft.maui", "mauiwinuiapplication", "mauiapp"),
        "Unity managed": ("unityengine", "unityengine.coremodule", "unityplayer.dll"),
    }
    WEB_SIGNATURES = {
        "ASP.NET Core": ("microsoft.aspnetcore", "webapplicationbuilder", "kestrel"),
        "Blazor": ("microsoft.aspnetcore.components", "blazor", "razorcomponent"),
    }

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or (not context.probable_binary and context.pe_metadata is None):
            return

        strings_lower = [value.lower() for value in context.ascii_strings]
        imports_lower = {value.lower() for value in context.pe_imports}
        cli_metadata = context.pe_cli_metadata
        indicators = ("mscoree.dll", "system.runtime", "clr.dll", "coreclr", "system.private.corelib")
        managed = cli_metadata is not None or any(
            indicator in value for value in strings_lower for indicator in indicators
        ) or "mscoree.dll" in imports_lower
        if not managed:
            return

        report.add_framework(".NET")
        report.fingerprints["dotnet"] = cli_metadata or {"detection": "string/import heuristics"}
        report.add_finding(
            ".NET runtime indicators detected",
            "The executable appears to be a managed .NET assembly or mixed-mode host.",
            severity="info",
        )

        bundle_probe = self._probe_single_file_bundle(context, report)
        decompile_target = self._select_managed_assembly_target(context, cli_metadata, bundle_probe)
        effective_cli_metadata = cli_metadata
        if decompile_target != context.target:
            effective_cli_metadata = parse_pe_cli_metadata(decompile_target) or cli_metadata
            report.add_artifact(str(decompile_target), "binary", "Companion managed assembly selected for .NET decompilation")
            report.add_note(f"Using companion managed assembly {decompile_target.name} for .NET metadata export and decompilation.")

        if effective_cli_metadata is not None:
            report.fingerprints["dotnet"] = effective_cli_metadata
            self._write_metadata_artifact(context, report, effective_cli_metadata)
            metadata_version = str(effective_cli_metadata.get("metadata_version", "")).strip() or "unknown"
            runtime_version = effective_cli_metadata.get("runtime_version", "unknown")
            stream_names = ", ".join(effective_cli_metadata.get("metadata_streams", [])) or "none"
            flag_names = ", ".join(effective_cli_metadata.get("flags", [])) or "none"
            report.add_note(
                f".NET CLR header detected: runtime {runtime_version}, metadata {metadata_version}, flags {flag_names}, streams {stream_names}."
            )
            self._classify_runtime(context, report, effective_cli_metadata, strings_lower)
        else:
            report.add_note("Managed detection fell back to CLR-related strings/imports because no CLI header could be parsed.")
            if self._looks_like_apphost(context, strings_lower):
                report.add_framework(".NET apphost")
                report.add_note("The outer executable looks like a native .NET apphost; the managed payload may be bundled or stored in a companion DLL.")

        self._detect_dotnet_frameworks(context, report, strings_lower)
        self._add_runtime_config_artifacts(context, report, bundle_probe)
        self._extract_managed_resource_artifacts(context, report, decompile_target, effective_cli_metadata is not None)
        self._attempt_ilspy_export(context, report, decompile_target, effective_cli_metadata is not None)

    def _write_metadata_artifact(self, context, report, cli_metadata: dict[str, object]) -> None:
        output_dir = ensure_dir(context.output_dir / "dotnet")
        metadata_path = output_dir / "cli_metadata.json"
        metadata_path.write_text(json.dumps(cli_metadata, indent=2), encoding="utf-8")
        report.add_artifact(str(metadata_path), "manifest", ".NET CLR metadata manifest")

    def _classify_runtime(self, context, report, cli_metadata: dict[str, object], strings_lower: list[str]) -> None:
        sibling_names = (
            {path.name.lower() for path in context.target.parent.iterdir()}
            if context.target.parent.exists()
            else set()
        )
        stream_names = {str(name).lower() for name in cli_metadata.get("metadata_streams", [])}
        metadata_version = str(cli_metadata.get("metadata_version", "")).lower()

        if any(name.endswith(".runtimeconfig.json") or name.endswith(".deps.json") for name in sibling_names) or any(
            marker in value for value in strings_lower for marker in ("system.private.corelib", "hostfxr", "coreclr")
        ):
            report.add_framework(".NET Core / .NET 5+")
        elif "mscorlib" in " ".join(strings_lower) or metadata_version.startswith("v4.0.30319"):
            report.add_framework(".NET Framework")

        if "TRACKDEBUGDATA" in cli_metadata.get("flags", []):
            report.add_note("The CLR header indicates debug tracking data is present.")
        if "STRONGNAMESIGNED" in cli_metadata.get("flags", []):
            report.add_note("The managed assembly is strong-name signed.")
        managed_native_header = cli_metadata.get("managed_native_header")
        if isinstance(managed_native_header, dict) and managed_native_header.get("is_readytorun"):
            report.add_framework(".NET ReadyToRun")
            report.add_note(
                ".NET ReadyToRun native header detected: "
                f"version {managed_native_header.get('major_version')}.{managed_native_header.get('minor_version')} "
                f"with {managed_native_header.get('section_count')} R2R sections."
            )
        elif cli_metadata.get("managed_native_header_rva"):
            report.add_note(
                "A CLR ManagedNativeHeader is present but does not identify as ReadyToRun; this may indicate another managed native-image format."
            )
        if "#pdb" in stream_names:
            report.add_note("The managed metadata includes a #Pdb stream.")

    def _detect_dotnet_frameworks(self, context, report, strings_lower: list[str]) -> None:
        sibling_names = (
            {path.name.lower() for path in context.target.parent.iterdir()}
            if context.target.parent.exists()
            else set()
        )
        for framework, markers in self.UI_SIGNATURES.items():
            if any(marker in value for value in strings_lower for marker in markers) or any(
                marker in name for name in sibling_names for marker in markers
            ):
                report.add_framework(framework)
        for framework, markers in self.WEB_SIGNATURES.items():
            if any(marker in value for value in strings_lower for marker in markers):
                report.add_framework(framework)

    def _add_runtime_config_artifacts(self, context, report, bundle_probe: dict[str, object] | None) -> None:
        for suffix, description in (
            (".runtimeconfig.json", ".NET runtime configuration"),
            (".deps.json", ".NET dependency manifest"),
            (".config", "Application configuration file"),
        ):
            sibling = context.target.with_suffix(suffix)
            if sibling.exists():
                report.add_artifact(str(sibling), "config", description)
        if not bundle_probe:
            return
        for entry in bundle_probe.get("extracted_entries", []):
            path = Path(str(entry.get("destination", "")))
            if not path.exists():
                continue
            if path.name.endswith(".runtimeconfig.json"):
                report.add_artifact(str(path), "config", ".NET runtime configuration")
            elif path.name.endswith(".deps.json"):
                report.add_artifact(str(path), "config", ".NET dependency manifest")

    def _extract_managed_resource_artifacts(self, context, report, target: Path, target_has_metadata: bool) -> None:
        if not target_has_metadata:
            return

        output_dir = ensure_dir(context.output_dir / "dotnet_resources")
        resource_manifest = extract_managed_resources(target, output_dir, logger=context.log)
        if resource_manifest is None:
            report.add_note("Managed manifest-resource extraction was not available; keep `dotnet` installed to recover embedded .resources and BAML payloads.")
            return

        manifest_path = output_dir / "resource_manifest.json"
        if manifest_path.exists():
            report.add_artifact(str(manifest_path), "manifest", ".NET managed resource manifest")
        resources_dir = output_dir / "resources"
        if resources_dir.exists():
            report.add_artifact(str(resources_dir), "directory", "Extracted nested .NET resources")
        raw_dir = output_dir / "manifest_resources"
        if raw_dir.exists():
            report.add_artifact(str(raw_dir), "directory", "Raw managed manifest resources")

        manifest_resources = resource_manifest.get("manifest_resources", [])
        embedded_count = 0
        baml_entries: list[dict[str, object]] = []
        for resource in manifest_resources:
            if resource.get("relative_path"):
                embedded_count += 1
            for entry in resource.get("resource_entries") or []:
                if entry.get("probable_baml"):
                    baml_entries.append(
                        {
                            "resource_name": resource.get("name"),
                            "entry_name": entry.get("name"),
                            "relative_path": entry.get("relative_path"),
                            "probable_xaml_path": entry.get("probable_xaml_path"),
                        }
                    )

        if embedded_count:
            report.add_note(f"Recovered {embedded_count} embedded managed manifest resource payload(s).")
        if baml_entries:
            hints_path = output_dir / "wpf_baml_hints.json"
            hints_path.write_text(json.dumps(baml_entries, indent=2), encoding="utf-8")
            report.add_artifact(str(hints_path), "manifest", "WPF BAML-to-XAML path hints")
            report.add_note(
                f"Recovered {len(baml_entries)} probable WPF BAML payload(s); path hints for likely original .xaml files were written to {hints_path.name}."
            )
            jobs = self._build_resource_baml_jobs(output_dir, baml_entries)
            self._reconstruct_baml_xaml(
                context,
                report,
                target,
                jobs,
                source_label="managed resource",
                output_dir=context.output_dir / "dotnet_xaml" / "from_managed_resources",
            )

    def _attempt_ilspy_export(self, context, report, target: Path, target_has_metadata: bool) -> None:
        command = self._resolve_ilspy_command()
        if command is None:
            report.add_note("Install a local .NET SDK and `ilspycmd` to enable automatic .NET decompilation.")
            return
        if not target_has_metadata:
            return

        output_dir = ensure_dir(context.output_dir / "dotnet_decompile")
        full_command = command + ["-p", "-o", str(output_dir), str(target)]
        code, stdout, stderr = run_command(full_command, cwd=context.target.parent, timeout=1800)
        if code == 0 and output_dir.exists():
            report.add_artifact(str(output_dir), "directory", "Decompiled .NET project via ilspycmd")
            message = stdout.strip()
            if message:
                log_path = output_dir / "ilspycmd.log"
                log_path.write_text(message + "\n", encoding="utf-8", errors="ignore")
                report.add_artifact(str(log_path), "log", "ILSpy command output")
            report.add_finding(
                ".NET decompilation completed",
                "ILSpy successfully exported a project representation of the target assembly.",
                severity="info",
            )
            self._record_baml_outputs(context, report, target, output_dir)
            context.log(f"ILSpy decompilation output written to {output_dir}")
            return
        message = stderr.strip() or stdout.strip() or "unknown error"
        report.add_note(f"ilspycmd failed: {message}")

    def _record_baml_outputs(self, context, report, assembly_target: Path, output_dir: Path) -> None:
        baml_files = sorted(output_dir.rglob("*.baml"))
        if not baml_files:
            return

        manifest = [
            {
                "source_path": str(path),
                "baml_path": str(path),
                "relative_path": path.relative_to(output_dir).as_posix(),
                "probable_xaml_path": path.relative_to(output_dir).with_suffix(".xaml").as_posix(),
            }
            for path in baml_files
        ]
        manifest_path = context.output_dir / "dotnet" / "ilspy_baml_manifest.json"
        ensure_dir(manifest_path.parent)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        report.add_artifact(str(manifest_path), "manifest", "ILSpy BAML output manifest")
        report.add_note(
            f"ILSpy recovered {len(baml_files)} BAML file(s); probable XAML source paths were inferred in {manifest_path.name}."
        )
        jobs = [
            {
                "source_path": entry["source_path"],
                "output_relative_path": entry["probable_xaml_path"],
                "source_kind": "ilspy-baml",
            }
            for entry in manifest
        ]
        self._reconstruct_baml_xaml(
            context,
            report,
            assembly_target,
            jobs,
            source_label="ILSpy BAML",
            output_dir=context.output_dir / "dotnet_xaml" / "from_ilspy_baml",
        )

    def _build_resource_baml_jobs(self, resource_output_dir: Path, baml_entries: list[dict[str, object]]) -> list[dict[str, object]]:
        jobs: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for entry in baml_entries:
            relative_path = str(entry.get("relative_path", "")).strip()
            if not relative_path:
                continue
            source_path = resource_output_dir / relative_path
            if not source_path.exists():
                continue
            output_relative = str(entry.get("probable_xaml_path", "")).strip() or Path(relative_path).with_suffix(".xaml").as_posix()
            key = (str(source_path.resolve()), output_relative)
            if key in seen:
                continue
            seen.add(key)
            jobs.append(
                {
                    "source_path": str(source_path),
                    "output_relative_path": output_relative,
                    "source_kind": "managed-resource",
                    "resource_name": entry.get("resource_name"),
                    "entry_name": entry.get("entry_name"),
                }
            )
        return jobs

    def _reconstruct_baml_xaml(
        self,
        context,
        report,
        assembly_target: Path,
        jobs: list[dict[str, object]],
        *,
        source_label: str,
        output_dir: Path,
    ) -> None:
        if not jobs:
            return

        source_descriptor = source_label if source_label.lower().endswith("baml") else f"{source_label} BAML"
        manifest = decompile_baml_to_xaml(assembly_target, jobs, ensure_dir(output_dir), logger=context.log)
        if manifest is None:
            report.add_note(
                f"Readable XAML reconstruction from {source_descriptor} was not available; the bundled .NET helper could not complete BAML decompilation."
            )
            return

        manifest_path = output_dir / "xaml_manifest.json"
        if manifest_path.exists():
            report.add_artifact(str(manifest_path), "manifest", f".NET reconstructed XAML manifest ({source_label})")
        reconstructed_files = [
            entry
            for entry in manifest.get("results", [])
            if entry.get("success") and entry.get("output_path")
        ]
        if reconstructed_files:
            report.add_artifact(str(output_dir), "directory", f"Readable WPF XAML reconstructed from {source_descriptor}")
            report.add_note(
                f"Reconstructed {len(reconstructed_files)} readable WPF XAML file(s) from {source_descriptor} into {output_dir.name}."
            )
            return

        error_count = len([entry for entry in manifest.get("results", []) if entry.get("error")])
        if error_count:
            report.add_note(
                f"BAML-to-XAML reconstruction attempted for {source_descriptor} inputs, but all {error_count} decompilation job(s) failed."
            )

    @staticmethod
    def _resolve_ilspy_command() -> list[str] | None:
        direct = resolve_command([["ilspycmd"], ["ilspycmd.exe"]])
        if direct is not None:
            return direct

        ilspy_path = resolve_tool_path("ilspycmd", extra_patterns=["ilspycmd/ilspycmd.exe", "ilspycmd*/ilspycmd.exe"])
        if ilspy_path:
            return [ilspy_path]
        return None

    def _select_managed_assembly_target(
        self,
        context,
        cli_metadata: dict[str, object] | None,
        bundle_probe: dict[str, object] | None,
    ) -> Path:
        if cli_metadata is not None:
            return context.target

        if bundle_probe:
            bundle_candidates = self._bundle_managed_candidates(context, bundle_probe)
            for candidate in bundle_candidates:
                metadata = parse_pe_cli_metadata(candidate)
                if metadata is not None:
                    return candidate

        candidates: list[Path] = []
        for key in ("OriginalFilename", "InternalName"):
            value = context.version_info.get(key, "").strip()
            if value.lower().endswith(".dll"):
                candidates.append(context.target.parent / Path(value).name)
        candidates.append(context.target.with_suffix(".dll"))

        for candidate in dict.fromkeys(candidates):
            if candidate.exists() and candidate.is_file():
                metadata = parse_pe_cli_metadata(candidate)
                if metadata is not None:
                    return candidate
        return context.target

    def _looks_like_apphost(self, context, strings_lower: list[str]) -> bool:
        original = context.version_info.get("OriginalFilename", "").lower()
        internal = context.version_info.get("InternalName", "").lower()
        return (
            original.endswith(".dll")
            or internal.endswith(".dll")
            or any(marker in value for value in strings_lower for marker in ("apphost", "hostfxr", "system.private.corelib"))
        )

    def _probe_single_file_bundle(self, context, report) -> dict[str, object] | None:
        bundle_manifest = parse_dotnet_single_file_bundle(context.target)
        if bundle_manifest is None:
            return None

        output_dir = ensure_dir(context.output_dir / "dotnet_bundle")
        bundle_probe = extract_dotnet_single_file_bundle(context.target, output_dir)
        if bundle_probe is None:
            return None

        report.add_framework(".NET single-file bundle")
        report.add_artifact(str(output_dir / "files"), "directory", ".NET single-file bundle extracted files")
        report.add_artifact(str(output_dir / "bundle_manifest.json"), "manifest", ".NET single-file bundle manifest")
        report.add_note(
            f".NET single-file bundle manifest parsed: version {bundle_probe['major_version']}.{bundle_probe['minor_version']} with {bundle_probe['file_count']} embedded files."
        )
        main_assembly = self._select_main_bundle_assembly(context, bundle_probe)
        if main_assembly is not None:
            report.add_note(f"Recovered bundled managed assembly candidate: {main_assembly.name}.")
        return bundle_probe

    def _bundle_managed_candidates(self, context, bundle_probe: dict[str, object]) -> list[Path]:
        files: list[Path] = []
        main_candidate = self._select_main_bundle_assembly(context, bundle_probe)
        if main_candidate is not None:
            files.append(main_candidate)
        for entry in bundle_probe.get("extracted_entries", []):
            path = Path(str(entry.get("destination", "")))
            if path.suffix.lower() == ".dll" and path not in files:
                files.append(path)
        return files

    def _select_main_bundle_assembly(self, context, bundle_probe: dict[str, object]) -> Path | None:
        expected_names: list[str] = []
        for key in ("OriginalFilename", "InternalName"):
            value = context.version_info.get(key, "").strip()
            if value.lower().endswith(".dll"):
                expected_names.append(Path(value).name.lower())
        expected_names.extend(
            [
                f"{context.target.stem.lower()}.dll",
                f"{safe_slug(context.target.stem).lower()}.dll",
            ]
        )

        extracted = [
            Path(str(entry.get("destination", "")))
            for entry in bundle_probe.get("extracted_entries", [])
            if str(entry.get("relative_path", "")).lower().endswith(".dll")
        ]
        for expected in dict.fromkeys(expected_names):
            for candidate in extracted:
                if candidate.name.lower() == expected:
                    return candidate
        return extracted[0] if extracted else None
