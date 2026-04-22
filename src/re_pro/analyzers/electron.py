from __future__ import annotations

import json
from pathlib import Path

from ..sourcemap import restore_sources_from_map
from ..tooling import resolve_command, run_command
from ..utils import ensure_dir
from .base import Analyzer


class ElectronAnalyzer(Analyzer):
    name = "Electron/web package recovery"

    def analyze(self, context, report) -> None:
        base_dir = context.target if context.target.is_dir() else context.target.parent
        if not context.target.is_dir() and not context.probable_binary and context.pe_metadata is None:
            return
        resources_dir = base_dir / "resources"
        app_dir = resources_dir / "app"
        unpacked_dir = resources_dir / "app.asar.unpacked"
        asar_path = resources_dir / "app.asar"

        search_roots: list[Path] = []
        extracted_dir: Path | None = None

        if app_dir.exists() or unpacked_dir.exists() or asar_path.exists():
            report.add_framework("Electron")
            report.add_finding(
                "Electron packaging detected",
                "Sibling Electron resources were found next to the target executable.",
                severity="info",
            )

        if app_dir.exists():
            search_roots.append(app_dir)
            report.add_artifact(str(app_dir), "directory", "Electron unpacked app directory")
        if unpacked_dir.exists():
            search_roots.append(unpacked_dir)
            report.add_artifact(str(unpacked_dir), "directory", "Electron unpacked asar resources")
        if asar_path.exists():
            report.add_artifact(str(asar_path), "archive", "Electron app.asar archive")
            extracted_dir = self._extract_asar(asar_path, context)
            if extracted_dir:
                search_roots.append(extracted_dir)
                report.add_artifact(str(extracted_dir), "directory", "Extracted app.asar contents")
            else:
                report.add_note(
                    "app.asar was found but could not be extracted automatically. Install `asar` or Node.js with `npx` available."
                )

        if not search_roots:
            if any(
                marker in value.lower()
                for value in context.ascii_strings
                for marker in ("electron.exe", "app.asar", "electron-builder", "squirrel")
            ):
                report.add_framework("Possible Electron")
                report.add_note("Electron-related strings were present, but no sibling resources folder was found.")
            return

        package_json = self._find_first(search_roots, "package.json")
        if package_json:
            report.add_artifact(str(package_json), "manifest", "Recovered package.json")
            self._record_package_metadata(package_json, report)

        js_files = self._collect_files(search_roots, "*.js")
        map_files = self._collect_files(search_roots, "*.map")
        if js_files:
            report.add_note(f"Recovered {len(js_files)} JavaScript files across Electron asset roots.")
        if map_files:
            report.add_note(f"Recovered {len(map_files)} source maps across Electron asset roots.")
            recovered_root = ensure_dir(context.output_dir / "recovered_sources")
            total_restored = 0
            for map_file in map_files:
                restored_sources, notes = restore_sources_from_map(map_file, recovered_root)
                for source in restored_sources:
                    report.add_recovered_source(
                        original_path=source.original_path,
                        restored_path=source.restored_path,
                        source_map=source.source_map,
                    )
                total_restored += len(restored_sources)
                report.notes.extend(notes)
            if total_restored:
                report.add_finding(
                    "Source map restoration succeeded",
                    f"Recovered {total_restored} original source files from shipped source maps.",
                    severity="info",
                )

    def _extract_asar(self, asar_path: Path, context) -> Path | None:
        destination = context.output_dir / "extracted_asar"
        ensure_dir(destination)
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
            context.log(f"Extracted app.asar into {destination}")
            return destination
        context.log(f"asar extraction failed: {stderr.strip()}")
        return None

    @staticmethod
    def _find_first(search_roots: list[Path], pattern: str) -> Path | None:
        for root in search_roots:
            for candidate in root.rglob(pattern):
                return candidate
        return None

    @staticmethod
    def _collect_files(search_roots: list[Path], pattern: str) -> list[Path]:
        results: list[Path] = []
        seen: set[Path] = set()
        for root in search_roots:
            for candidate in root.rglob(pattern):
                resolved = candidate.resolve()
                if resolved not in seen:
                    results.append(candidate)
                    seen.add(resolved)
        return results

    @staticmethod
    def _record_package_metadata(package_json: Path, report) -> None:
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            report.add_note(f"package.json was found at {package_json} but could not be parsed.")
            return

        name = payload.get("name")
        version = payload.get("version")
        dependencies = payload.get("dependencies") or {}
        dev_dependencies = payload.get("devDependencies") or {}
        report.add_note(
            f"package.json name={name or 'unknown'} version={version or 'unknown'} with {len(dependencies)} runtime dependencies."
        )

        for framework_name in ("react", "vue", "svelte", "angular", "next", "nuxt"):
            if framework_name in dependencies or framework_name in dev_dependencies:
                report.add_framework(f"Web framework: {framework_name}")
