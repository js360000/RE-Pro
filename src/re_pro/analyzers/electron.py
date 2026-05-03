from __future__ import annotations

import json
from pathlib import Path

from ..asar_tools import extract_asar_archive
from ..frontend_reconstruct import reconstruct_bundled_frontend_assets
from ..sourcemap import restore_sources_from_map
from ..sourcemap import restore_inline_source_maps_from_file
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
        css_files = self._collect_files(search_roots, "*.css")
        map_files = self._collect_files(search_roots, "*.map")
        if js_files:
            report.add_note(f"Recovered {len(js_files)} JavaScript files across Electron asset roots.")
        if css_files:
            report.add_note(f"Recovered {len(css_files)} CSS files across Electron asset roots.")
        total_restored = self._restore_source_maps(context, report, map_files, js_files + css_files)
        if extracted_dir and map_files:
            maps_inside_asar = [path for path in map_files if extracted_dir in path.parents]
            if maps_inside_asar:
                report.add_note(f"Found {len(maps_inside_asar)} source map file(s) inside extracted app.asar.")

        if not total_restored and getattr(context.frontend_settings, "beautify_bundles", False):
            self._reconstruct_bundled_assets(search_roots, context, report)

    def _extract_asar(self, asar_path: Path, context) -> Path | None:
        destination, error = extract_asar_archive(asar_path, context.output_dir / "extracted_asar", cwd=asar_path.parent)
        if destination is not None:
            context.log(f"Extracted app.asar into {destination}")
            return destination
        context.log(f"asar extraction failed: {error}")
        return None

    @staticmethod
    def _restore_source_maps(context, report, map_files: list[Path], js_files: list[Path]) -> int:
        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        total_restored = 0
        if map_files:
            report.add_note(f"Recovered {len(map_files)} source map file(s) across Electron asset roots.")
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
        inline_map_count = 0
        for source_file in js_files:
            restored_sources, notes = restore_inline_source_maps_from_file(source_file, recovered_root)
            if restored_sources:
                inline_map_count += 1
            for source in restored_sources:
                report.add_recovered_source(
                    original_path=source.original_path,
                    restored_path=source.restored_path,
                    source_map=source.source_map,
                )
            total_restored += len(restored_sources)
            report.notes.extend(notes)
        if inline_map_count:
            report.add_note(f"Recovered original sources from {inline_map_count} inline Electron source map reference(s).")
        if total_restored:
            report.add_finding(
                "Source map restoration succeeded",
                f"Recovered {total_restored} original source files from shipped Electron source maps.",
                severity="info",
            )
        return total_restored

    @staticmethod
    def _reconstruct_bundled_assets(search_roots: list[Path], context, report) -> None:
        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        total = 0
        for root in search_roots:
            if not root.exists() or not root.is_dir():
                continue
            reconstructed = reconstruct_bundled_frontend_assets(
                root,
                root / "RE_PRO_ASSET_MANIFEST.json",
                recovered_root,
                bundle_name=f"electron_{root.name}",
                llm_settings=getattr(context, "llm_settings", None),
            )
            count = int(reconstructed.get("recovered_count") or 0)
            if not count:
                continue
            total += count
            report.add_artifact(
                str(reconstructed["source_root"]),
                "directory",
                "Beautified Electron bundled frontend sources",
            )
            report.add_artifact(
                str(reconstructed["manifest_path"]),
                "manifest",
                "Electron bundled source beautification manifest",
            )
            for recovered in reconstructed.get("recovered_sources") or []:
                report.add_recovered_source(
                    original_path=str(recovered["original_path"]),
                    restored_path=str(recovered["restored_path"]),
                    source_map=str(recovered["source_map"]),
                )
            report.notes.extend(str(note) for note in reconstructed.get("notes") or [])
        if total:
            report.add_finding(
                "Bundled frontend source approximation generated",
                f"Beautified {total} Electron frontend asset(s) because no usable source maps were restored.",
                severity="info",
            )

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
