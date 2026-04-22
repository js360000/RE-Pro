from __future__ import annotations

import json
import re
from pathlib import Path

from ..tauri_extract import extract_tauri_assets
from ..utils import ensure_dir
from .base import Analyzer


class TauriAnalyzer(Analyzer):
    name = "Tauri detection"

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or context.pe_metadata is None:
            return

        sections = context.pe_metadata.get("sections", []) if context.pe_metadata else []
        strings_lower = [value.lower() for value in context.ascii_strings]
        sibling_names = {path.name.lower() for path in context.target.parent.iterdir()}
        binary_markers = self._scan_binary_markers(context.target)

        tauri_section = any(section in {".taubndl", ".tauri", ".taurii"} for section in sections)
        tauri_hits = [
            value
            for value in strings_lower
            if any(marker in value for marker in ("tauri://", "wry::", "tao::", "tauri-runtime", "__tauri", "tauri.conf"))
        ]
        sibling_hits = {
            name
            for name in sibling_names
            if name in {"bundled-node", "bundled-agents", "configs", "subagents", "codex-acp", "nsis_tauri_utils.dll"}
        }
        if any(framework.startswith("Installer:") for framework in report.frameworks) and not tauri_section:
            return
        if not tauri_section and len(tauri_hits) < 2 and not binary_markers["strong_tauri"] and not sibling_hits:
            return

        report.add_framework("Tauri")
        report.add_framework("Rust native binary")
        report.add_finding(
            "Tauri application detected",
            "The executable appears to be a Tauri desktop application with a Rust native host and bundled web frontend assets.",
            severity="info",
        )

        if tauri_section:
            report.add_note("The PE contains a .taubndl-style section, which is consistent with embedded Tauri bundle data.")
        if sibling_hits:
            report.add_note(
                "Sibling files next to the executable also match a Tauri app layout: " + ", ".join(sorted(sibling_hits))
            )
        report.add_note(
            "Tauri apps often embed their frontend assets inside the executable, so original filenames and source trees are only recoverable when source maps or debug paths were shipped."
        )
        self._recover_embedded_manifest(context, report, binary_markers)

    def _recover_embedded_manifest(self, context, report, binary_markers: dict[str, object]) -> None:
        data = context.target.read_bytes()
        tauri_dir = ensure_dir(context.output_dir / "tauri")

        self._dump_sections(context, tauri_dir, report)

        asset_paths = sorted(
            {
                match.group(0).decode("utf-8", "ignore")
                for match in re.finditer(
                    rb"(?:"
                    rb"/assets/[A-Za-z0-9_./%-]+?\.(?:js|css|html|svg|png|ico|json|map|woff2?|ttf|otf|md)"
                    rb"|/_next/static/[A-Za-z0-9_./%-]+?\.(?:js|css|map|json|woff2?)"
                    rb"|/index\.html"
                    rb"|/manifest\.json"
                    rb"|/web-app-manifest-[A-Za-z0-9._-]+?\.png"
                    rb"|/favicon-[A-Za-z0-9._-]+?\.png"
                    rb"|/apple-touch-icon(?:-[A-Za-z0-9._-]+)?\.png"
                    rb")",
                    data,
                )
            }
        )
        icon_paths = sorted(
            {
                match.group(0).decode("utf-8", "ignore")
                for match in re.finditer(rb"icons/[A-Za-z0-9_./-]+?\.(?:png|ico|icns)", data)
            }
        )
        sidecars = sorted(
            {
                match.group(0).decode("utf-8", "ignore")
                for match in re.finditer(rb"sidecars/[A-Za-z0-9_./-]+", data)
            }
        )
        updater_urls = sorted(
            {
                match.group(0).decode("utf-8", "ignore")
                for match in re.finditer(rb"https?://[A-Za-z0-9./_%:+?=&-]+latest\.json", data)
            }
        )
        cargo_paths = sorted(
            {
                value
                for value in context.ascii_strings
                if ".cargo\\registry\\" in value or ".cargo/registry/" in value
            }
        )

        manifest = {
            "asset_paths": asset_paths,
            "icon_paths": icon_paths,
            "sidecars": sidecars,
            "updater_urls": updater_urls,
            "cargo_paths": cargo_paths[:100],
            "frontend": self._infer_frontend(asset_paths, context.ascii_strings),
            "source_map_paths": binary_markers["source_map_paths"],
        }
        manifest_path = tauri_dir / "embedded_asset_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        report.add_artifact(str(manifest_path), "manifest", "Recovered Tauri embedded asset manifest")

        if asset_paths:
            report.add_finding(
                "Embedded frontend asset names recovered",
                f"Recovered {len(asset_paths)} embedded frontend asset paths from the Tauri executable.",
                severity="info",
            )
            report.add_note(f"Recovered {len(asset_paths)} embedded frontend asset paths from the executable image.")
        if binary_markers["source_map_paths"]:
            report.add_note(
                f"Embedded web bundle references include {len(binary_markers['source_map_paths'])} source map path(s)."
            )

        if sidecars:
            report.add_note(f"Tauri sidecars referenced by the app: {', '.join(sidecars[:5])}")

        if updater_urls:
            report.add_note(f"Recovered updater metadata URL: {updater_urls[0]}")
        if cargo_paths:
            report.add_note("Recovered Rust cargo registry source paths, which may help fingerprint the exact Tauri/runtime dependency set.")

        frontend = manifest["frontend"]
        if frontend:
            report.add_framework(frontend)

        extracted = extract_tauri_assets(
            context.target,
            destination_root=tauri_dir,
            recovered_sources_root=ensure_dir(context.output_dir / "recovered_sources"),
        )
        extracted_count = int(extracted["extracted_count"])
        if extracted_count:
            assets_dir = extracted["assets_dir"]
            manifest_path = extracted["manifest_path"]
            report.add_artifact(str(assets_dir), "directory", "Extracted Tauri frontend assets")
            report.add_artifact(str(manifest_path), "manifest", "Extracted Tauri asset manifest")
            report.add_finding(
                "Embedded Tauri asset extraction succeeded",
                f"Extracted and decompressed {extracted_count} embedded Tauri assets from the executable.",
                severity="info",
            )
            report.add_note(f"Extracted {extracted_count} embedded Tauri asset bodies into {assets_dir}.")
        restored_total = len(extracted["restored_sources"])
        if restored_total:
            report.add_finding(
                "Source map restoration succeeded",
                f"Recovered {restored_total} original source files from shipped Tauri source maps.",
                severity="info",
            )
        for recovered in extracted["restored_sources"]:
            report.add_recovered_source(
                original_path=recovered["original_path"],
                restored_path=recovered["restored_path"],
                source_map=recovered["source_map"],
            )
        report.notes.extend(extracted["notes"])

    @staticmethod
    def _infer_frontend(asset_paths: list[str], ascii_strings: list[str]) -> str | None:
        if any(path.startswith("/_next/static/") for path in asset_paths):
            if any("turbopack" in path for path in asset_paths) or any("turbopack" in value.lower() for value in ascii_strings):
                return "Web framework: Next.js (Turbopack)"
            return "Web framework: Next.js"
        if any("__vite-browser-external" in path or re.search(r"/assets/index-[A-Za-z0-9_-]+\.(?:js|css)", path) for path in asset_paths):
            return "Frontend bundle: Vite"
        if any("__webpack_require__" in value or "webpack://" in value for value in ascii_strings):
            return "Frontend bundle: webpack"
        return None

    @staticmethod
    def _scan_binary_markers(target: Path) -> dict[str, object]:
        data = target.read_bytes()
        lower_data = data.lower()
        source_map_paths = sorted(
            {
                match.group(0).decode("utf-8", "ignore")
                for match in re.finditer(rb"/(?:_next/static|assets)/[A-Za-z0-9_./%-]+?\.map", data)
            }
        )
        return {
            "strong_tauri": any(marker in lower_data for marker in (b"__tauri", b"tauri://", b"tauri-runtime", b"wry::", b"tao::")),
            "source_map_paths": source_map_paths,
        }

    @staticmethod
    def _dump_sections(context, tauri_dir: Path, report) -> None:
        if not context.pe_sections:
            return
        sections_dir = ensure_dir(tauri_dir / "sections")
        with context.target.open("rb") as handle:
            for section in context.pe_sections:
                name = str(section.get("name") or "section")
                raw_offset = int(section.get("raw_offset") or 0)
                raw_size = int(section.get("raw_size") or 0)
                if raw_size <= 0:
                    continue
                if name not in {".taubndl", ".rsrc"}:
                    continue
                handle.seek(raw_offset)
                blob = handle.read(raw_size)
                section_path = sections_dir / f"{name.strip('.') or 'section'}.bin"
                section_path.write_bytes(blob)
                report.add_artifact(str(section_path), "binary", f"Extracted PE section {name}")
