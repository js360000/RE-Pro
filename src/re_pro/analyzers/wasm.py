from __future__ import annotations

import json

from ..sourcemap import restore_sources_from_map
from ..utils import ensure_dir
from ..wasm import describe_wasm_toolchains, find_adjacent_wasm_map, is_wasm_binary, parse_wasm_module
from .base import Analyzer


class WasmAnalyzer(Analyzer):
    name = "WebAssembly recovery"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return
        if context.target.suffix.lower() != ".wasm" and not is_wasm_binary(context.target):
            return

        module_info = parse_wasm_module(context.target)
        if module_info is None:
            return

        report.target_type = "wasm-module"
        for framework in describe_wasm_toolchains(module_info):
            report.add_framework(framework)

        metadata_path = context.output_dir / "wasm_metadata.json"
        metadata_path.write_text(json.dumps(module_info, indent=2), encoding="utf-8")
        report.add_artifact(str(metadata_path), "metadata", "WebAssembly module metadata")

        imports = module_info.get("imports") or []
        exports = module_info.get("exports") or []
        custom_sections = module_info.get("custom_sections") or []
        report.add_finding(
            "WebAssembly module parsed",
            "RE-Pro parsed the WebAssembly header, sections, imports, exports, and custom metadata.",
            severity="info",
            details=f"imports={len(imports)}; exports={len(exports)}; custom_sections={len(custom_sections)}",
        )
        producers = module_info.get("producers") or {}
        if producers:
            producer_summary = []
            for category, values in producers.items():
                rendered = ", ".join(f"{item.get('name')} {item.get('version')}".strip() for item in values[:4])
                producer_summary.append(f"{category}: {rendered}")
            report.add_note(f"WASM producers metadata: {'; '.join(producer_summary)}")
        if module_info.get("source_mapping_url"):
            report.add_note(f"WASM sourceMappingURL: {module_info['source_mapping_url']}")

        self._restore_source_map(context, report, module_info)
        self._index_wasm_module(context, module_info, metadata_path)

    @staticmethod
    def _restore_source_map(context, report, module_info: dict[str, object]) -> None:
        map_path = find_adjacent_wasm_map(context.target, module_info)
        if map_path is None:
            return
        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        restored_sources, notes = restore_sources_from_map(map_path, recovered_root)
        for source in restored_sources:
            report.add_recovered_source(
                original_path=source.original_path,
                restored_path=source.restored_path,
                source_map=source.source_map,
            )
        report.notes.extend(notes)
        if restored_sources:
            report.add_finding(
                "WebAssembly source map restoration succeeded",
                f"Recovered {len(restored_sources)} source file(s) from the adjacent WebAssembly source map.",
                severity="info",
            )

    @staticmethod
    def _index_wasm_module(context, module_info: dict[str, object], metadata_path) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        module_id = context.analysis_index.add_entity(
            "format",
            f"wasm:{context.target.name}",
            "WebAssembly module",
            attributes={
                "version": module_info.get("version"),
                "import_count": len(module_info.get("imports") or []),
                "export_count": len(module_info.get("exports") or []),
            },
        )
        context.analysis_index.add_relation(target_id, "has_format", module_id)
        artifact_id = context.analysis_index.add_entity(
            "artifact",
            str(metadata_path),
            metadata_path.name,
            attributes={"path": str(metadata_path), "category": "metadata"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        for imported in module_info.get("imports") or []:
            label = f"{imported.get('module')}::{imported.get('name')}"
            import_id = context.analysis_index.add_entity(
                "import",
                label.lower(),
                label,
                attributes=imported,
            )
            context.analysis_index.add_relation(target_id, "imports", import_id)
        for exported in module_info.get("exports") or []:
            label = str(exported.get("name") or "export")
            export_id = context.analysis_index.add_entity(
                "export",
                label.lower(),
                label,
                attributes=exported,
            )
            context.analysis_index.add_relation(target_id, "exports", export_id)
