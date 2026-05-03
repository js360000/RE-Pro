from __future__ import annotations

import json
from pathlib import Path

from ..ddl import index_ddl_results, parse_ddl_from_file, write_ddl_manifest, write_ddl_struct_sources
from ..live_process import capture_live_process
from ..models import LiveProcessSettings
from ..utils import ensure_dir
from .base import Analyzer


class LiveProcessAnalyzer(Analyzer):
    name = "Live process attach"

    def analyze(self, context, report) -> None:
        settings: LiveProcessSettings = context.live_process_settings
        if not settings.enabled:
            return
        live_dir = ensure_dir(context.output_dir / "live_process")
        try:
            manifest = capture_live_process(output_dir=live_dir, settings=settings, logger=context.log)
        except Exception as exc:
            report.add_finding(
                "Live process attach failed",
                "RE-Pro could not attach to the requested running process.",
                severity="warning",
                details=str(exc),
            )
            report.add_note(f"Live process attach failed: {exc}")
            return

        manifest_path = Path(str(manifest.get("manifest_path", live_dir / "live_process_manifest.json")))
        if not manifest_path.exists():
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        report.add_framework("Live process attach")
        report.add_artifact(str(manifest_path), "runtime", "Live process attach manifest")
        for key, description in [
            ("process", "Live process metadata"),
            ("modules", "Live process module list"),
            ("regions", "Live process memory region map"),
            ("strings", "Live process strings recovered from dumped memory"),
        ]:
            path = str((manifest.get("artifacts") or {}).get(key, "")).strip()
            if path:
                report.add_artifact(path, "runtime", description)
        for region in manifest.get("dumped_regions") or []:
            path = str(region.get("path", "")).strip()
            if path:
                report.add_artifact(path, "memory", "Live process memory region dump")
        for payload in manifest.get("carved_payloads") or []:
            path = str(payload.get("path", "")).strip()
            kind = str(payload.get("kind", "payload"))
            if not path:
                continue
            category = "source" if kind == "source_text_fragment" else "payload"
            report.add_artifact(path, category, f"Live process carved {kind}")
            if kind == "source_text_fragment":
                report.add_recovered_source(
                    f"live_process/{Path(path).name}",
                    path,
                    str(manifest_path),
                )

        self._recover_runtime_ddl(context, report, manifest, manifest_path)

        summary = manifest.get("summary") or {}
        report.add_finding(
            "Live process memory snapshot captured",
            "RE-Pro attached to an already-running process and captured modules, memory metadata, dumped regions, carved payloads, and runtime strings.",
            severity="info",
            details=(
                f"pid={(manifest.get('process') or {}).get('pid')}; "
                f"modules={summary.get('module_count', 0)}; "
                f"regions={summary.get('dumped_region_count', 0)}; "
                f"carved={summary.get('carved_payload_count', 0)}; "
                f"bytes={summary.get('dumped_bytes', 0)}"
            ),
        )
        if manifest.get("carved_payloads"):
            kinds = ", ".join(sorted({str(item.get("kind", "")) for item in manifest.get("carved_payloads") or [] if item.get("kind")})[:12])
            report.add_note(f"Live process attach carved runtime payloads: {kinds}.")
        self._index_manifest(context, manifest, manifest_path)

    @staticmethod
    def _index_manifest(context, manifest: dict, manifest_path: Path) -> None:
        process = manifest.get("process") or {}
        target_id = context.analysis_index.make_id("target", str(context.target))
        artifact_id = context.analysis_index.add_entity(
            "artifact",
            str(manifest_path),
            "Live process attach manifest",
            attributes={"path": str(manifest_path), "category": "runtime"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        process_id = context.analysis_index.add_entity(
            "runtime_process",
            str(process.get("pid")),
            str(process.get("name") or f"PID {process.get('pid')}"),
            attributes=process,
        )
        context.analysis_index.add_relation(target_id, "attached_to_runtime_process", process_id)
        context.analysis_index.add_relation(process_id, "originates_from_artifact", artifact_id)
        for module in manifest.get("modules") or []:
            label = str(module.get("name") or module.get("path") or "module")
            key = str(module.get("path") or label).lower()
            module_id = context.analysis_index.add_entity("runtime_module", key, label, attributes=module)
            context.analysis_index.add_relation(process_id, "loaded_module", module_id)
        for region in manifest.get("dumped_regions") or []:
            key = f"{process.get('pid')}:{region.get('base_address_hex')}"
            label = f"region {region.get('base_address_hex')}"
            region_id = context.analysis_index.add_entity("runtime_memory_region", key, label, attributes=region)
            context.analysis_index.add_relation(process_id, "dumped_memory_region", region_id)
        for payload in manifest.get("carved_payloads") or []:
            key = str(payload.get("path", "")).lower()
            label = f"{payload.get('kind')} {Path(str(payload.get('path', 'payload'))).name}"
            payload_id = context.analysis_index.add_entity("runtime_payload", key, label, attributes=payload)
            context.analysis_index.add_relation(process_id, "materialized_runtime_payload", payload_id)

    @staticmethod
    def _recover_runtime_ddl(context, report, manifest: dict, manifest_path: Path) -> None:
        candidate_paths: list[Path] = []
        seen: set[Path] = set()
        for region in manifest.get("dumped_regions") or []:
            path = Path(str(region.get("path", "")).strip())
            if path.exists() and path not in seen:
                candidate_paths.append(path)
                seen.add(path)
        for payload in manifest.get("carved_payloads") or []:
            path = Path(str(payload.get("path", "")).strip())
            kind = str(payload.get("kind", ""))
            if path.exists() and kind in {"source_text_fragment", "payload", "text"} and path not in seen:
                candidate_paths.append(path)
                seen.add(path)
        if not candidate_paths:
            return

        parsed_results: list[dict[str, object]] = []
        generated_sources: list[Path] = []
        source_dir = ensure_dir(context.output_dir / "live_process" / "ddl" / "recovered_structs")
        for candidate in candidate_paths:
            parsed = parse_ddl_from_file(candidate)
            if not parsed.get("ok"):
                continue
            parsed_results.append(parsed)
            generated_sources.extend(write_ddl_struct_sources(parsed, source_dir, prefix=candidate.stem))
        if not parsed_results:
            return

        ddl_manifest_path = write_ddl_manifest(parsed_results, context.output_dir / "live_process" / "ddl" / "runtime_ddl_structs.json")
        report.add_framework("Runtime DDL schemas")
        report.add_artifact(str(ddl_manifest_path), "runtime", "Runtime-recovered DDL struct manifest")
        if generated_sources:
            report.add_artifact(str(source_dir), "source", "Runtime-recovered DDL struct pseudo-source")
            for source_path in generated_sources:
                report.add_recovered_source(
                    f"live_process/ddl/{source_path.name}",
                    str(source_path),
                    str(ddl_manifest_path),
                )
        report.add_finding(
            "Runtime DDL structs recovered",
            "Live memory contained recoverable data-definition structs, likely after the process decompressed or materialized runtime schemas.",
            severity="info",
            details=f"sources={len(parsed_results)}; manifest={ddl_manifest_path}; capture={manifest_path}",
        )
        index_ddl_results(
            context.analysis_index,
            target_path=str(context.target),
            manifest_path=ddl_manifest_path,
            results=parsed_results,
            target_relation="defines_runtime_ddl_struct",
        )
