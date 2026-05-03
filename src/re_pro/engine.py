from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import time
from typing import Callable

from .analysis_index import AnalysisIndex
from .index_ingest import ingest_structured_artifacts
from .models import AnalysisReport
from .models import FrontendSettings
from .models import LiveProcessSettings
from .models import LlmAssistSettings
from .models import OutputSettings
from .models import PortingSettings
from .models import RuntimeTraceSettings
from .output_organizer import organize_output_view
from .plugins import build_analyzers, resolve_plugin_dirs
from .recovery_insights import write_recovery_insights
from .reporting import write_json_report, write_markdown_report
from .elf import (
    parse_elf_interpreter,
    parse_elf_metadata,
    parse_elf_needed_libraries,
    parse_elf_program_headers,
    parse_elf_sections,
    parse_elf_symbols,
)
from .utils import (
    ensure_dir,
    extract_ascii_strings,
    is_probable_binary,
    parse_pe_cli_metadata,
    parse_pe_imports,
    parse_pe_metadata,
    parse_pe_sections,
    parse_pe_codeview_records,
    read_pe_version_info,
    read_binary_head,
    safe_slug,
)


@dataclass
class AnalysisContext:
    target: Path
    output_dir: Path
    logger: Callable[[str], None] | None = None
    analysis_index: AnalysisIndex = field(default_factory=AnalysisIndex)
    binary_head: bytes = b""
    ascii_strings: list[str] = field(default_factory=list)
    pe_metadata: dict[str, object] | None = None
    pe_sections: list[dict[str, object]] = field(default_factory=list)
    pe_imports: list[str] = field(default_factory=list)
    pe_codeview_records: list[dict[str, object]] = field(default_factory=list)
    pe_cli_metadata: dict[str, object] | None = None
    elf_metadata: dict[str, object] | None = None
    elf_program_headers: list[dict[str, object]] = field(default_factory=list)
    elf_sections: list[dict[str, object]] = field(default_factory=list)
    elf_symbols: list[dict[str, object]] = field(default_factory=list)
    elf_needed_libraries: list[str] = field(default_factory=list)
    elf_interpreter: str | None = None
    version_info: dict[str, str] = field(default_factory=dict)
    probable_binary: bool = False
    run_external_tools: bool = False
    run_ghidra: bool = False
    llm_settings: LlmAssistSettings = field(default_factory=LlmAssistSettings)
    porting_settings: PortingSettings = field(default_factory=PortingSettings)
    runtime_trace_settings: RuntimeTraceSettings = field(default_factory=RuntimeTraceSettings)
    live_process_settings: LiveProcessSettings = field(default_factory=LiveProcessSettings)
    frontend_settings: FrontendSettings = field(default_factory=FrontendSettings)
    output_settings: OutputSettings = field(default_factory=OutputSettings)

    def log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


class ReverseEngineeringEngine:
    def __init__(
        self,
        output_root: str | Path | None = None,
        logger: Callable[[str], None] | None = None,
        *,
        run_external_tools: bool = False,
        run_ghidra: bool = False,
        llm_settings: LlmAssistSettings | None = None,
        porting_settings: PortingSettings | None = None,
        runtime_trace_settings: RuntimeTraceSettings | None = None,
        live_process_settings: LiveProcessSettings | None = None,
        frontend_settings: FrontendSettings | None = None,
        output_settings: OutputSettings | None = None,
        plugin_dirs: list[str | Path] | None = None,
    ) -> None:
        self.output_root = Path(output_root).resolve() if output_root else (Path.cwd() / "analysis_output").resolve()
        self.logger = logger
        self.run_external_tools = run_external_tools
        self.run_ghidra = run_ghidra
        self.llm_settings = llm_settings or LlmAssistSettings()
        self.porting_settings = porting_settings or PortingSettings()
        self.runtime_trace_settings = runtime_trace_settings or RuntimeTraceSettings()
        self.live_process_settings = live_process_settings or LiveProcessSettings()
        self.frontend_settings = frontend_settings or FrontendSettings()
        self.output_settings = output_settings or OutputSettings()
        self.plugin_dirs = resolve_plugin_dirs(plugin_dirs)
        self.analyzers = build_analyzers(plugin_dirs=self.plugin_dirs, logger=self.logger)

    def analyze(self, target: str | Path) -> AnalysisReport:
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(target_path)

        output_dir = self._create_output_dir(target_path)
        context = AnalysisContext(
            target=target_path,
            output_dir=output_dir,
            logger=self.logger,
            run_external_tools=self.run_external_tools,
            run_ghidra=self.run_ghidra,
            llm_settings=self.llm_settings,
            porting_settings=self.porting_settings,
            runtime_trace_settings=self.runtime_trace_settings,
            live_process_settings=self.live_process_settings,
            frontend_settings=self.frontend_settings,
            output_settings=self.output_settings,
        )
        report = AnalysisReport(target=str(target_path), output_dir=str(output_dir))

        if target_path.is_dir():
            report.target_type = "directory"
        else:
            report.target_type = target_path.suffix.lstrip(".").lower() or "file"
            context.binary_head = read_binary_head(target_path)
            context.ascii_strings = extract_ascii_strings(context.binary_head)
            context.pe_metadata = parse_pe_metadata(target_path)
            context.pe_sections = parse_pe_sections(target_path)
            context.pe_imports = parse_pe_imports(target_path)
            context.pe_codeview_records = parse_pe_codeview_records(target_path)
            context.pe_cli_metadata = parse_pe_cli_metadata(target_path)
            context.elf_metadata = parse_elf_metadata(target_path)
            context.elf_program_headers = parse_elf_program_headers(target_path)
            context.elf_sections = parse_elf_sections(target_path)
            context.elf_symbols = parse_elf_symbols(target_path)
            context.elf_needed_libraries = parse_elf_needed_libraries(target_path)
            context.elf_interpreter = parse_elf_interpreter(target_path)
            context.version_info = read_pe_version_info(target_path)
            context.probable_binary = is_probable_binary(target_path, context.binary_head)
            if report.target_type == "file" and context.elf_metadata is not None:
                report.target_type = "elf"
        self._seed_analysis_index(context, report)

        self._log(f"Starting analysis for {target_path}")
        for analyzer in self.analyzers:
            started = time.monotonic()
            self._log(f"Running analyzer: {analyzer.name}")
            analyzer.analyze(context, report)
            self._log(f"Completed analyzer: {analyzer.name} in {time.monotonic() - started:.1f}s")

        self._write_pipeline_manifest(report, output_dir)
        self._write_analysis_index(context, report, output_dir)
        report_json = write_json_report(report, output_dir / "report.json")
        report_markdown = write_markdown_report(report, output_dir / "report.md")
        report.add_artifact(str(report_json), "report", "Machine-readable JSON report")
        report.add_artifact(str(report_markdown), "report", "Human-readable markdown report")
        output_view = organize_output_view(report, output_dir, self.output_settings)
        if output_view:
            report.add_artifact(str(output_view["view_root"]), "directory", "Curated operator output view")
            report.add_artifact(str(output_view["manifest_path"]), "manifest", "Output view manifest")
            report.add_artifact(str(output_view["readme_path"]), "report", "Output view README")
            report.add_note(
                f"Curated output view generated at {output_view['view_root']} "
                f"({output_view['profile']} profile, {output_view['mode']} mode, {output_view['entry_count']} entries)."
            )
        write_json_report(report, output_dir / "report.json")
        write_markdown_report(report, output_dir / "report.md")
        self._log(f"Analysis completed. Output written to {output_dir}")
        return report

    def _create_output_dir(self, target_path: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return ensure_dir(self.output_root / f"{safe_slug(target_path.stem)}_{timestamp}")

    def _write_pipeline_manifest(self, report: AnalysisReport, output_dir: Path) -> None:
        manifest_path = output_dir / "analysis_pipeline.json"
        payload = {
            "analyzers": [
                {
                    "name": analyzer.name,
                    "class": analyzer.__class__.__name__,
                    "module": analyzer.__class__.__module__,
                }
                for analyzer in self.analyzers
            ],
            "plugin_dirs": [str(path) for path in self.plugin_dirs],
            "output_settings": self.output_settings.to_dict(),
        }
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        report.add_artifact(str(manifest_path), "manifest", "Analysis pipeline manifest")

    def _seed_analysis_index(self, context: AnalysisContext, report: AnalysisReport) -> None:
        target_id = context.analysis_index.ensure_target(str(context.target), report.target_type)
        if context.pe_metadata is not None:
            pe_id = context.analysis_index.add_entity(
                "format",
                f"pe:{context.target.name}",
                "Portable Executable",
                attributes={
                    "machine": context.pe_metadata.get("machine"),
                    "sections": context.pe_metadata.get("sections"),
                    "number_of_sections": context.pe_metadata.get("number_of_sections"),
                },
            )
            context.analysis_index.add_relation(target_id, "has_format", pe_id)
            for name in context.pe_imports:
                import_id = context.analysis_index.add_entity("import", name.lower(), name, attributes={"family": "pe"})
                context.analysis_index.add_relation(target_id, "imports", import_id)
            for section in context.pe_sections:
                name = str(section.get("name", "")).strip()
                if not name:
                    continue
                section_id = context.analysis_index.add_entity(
                    "section",
                    f"pe:{name}",
                    name,
                    attributes=section,
                )
                context.analysis_index.add_relation(target_id, "contains_section", section_id)
        if context.elf_metadata is not None:
            elf_id = context.analysis_index.add_entity(
                "format",
                f"elf:{context.target.name}",
                "ELF",
                attributes=context.elf_metadata,
            )
            context.analysis_index.add_relation(target_id, "has_format", elf_id)
            for section in context.elf_sections:
                name = str(section.get("name", "")).strip()
                if not name:
                    continue
                section_id = context.analysis_index.add_entity(
                    "section",
                    f"elf:{name}",
                    name,
                    attributes=section,
                )
                context.analysis_index.add_relation(target_id, "contains_section", section_id)
            for library in context.elf_needed_libraries:
                library_id = context.analysis_index.add_entity("import", library.lower(), library, attributes={"family": "elf"})
                context.analysis_index.add_relation(target_id, "imports", library_id)
        if context.pe_cli_metadata is not None:
            cli_id = context.analysis_index.add_entity(
                "managed_metadata",
                f"cli:{context.target.name}",
                ".NET CLR metadata",
                attributes={
                    "runtime_version": context.pe_cli_metadata.get("runtime_version"),
                    "metadata_version": context.pe_cli_metadata.get("metadata_version"),
                    "flags": context.pe_cli_metadata.get("flags"),
                    "streams": context.pe_cli_metadata.get("metadata_streams"),
                },
            )
            context.analysis_index.add_relation(target_id, "has_managed_metadata", cli_id)
        if context.version_info:
            version_id = context.analysis_index.add_entity(
                "version_info",
                context.target.name.lower(),
                context.target.name,
                attributes=context.version_info,
            )
            context.analysis_index.add_relation(target_id, "has_version_info", version_id)
        for record in context.pe_codeview_records:
            pdb_path = str(record.get("pdb_path", "")).strip()
            if not pdb_path:
                continue
            debug_id = context.analysis_index.add_entity(
                "debug_reference",
                pdb_path.lower(),
                pdb_path,
                attributes=record,
            )
            context.analysis_index.add_relation(target_id, "references_debug_artifact", debug_id)

    def _write_analysis_index(self, context: AnalysisContext, report: AnalysisReport, output_dir: Path) -> None:
        target_id = context.analysis_index.ensure_target(str(context.target), report.target_type)
        for framework in report.frameworks:
            framework_id = context.analysis_index.add_entity("framework", framework.lower(), framework)
            context.analysis_index.add_relation(target_id, "matches_framework", framework_id)
        for finding in report.findings:
            finding_id = context.analysis_index.add_entity(
                "finding",
                finding.title.lower(),
                finding.title,
                attributes={
                    "severity": finding.severity,
                    "summary": finding.summary,
                    "details": finding.details,
                },
            )
            context.analysis_index.add_relation(target_id, "has_finding", finding_id)
        for artifact in report.artifacts:
            artifact_id = context.analysis_index.add_entity(
                "artifact",
                artifact.path,
                artifact.description,
                attributes={
                    "path": artifact.path,
                    "category": artifact.category,
                    "description": artifact.description,
                },
            )
            context.analysis_index.add_relation(target_id, "produced_artifact", artifact_id)
        for source in report.recovered_sources:
            source_id = context.analysis_index.add_entity(
                "recovered_source",
                source.restored_path,
                source.original_path,
                attributes={
                    "original_path": source.original_path,
                    "restored_path": source.restored_path,
                    "source_map": source.source_map,
                },
            )
            context.analysis_index.add_relation(target_id, "recovered_source", source_id)

        ingest_summary = ingest_structured_artifacts(context.analysis_index, report)
        if ingest_summary["indexed_functions"] or ingest_summary["indexed_strings"]:
            report.add_note(
                "Unified analysis index normalized "
                f"{ingest_summary['indexed_functions']} function candidate(s) and "
                f"{ingest_summary['indexed_strings']} string candidate(s) from structured tool exports."
            )
        if ingest_summary["correlated_functions"] or ingest_summary["correlated_strings"]:
            report.add_note(
                "Cross-tool correlation linked "
                f"{ingest_summary['correlated_functions']} function address match(es) and "
                f"{ingest_summary['correlated_strings']} string address match(es)."
            )

        insight_artifacts = write_recovery_insights(report, context.analysis_index.to_dict(), output_dir)
        for insight in insight_artifacts:
            report.add_artifact(str(insight.path), insight.category, insight.description)
            insight_id = context.analysis_index.add_entity(
                "artifact",
                str(insight.path),
                insight.description,
                attributes={
                    "path": str(insight.path),
                    "category": insight.category,
                    "description": insight.description,
                },
            )
            context.analysis_index.add_relation(target_id, "produced_artifact", insight_id)

        index_path = output_dir / "analysis_index.json"
        index_path.write_text(json.dumps(context.analysis_index.to_dict(), indent=2), encoding="utf-8")
        report.add_artifact(str(index_path), "manifest", "Unified analysis index")

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)
