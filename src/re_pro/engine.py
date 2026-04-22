from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import time
from typing import Callable

from .analyzers import (
    AndroidAnalyzer,
    AppleAnalyzer,
    DotNetAnalyzer,
    ElectronAnalyzer,
    ExternalToolAnalyzer,
    GameNativeAnalyzer,
    InstallerAnalyzer,
    LLMAssistAnalyzer,
    NativeLanguageAnalyzer,
    PDBAnalyzer,
    PEAnalyzer,
    PEResourceAnalyzer,
    PortingAdvisorAnalyzer,
    PythonPackagedAnalyzer,
    TauriAnalyzer,
)
from .models import AnalysisReport
from .models import LlmAssistSettings
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
    ) -> None:
        self.output_root = Path(output_root).resolve() if output_root else (Path.cwd() / "analysis_output").resolve()
        self.logger = logger
        self.run_external_tools = run_external_tools
        self.run_ghidra = run_ghidra
        self.llm_settings = llm_settings or LlmAssistSettings()
        self.analyzers = [
            AndroidAnalyzer(),
            AppleAnalyzer(),
            PEAnalyzer(),
            PDBAnalyzer(),
            PEResourceAnalyzer(),
            InstallerAnalyzer(),
            ElectronAnalyzer(),
            TauriAnalyzer(),
            DotNetAnalyzer(),
            PythonPackagedAnalyzer(),
            NativeLanguageAnalyzer(),
            GameNativeAnalyzer(),
            ExternalToolAnalyzer(),
            LLMAssistAnalyzer(),
            PortingAdvisorAnalyzer(),
        ]

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

        self._log(f"Starting analysis for {target_path}")
        for analyzer in self.analyzers:
            started = time.monotonic()
            self._log(f"Running analyzer: {analyzer.name}")
            analyzer.analyze(context, report)
            self._log(f"Completed analyzer: {analyzer.name} in {time.monotonic() - started:.1f}s")

        report_json = write_json_report(report, output_dir / "report.json")
        report_markdown = write_markdown_report(report, output_dir / "report.md")
        report.add_artifact(str(report_json), "report", "Machine-readable JSON report")
        report.add_artifact(str(report_markdown), "report", "Human-readable markdown report")
        write_json_report(report, output_dir / "report.json")
        write_markdown_report(report, output_dir / "report.md")
        self._log(f"Analysis completed. Output written to {output_dir}")
        return report

    def _create_output_dir(self, target_path: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return ensure_dir(self.output_root / f"{safe_slug(target_path.stem)}_{timestamp}")

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)
