from __future__ import annotations

from PyQt5.QtCore import QThread, pyqtSignal

from ..dependency_installer import DependencyInstaller
from ..engine import ReverseEngineeringEngine
from ..models import (
    FrontendSettings,
    LiveProcessSettings,
    LlmAssistSettings,
    OutputSettings,
    PortingSettings,
    RuntimeTraceSettings,
)


class AnalysisWorker(QThread):
    progress = pyqtSignal(str)
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(
        self,
        target: str,
        output_root: str,
        run_external_tools: bool,
        run_ghidra: bool,
        llm_settings: LlmAssistSettings,
        porting_settings: PortingSettings,
        runtime_trace_settings: RuntimeTraceSettings,
        live_process_settings: LiveProcessSettings,
        frontend_settings: FrontendSettings,
        output_settings: OutputSettings,
    ) -> None:
        super().__init__()
        self.target = target
        self.output_root = output_root
        self.run_external_tools = run_external_tools
        self.run_ghidra = run_ghidra
        self.llm_settings = llm_settings
        self.porting_settings = porting_settings
        self.runtime_trace_settings = runtime_trace_settings
        self.live_process_settings = live_process_settings
        self.frontend_settings = frontend_settings
        self.output_settings = output_settings

    def run(self) -> None:
        try:
            engine = ReverseEngineeringEngine(
                output_root=self.output_root,
                logger=self.progress.emit,
                run_external_tools=self.run_external_tools,
                run_ghidra=self.run_ghidra,
                llm_settings=self.llm_settings,
                porting_settings=self.porting_settings,
                runtime_trace_settings=self.runtime_trace_settings,
                live_process_settings=self.live_process_settings,
                frontend_settings=self.frontend_settings,
                output_settings=self.output_settings,
            )
            report = engine.analyze(self.target)
            self.completed.emit(report.to_dict())
        except Exception as exc:  # pragma: no cover - GUI surface
            self.failed.emit(str(exc))


class ToolInstallWorker(QThread):
    progress = pyqtSignal(str)
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, tools_root: str) -> None:
        super().__init__()
        self.tools_root = tools_root

    def run(self) -> None:
        try:
            installer = DependencyInstaller(tools_root=self.tools_root, logger=self.progress.emit)
            result = installer.install_all()
            self.completed.emit(result)
        except Exception as exc:  # pragma: no cover - GUI surface
            self.failed.emit(str(exc))
