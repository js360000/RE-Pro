from __future__ import annotations

import json
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, QTimer, Qt, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .engine import ReverseEngineeringEngine
from .dependency_installer import DependencyInstaller
from .index_workflows import build_entity_workflow
from .live_process import resolve_live_process
from .mcp_launch import build_mcp_launch_details
from .mcp_launch import start_mcp_server_process
from .mcp_launch import stop_mcp_server_process
from .models import LiveProcessSettings
from .models import LlmAssistSettings
from .models import FrontendSettings
from .models import PortingSettings
from .models import RuntimeTraceSettings
from .profiles import analysis_settings_from_profile
from .profiles import build_analysis_profile
from .profiles import list_profiles
from .profiles import load_profile
from .profiles import save_profile
from .workspace_browser import build_browser_workspace
from .workspace_browser import patch_browser_node_bytes
from .workspace_browser import read_browser_node
from .workspace_browser import write_browser_node


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


class BackgroundLogWindow(QDialog):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(920, 620)
        self._log_path: Path | None = None
        self._status_path: Path | None = None

        layout = QVBoxLayout(self)
        self.path_label = QLabel("No background job selected.")
        self.path_label.setWordWrap(True)
        layout.addWidget(self.path_label)

        self.status_text = QPlainTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(160)
        layout.addWidget(self.status_text)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        button_row = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.open_log_button = QPushButton("Open Log")
        self.open_status_button = QPushButton("Open Status")
        button_row.addWidget(self.refresh_button)
        button_row.addWidget(self.open_log_button)
        button_row.addWidget(self.open_status_button)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.refresh_button.clicked.connect(self.refresh_contents)
        self.open_log_button.clicked.connect(self._open_log_path)
        self.open_status_button.clicked.connect(self._open_status_path)

        self.timer = QTimer(self)
        self.timer.setInterval(1500)
        self.timer.timeout.connect(self.refresh_contents)
        self.timer.start()

    def set_job_paths(self, log_path: str | None, status_path: str | None) -> None:
        self._log_path = Path(log_path) if log_path else None
        self._status_path = Path(status_path) if status_path else None
        self.open_log_button.setEnabled(bool(self._log_path))
        self.open_status_button.setEnabled(bool(self._status_path))
        self.path_label.setText(
            "\n".join(
                [
                    f"Log: {self._log_path}" if self._log_path else "Log: unavailable",
                    f"Status: {self._status_path}" if self._status_path else "Status: unavailable",
                    "Showing the tail of the live log so large background jobs do not freeze the UI.",
                ]
            )
        )
        self.refresh_contents()

    def refresh_contents(self) -> None:
        self.status_text.setPlainText(self._format_status_text())
        self.log_text.setPlainText(self._tail_text(self._log_path))
        self.log_text.moveCursor(self.log_text.textCursor().End)

    def _format_status_text(self) -> str:
        if self._status_path is None:
            return "No status file configured."
        payload = self._read_json(self._status_path)
        if payload is None:
            return f"Waiting for status file:\n{self._status_path}"
        lines = [
            f"State: {payload.get('state', 'unknown')}",
            f"Target: {payload.get('target', '')}",
            f"Started: {payload.get('started_at', '')}",
            f"Finished: {payload.get('finished_at', '')}",
        ]
        if payload.get("exit_code") is not None:
            lines.append(f"Exit Code: {payload.get('exit_code')}")
        if payload.get("analysis_timed_out"):
            lines.append("Analysis Timed Out: yes")
        warning_counts = payload.get("warning_counts") or {}
        if isinstance(warning_counts, dict) and warning_counts:
            summary = ", ".join(f"{key}={value}" for key, value in sorted(warning_counts.items()))
            lines.append(f"Warnings: {summary}")
        message = str(payload.get("message", "")).strip()
        if message:
            lines.extend(["", message])
        return "\n".join(lines)

    @staticmethod
    def _tail_text(path: Path | None, *, max_bytes: int = 240_000) -> str:
        if path is None:
            return "No log file configured."
        if not path.exists():
            return f"Waiting for log file:\n{path}"
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                if size > max_bytes:
                    handle.seek(-max_bytes, 2)
                    prefix = f"... showing last {max_bytes} bytes of {size} ...\n"
                else:
                    prefix = ""
                text = handle.read().decode("utf-8", errors="ignore")
        except OSError as exc:
            return f"Could not read log file:\n{path}\n\n{exc}"
        return prefix + text

    @staticmethod
    def _read_json(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _open_log_path(self) -> None:
        if self._log_path is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._log_path)))

    def _open_status_path(self) -> None:
        if self._status_path is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._status_path)))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("RE-Pro")
        self.resize(1280, 840)
        self.worker: AnalysisWorker | None = None
        self.tool_worker: ToolInstallWorker | None = None
        self._history: list[dict] = []
        self._profile_entries: list[dict] = []
        self._current_profile: dict | None = None
        self._current_report: dict | None = None
        self._current_index_payload: dict | None = None
        self._current_index_workflow: dict | None = None
        self._ghidra_job_paths: dict[str, str] = {}
        self._pe_job_paths: dict[str, str] = {}
        self._llm_job_paths: dict[str, str] = {}
        self._mcp_details: dict | None = None
        self._browser_manifest: dict | None = None
        self._current_browser_node_id: str = ""
        self._function_evidence_entities: list[dict] = []
        self._job_center_rows: list[dict] = []
        self.ghidra_log_window: BackgroundLogWindow | None = None
        self.pe_log_window: BackgroundLogWindow | None = None
        self.llm_refresh_timer = QTimer(self)
        self.llm_refresh_timer.setInterval(1500)
        self.llm_refresh_timer.timeout.connect(self._refresh_llm_live_view)
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        root_layout = QVBoxLayout(central)

        controls = QGroupBox("Analysis Target")
        controls_layout = QFormLayout(controls)

        target_row = QHBoxLayout()
        self.target_input = QLineEdit()
        browse_file = QPushButton("Browse File")
        browse_dir = QPushButton("Browse Dir")
        target_row.addWidget(self.target_input)
        target_row.addWidget(browse_file)
        target_row.addWidget(browse_dir)

        output_row = QHBoxLayout()
        self.output_input = QLineEdit(str((Path.cwd() / "analysis_output").resolve()))
        browse_output = QPushButton("Output")
        output_row.addWidget(self.output_input)
        output_row.addWidget(browse_output)

        profile_row = QHBoxLayout()
        self.profile_name_input = QLineEdit()
        self.profile_name_input.setPlaceholderText("Optional profile name")
        self.save_profile_button = QPushButton("Save Profile")
        self.load_profile_button = QPushButton("Load Selected Profile")
        self.refresh_profiles_button = QPushButton("Refresh Profiles")
        profile_row.addWidget(self.profile_name_input)
        profile_row.addWidget(self.save_profile_button)
        profile_row.addWidget(self.load_profile_button)
        profile_row.addWidget(self.refresh_profiles_button)

        action_row = QHBoxLayout()
        self.analyze_button = QPushButton("Run Analysis")
        self.install_tools_button = QPushButton("Install Tooling")
        self.external_tools_checkbox = QCheckBox("Run RE Tools")
        self.ghidra_checkbox = QCheckBox("Run Ghidra")
        self.frontend_beautify_checkbox = QCheckBox("Beautify JS/CSS")
        self.open_ghidra_log_button = QPushButton("Ghidra Log")
        self.open_pe_log_button = QPushButton("PE Log")
        self.open_ghidra_log_button.setEnabled(False)
        self.open_pe_log_button.setEnabled(False)
        self.tools_input = QLineEdit(str((Path.cwd() / "tools").resolve()))
        action_row.addWidget(self.analyze_button)
        action_row.addWidget(self.install_tools_button)
        action_row.addWidget(self.external_tools_checkbox)
        action_row.addWidget(self.ghidra_checkbox)
        action_row.addWidget(self.frontend_beautify_checkbox)
        action_row.addWidget(self.open_ghidra_log_button)
        action_row.addWidget(self.open_pe_log_button)
        controls_layout.addRow("Target", target_row)
        controls_layout.addRow("Output Root", output_row)
        controls_layout.addRow("Profiles", profile_row)
        controls_layout.addRow("Tools Root", self.tools_input)

        llm_options = QHBoxLayout()
        self.llm_checkbox = QCheckBox("Run LLM")
        self.llm_auto_checkbox = QCheckBox("Auto-trigger")
        self.llm_background_checkbox = QCheckBox("Background job")
        self.llm_background_checkbox.setChecked(True)
        self.llm_install_checkbox = QCheckBox("Allow installs")
        self.llm_install_checkbox.setChecked(True)
        self.llm_build_checkbox = QCheckBox("Run build checks")
        self.llm_build_checkbox.setChecked(True)
        llm_options.addWidget(self.llm_checkbox)
        llm_options.addWidget(self.llm_auto_checkbox)
        llm_options.addWidget(self.llm_background_checkbox)
        llm_options.addWidget(self.llm_install_checkbox)
        llm_options.addWidget(self.llm_build_checkbox)
        controls_layout.addRow("LLM", llm_options)

        runtime_options = QHBoxLayout()
        self.runtime_trace_checkbox = QCheckBox("Runtime Trace")
        self.runtime_trace_seconds_input = QLineEdit("8")
        self.runtime_trace_seconds_input.setMaximumWidth(60)
        self.runtime_trace_frida_checkbox = QCheckBox("Use Frida")
        self.runtime_trace_frida_checkbox.setChecked(True)
        runtime_options.addWidget(self.runtime_trace_checkbox)
        runtime_options.addWidget(QLabel("Seconds"))
        runtime_options.addWidget(self.runtime_trace_seconds_input)
        runtime_options.addWidget(self.runtime_trace_frida_checkbox)
        runtime_options.addStretch(1)
        controls_layout.addRow("Runtime", runtime_options)

        live_options = QHBoxLayout()
        self.live_process_checkbox = QCheckBox("Live Attach")
        self.live_pid_input = QLineEdit()
        self.live_pid_input.setPlaceholderText("PID")
        self.live_pid_input.setMaximumWidth(90)
        self.live_name_input = QLineEdit()
        self.live_name_input.setPlaceholderText("Process name, e.g. pcsx2-qt.exe")
        self.live_memory_checkbox = QCheckBox("Dump memory")
        self.live_memory_checkbox.setChecked(True)
        self.live_max_total_input = QLineEdit("256")
        self.live_max_total_input.setMaximumWidth(70)
        live_options.addWidget(self.live_process_checkbox)
        live_options.addWidget(QLabel("PID"))
        live_options.addWidget(self.live_pid_input)
        live_options.addWidget(QLabel("Name"))
        live_options.addWidget(self.live_name_input)
        live_options.addWidget(self.live_memory_checkbox)
        live_options.addWidget(QLabel("Max MiB"))
        live_options.addWidget(self.live_max_total_input)
        live_options.addStretch(1)
        controls_layout.addRow("Live Process", live_options)

        porting_options = QHBoxLayout()
        self.porting_enabled_checkbox = QCheckBox("Architecture port")
        self.porting_source_arch_input = QLineEdit()
        self.porting_source_arch_input.setPlaceholderText("auto/x86_64")
        self.porting_source_arch_input.setMaximumWidth(120)
        self.porting_target_arch_combo = QComboBox()
        self.porting_target_arch_combo.setEditable(True)
        self.porting_target_arch_combo.addItems(["", "arm64", "x86_64", "x86", "armv7", "riscv64"])
        self.porting_mode_combo = QComboBox()
        self.porting_mode_combo.addItems(["heuristic", "hybrid", "llm"])
        porting_options.addWidget(self.porting_enabled_checkbox)
        porting_options.addWidget(QLabel("Source"))
        porting_options.addWidget(self.porting_source_arch_input)
        porting_options.addWidget(QLabel("Target"))
        porting_options.addWidget(self.porting_target_arch_combo)
        porting_options.addWidget(QLabel("Mode"))
        porting_options.addWidget(self.porting_mode_combo)
        porting_options.addStretch(1)
        controls_layout.addRow("Porting", porting_options)

        llm_params = QHBoxLayout()
        self.llm_model_input = QLineEdit("gpt-5.4")
        self.llm_model_input.setPlaceholderText("gpt-5.5, gpt-5.4, gpt-5.4-mini, ...")
        self.llm_auth_combo = QComboBox()
        self.llm_auth_combo.addItems(["auto", "api-key", "codex-oauth"])
        self.codex_auth_input = QLineEdit()
        self.codex_auth_input.setPlaceholderText("Optional .codex/auth.json path")
        self.llm_reasoning_combo = QComboBox()
        self.llm_reasoning_combo.addItems(["none", "low", "medium", "high", "xhigh"])
        self.llm_reasoning_combo.setCurrentText("high")
        self.llm_verbosity_combo = QComboBox()
        self.llm_verbosity_combo.addItems(["low", "medium", "high"])
        self.llm_verbosity_combo.setCurrentText("medium")
        self.llm_max_output_input = QLineEdit("128000")
        llm_params.addWidget(QLabel("Model"))
        llm_params.addWidget(self.llm_model_input)
        llm_params.addWidget(QLabel("Auth"))
        llm_params.addWidget(self.llm_auth_combo)
        llm_params.addWidget(QLabel("Reasoning"))
        llm_params.addWidget(self.llm_reasoning_combo)
        llm_params.addWidget(QLabel("Verbosity"))
        llm_params.addWidget(self.llm_verbosity_combo)
        llm_params.addWidget(QLabel("Max Output"))
        llm_params.addWidget(self.llm_max_output_input)
        controls_layout.addRow("LLM Params", llm_params)
        controls_layout.addRow("Codex Auth", self.codex_auth_input)

        self.llm_task_input = QPlainTextEdit()
        self.llm_task_input.setMaximumHeight(90)
        self.llm_task_input.setPlaceholderText(
            "Optional GPT task steering, e.g. reconstruct update flow, map strings to functions, or focus on porting blockers"
        )
        controls_layout.addRow("LLM Task", self.llm_task_input)
        controls_layout.addRow("", action_row)

        root_layout.addWidget(controls)

        splitter = QSplitter(Qt.Vertical)
        self.tabs = QTabWidget()

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.runtime_text = QPlainTextEdit()
        self.runtime_text.setReadOnly(True)
        self.porting_text = QPlainTextEdit()
        self.porting_text.setReadOnly(True)
        self.llm_text = QTextEdit()
        self.llm_text.setReadOnly(True)

        self.frameworks_list = QListWidget()

        self.findings_table = QTableWidget(0, 3)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Title", "Summary"])
        self.findings_table.horizontalHeader().setStretchLastSection(True)

        self.artifacts_list = QListWidget()
        self.artifacts_list.itemDoubleClicked.connect(self._open_item_path)
        self.artifacts_list.currentItemChanged.connect(self._preview_artifact)

        self.preview_label = QLabel("Preview")
        self.preview_label.setWordWrap(True)
        self.artifact_text_preview = QPlainTextEdit()
        self.artifact_text_preview.setReadOnly(True)
        self.artifact_image_preview = QLabel()
        self.artifact_image_preview.setAlignment(Qt.AlignCenter)
        self.artifact_image_preview.setMinimumSize(320, 240)
        image_scroll = QScrollArea()
        image_scroll.setWidgetResizable(True)
        image_scroll.setWidget(self.artifact_image_preview)
        self.artifact_preview_stack = QStackedWidget()
        self.artifact_preview_stack.addWidget(self.artifact_text_preview)
        self.artifact_preview_stack.addWidget(image_scroll)
        preview_panel = QWidget()
        preview_layout = QVBoxLayout(preview_panel)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.addWidget(self.preview_label)
        preview_layout.addWidget(self.artifact_preview_stack)
        artifacts_splitter = QSplitter(Qt.Horizontal)
        artifacts_splitter.addWidget(self.artifacts_list)
        artifacts_splitter.addWidget(preview_panel)
        artifacts_splitter.setSizes([420, 720])
        self.artifacts_tab_widget = artifacts_splitter

        self.sources_tree = QTreeWidget()
        self.sources_tree.setHeaderLabels(["Recovered Source", "Restored Path"])
        self.sources_tree.itemDoubleClicked.connect(self._open_tree_item_path)
        self.sources_tree.currentItemChanged.connect(self._preview_source)
        self.sources_tab_widget = self.sources_tree

        browser_panel = QWidget()
        browser_layout = QVBoxLayout(browser_panel)
        browser_actions = QHBoxLayout()
        self.browser_refresh_button = QPushButton("Refresh Browser")
        self.browser_open_button = QPushButton("Open Node")
        self.browser_save_button = QPushButton("Save Editor")
        self.browser_mode_combo = QComboBox()
        self.browser_mode_combo.addItems(["auto", "text", "json", "hex", "base64"])
        self.browser_offset_input = QLineEdit("0")
        self.browser_offset_input.setMaximumWidth(90)
        self.browser_patch_bytes_input = QLineEdit()
        self.browser_patch_bytes_input.setPlaceholderText("Hex patch bytes, e.g. 90 90")
        self.browser_patch_button = QPushButton("Apply Hex Patch")
        browser_actions.addWidget(self.browser_refresh_button)
        browser_actions.addWidget(self.browser_open_button)
        browser_actions.addWidget(QLabel("View"))
        browser_actions.addWidget(self.browser_mode_combo)
        browser_actions.addWidget(self.browser_save_button)
        browser_actions.addWidget(QLabel("Offset"))
        browser_actions.addWidget(self.browser_offset_input)
        browser_actions.addWidget(self.browser_patch_bytes_input)
        browser_actions.addWidget(self.browser_patch_button)
        browser_actions.addStretch(1)
        self.browser_status_label = QLabel("Run an analysis or load a report to browse editable internals.")
        self.browser_status_label.setWordWrap(True)
        self.browser_tree = QTreeWidget()
        self.browser_tree.setHeaderLabels(["Name", "Mode", "Origin", "Size"])
        self.browser_tree.currentItemChanged.connect(self._preview_browser_node)
        self.browser_tree.itemDoubleClicked.connect(self._open_browser_item_path)
        self.browser_editor = QPlainTextEdit()
        browser_splitter = QSplitter(Qt.Horizontal)
        browser_splitter.addWidget(self.browser_tree)
        browser_splitter.addWidget(self.browser_editor)
        browser_splitter.setSizes([420, 760])
        browser_layout.addLayout(browser_actions)
        browser_layout.addWidget(self.browser_status_label)
        browser_layout.addWidget(browser_splitter)
        self.browser_tab_widget = browser_panel

        index_panel = QWidget()
        index_layout = QVBoxLayout(index_panel)
        index_search_row = QHBoxLayout()
        self.index_search_input = QLineEdit()
        self.index_search_input.setPlaceholderText("Search analysis index entities, e.g. imgui, d3d11, success, function")
        self.index_kind_combo = QComboBox()
        self.index_kind_combo.addItems(["All", "framework", "function", "string", "artifact", "resource", "import", "section", "tool", "finding"])
        index_search_row.addWidget(QLabel("Search"))
        index_search_row.addWidget(self.index_search_input)
        index_search_row.addWidget(QLabel("Kind"))
        index_search_row.addWidget(self.index_kind_combo)
        self.index_summary_text = QPlainTextEdit()
        self.index_summary_text.setReadOnly(True)
        self.index_summary_text.setMaximumHeight(100)
        self.index_table = QTableWidget(0, 4)
        self.index_table.setHorizontalHeaderLabels(["Kind", "Label", "Key", "Attributes"])
        self.index_table.horizontalHeader().setStretchLastSection(True)
        self.index_table.itemSelectionChanged.connect(self._show_selected_index_entity)
        self.index_detail_text = QPlainTextEdit()
        self.index_detail_text.setReadOnly(True)
        self.index_workflow_summary = QPlainTextEdit()
        self.index_workflow_summary.setReadOnly(True)
        self.index_workflow_summary.setMaximumHeight(110)
        self.index_related_list = QListWidget()
        self.index_related_list.itemDoubleClicked.connect(self._open_index_related_item)
        workflow_actions = QHBoxLayout()
        self.index_open_button = QPushButton("Open Selected")
        self.index_preview_button = QPushButton("Preview Selected")
        self.index_artifacts_button = QPushButton("Show Artifacts")
        self.index_sources_button = QPushButton("Show Sources")
        self.index_porting_button = QPushButton("Open Porting")
        self.index_recompile_button = QPushButton("Open Recompile")
        workflow_actions.addWidget(self.index_open_button)
        workflow_actions.addWidget(self.index_preview_button)
        workflow_actions.addWidget(self.index_artifacts_button)
        workflow_actions.addWidget(self.index_sources_button)
        workflow_actions.addWidget(self.index_porting_button)
        workflow_actions.addWidget(self.index_recompile_button)
        workflow_panel = QWidget()
        workflow_layout = QVBoxLayout(workflow_panel)
        workflow_layout.setContentsMargins(0, 0, 0, 0)
        workflow_layout.addWidget(self.index_workflow_summary)
        workflow_layout.addWidget(self.index_related_list)
        workflow_layout.addLayout(workflow_actions)
        index_detail_splitter = QSplitter(Qt.Horizontal)
        index_detail_splitter.addWidget(self.index_detail_text)
        index_detail_splitter.addWidget(workflow_panel)
        index_detail_splitter.setSizes([500, 360])
        index_splitter = QSplitter(Qt.Vertical)
        index_splitter.addWidget(self.index_table)
        index_splitter.addWidget(index_detail_splitter)
        index_splitter.setSizes([360, 260])
        index_layout.addLayout(index_search_row)
        index_layout.addWidget(self.index_summary_text)
        index_layout.addWidget(index_splitter)

        function_panel = QWidget()
        function_layout = QVBoxLayout(function_panel)
        function_filter_row = QHBoxLayout()
        self.function_search_input = QLineEdit()
        self.function_search_input.setPlaceholderText("Search functions, classes, addresses, tool provenance, or confidence")
        self.function_confidence_combo = QComboBox()
        self.function_confidence_combo.addItems(["All", "high", "medium", "low"])
        function_filter_row.addWidget(QLabel("Search"))
        function_filter_row.addWidget(self.function_search_input)
        function_filter_row.addWidget(QLabel("Confidence"))
        function_filter_row.addWidget(self.function_confidence_combo)
        self.function_evidence_table = QTableWidget(0, 6)
        self.function_evidence_table.setHorizontalHeaderLabels(["Label", "Address", "Class", "Tool", "Confidence", "Provenance"])
        self.function_evidence_table.horizontalHeader().setStretchLastSection(True)
        self.function_evidence_table.itemSelectionChanged.connect(self._show_selected_function_evidence)
        self.function_evidence_detail = QPlainTextEdit()
        self.function_evidence_detail.setReadOnly(True)
        function_splitter = QSplitter(Qt.Vertical)
        function_splitter.addWidget(self.function_evidence_table)
        function_splitter.addWidget(self.function_evidence_detail)
        function_splitter.setSizes([360, 260])
        function_layout.addLayout(function_filter_row)
        function_layout.addWidget(function_splitter)

        quality_panel = QWidget()
        quality_layout = QVBoxLayout(quality_panel)
        self.quality_text = QTextEdit()
        self.quality_text.setReadOnly(True)
        quality_layout.addWidget(self.quality_text)

        jobs_panel = QWidget()
        jobs_layout = QVBoxLayout(jobs_panel)
        self.job_center_table = QTableWidget(0, 5)
        self.job_center_table.setHorizontalHeaderLabels(["Type", "State", "Priority", "Label", "Path"])
        self.job_center_table.horizontalHeader().setStretchLastSection(True)
        self.job_center_table.itemSelectionChanged.connect(self._show_selected_job_center_item)
        self.job_center_detail = QPlainTextEdit()
        self.job_center_detail.setReadOnly(True)
        job_actions = QHBoxLayout()
        self.job_center_open_button = QPushButton("Open Selected")
        self.job_center_preview_button = QPushButton("Preview Selected")
        job_actions.addWidget(self.job_center_open_button)
        job_actions.addWidget(self.job_center_preview_button)
        job_actions.addStretch(1)
        jobs_layout.addWidget(self.job_center_table)
        jobs_layout.addWidget(self.job_center_detail)
        jobs_layout.addLayout(job_actions)

        self.json_text = QPlainTextEdit()
        self.json_text.setReadOnly(True)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)

        self.history_list = QListWidget()
        self.history_list.currentRowChanged.connect(self._show_history_report)

        profiles_panel = QWidget()
        profiles_layout = QVBoxLayout(profiles_panel)
        profiles_search_row = QHBoxLayout()
        self.profile_search_input = QLineEdit()
        self.profile_search_input.setPlaceholderText("Search saved analysis/recompile profiles")
        self.profile_kind_combo = QComboBox()
        self.profile_kind_combo.addItems(["All", "analysis", "package_action"])
        profiles_search_row.addWidget(QLabel("Search"))
        profiles_search_row.addWidget(self.profile_search_input)
        profiles_search_row.addWidget(QLabel("Kind"))
        profiles_search_row.addWidget(self.profile_kind_combo)
        self.profiles_list = QListWidget()
        self.profiles_list.currentItemChanged.connect(self._show_selected_profile)
        self.profiles_list.itemDoubleClicked.connect(self._load_selected_profile)
        self.profile_detail_text = QPlainTextEdit()
        self.profile_detail_text.setReadOnly(True)
        profile_button_row = QHBoxLayout()
        self.profile_open_output_button = QPushButton("Open Output")
        self.profile_load_report_button = QPushButton("Load Report")
        profile_button_row.addWidget(self.profile_open_output_button)
        profile_button_row.addWidget(self.profile_load_report_button)
        profiles_layout.addLayout(profiles_search_row)
        profiles_layout.addWidget(self.profiles_list)
        profiles_layout.addWidget(self.profile_detail_text)
        profiles_layout.addLayout(profile_button_row)

        mcp_panel = QWidget()
        mcp_layout = QVBoxLayout(mcp_panel)
        mcp_form = QFormLayout()
        mcp_transport_row = QHBoxLayout()
        self.mcp_transport_combo = QComboBox()
        self.mcp_transport_combo.addItems(["streamable-http", "sse", "stdio"])
        self.mcp_host_input = QLineEdit("127.0.0.1")
        self.mcp_port_input = QLineEdit("8000")
        self.mcp_port_input.setMaximumWidth(90)
        mcp_transport_row.addWidget(QLabel("Transport"))
        mcp_transport_row.addWidget(self.mcp_transport_combo)
        mcp_transport_row.addWidget(QLabel("Host"))
        mcp_transport_row.addWidget(self.mcp_host_input)
        mcp_transport_row.addWidget(QLabel("Port"))
        mcp_transport_row.addWidget(self.mcp_port_input)
        mcp_transport_row.addStretch(1)
        mcp_form.addRow("Connection", mcp_transport_row)
        self.mcp_status_label = QLabel("MCP server is not running.")
        self.mcp_status_label.setWordWrap(True)
        mcp_form.addRow("Status", self.mcp_status_label)
        mcp_layout.addLayout(mcp_form)
        mcp_button_row = QHBoxLayout()
        self.mcp_start_button = QPushButton("Start MCP Server")
        self.mcp_stop_button = QPushButton("Stop MCP Server")
        self.mcp_refresh_button = QPushButton("Refresh JSON")
        self.mcp_open_log_button = QPushButton("Open MCP Log")
        self.mcp_stop_button.setEnabled(False)
        self.mcp_open_log_button.setEnabled(False)
        mcp_button_row.addWidget(self.mcp_start_button)
        mcp_button_row.addWidget(self.mcp_stop_button)
        mcp_button_row.addWidget(self.mcp_refresh_button)
        mcp_button_row.addWidget(self.mcp_open_log_button)
        mcp_button_row.addStretch(1)
        mcp_layout.addLayout(mcp_button_row)
        self.mcp_config_text = QPlainTextEdit()
        self.mcp_config_text.setReadOnly(True)
        mcp_layout.addWidget(self.mcp_config_text)

        self.tabs.addTab(self.summary_text, "Summary")
        self.tabs.addTab(self.runtime_text, "Runtime")
        self.tabs.addTab(self.porting_text, "Porting")
        self.tabs.addTab(self.llm_text, "LLM")
        self.tabs.addTab(self.frameworks_list, "Frameworks")
        self.tabs.addTab(self.findings_table, "Findings")
        self.tabs.addTab(artifacts_splitter, "Artifacts")
        self.tabs.addTab(self.sources_tree, "Recovered Sources")
        self.tabs.addTab(browser_panel, "File Browser")
        self.tabs.addTab(index_panel, "Analysis Index")
        self.tabs.addTab(function_panel, "Function Evidence")
        self.tabs.addTab(quality_panel, "Quality")
        self.tabs.addTab(jobs_panel, "Job Center")
        self.tabs.addTab(self.json_text, "JSON")
        self.tabs.addTab(profiles_panel, "Profiles")
        self.tabs.addTab(self.history_list, "History")
        self.tabs.addTab(mcp_panel, "MCP Server")
        splitter.addWidget(self.tabs)
        splitter.addWidget(self.log_text)
        splitter.setSizes([650, 180])

        root_layout.addWidget(splitter)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Ready")

        browse_file.clicked.connect(self._browse_file)
        browse_dir.clicked.connect(self._browse_dir)
        browse_output.clicked.connect(self._browse_output)
        self.analyze_button.clicked.connect(self._start_analysis)
        self.install_tools_button.clicked.connect(self._install_tooling)
        self.open_ghidra_log_button.clicked.connect(self._open_ghidra_log_window)
        self.open_pe_log_button.clicked.connect(self._open_pe_log_window)
        self.save_profile_button.clicked.connect(self._save_profile_from_form)
        self.load_profile_button.clicked.connect(self._load_selected_profile)
        self.refresh_profiles_button.clicked.connect(self._refresh_profiles)
        self.profile_search_input.textChanged.connect(self._refresh_profiles)
        self.profile_kind_combo.currentTextChanged.connect(self._refresh_profiles)
        self.profile_open_output_button.clicked.connect(self._open_selected_profile_output)
        self.profile_load_report_button.clicked.connect(self._load_selected_profile_report)
        self.index_search_input.textChanged.connect(self._refresh_index_table)
        self.index_kind_combo.currentTextChanged.connect(self._refresh_index_table)
        self.index_open_button.clicked.connect(self._open_selected_index_related_item)
        self.index_preview_button.clicked.connect(self._preview_selected_index_related_item)
        self.index_artifacts_button.clicked.connect(self._show_index_workflow_artifacts)
        self.index_sources_button.clicked.connect(self._show_index_workflow_sources)
        self.index_porting_button.clicked.connect(self._open_index_porting_target)
        self.index_recompile_button.clicked.connect(self._open_index_recompile_target)
        self.function_search_input.textChanged.connect(self._refresh_function_evidence_table)
        self.function_confidence_combo.currentTextChanged.connect(self._refresh_function_evidence_table)
        self.job_center_open_button.clicked.connect(self._open_selected_job_center_item)
        self.job_center_preview_button.clicked.connect(self._preview_selected_job_center_item)
        self.browser_refresh_button.clicked.connect(self._refresh_browser)
        self.browser_open_button.clicked.connect(self._open_current_browser_node_path)
        self.browser_save_button.clicked.connect(self._save_browser_node)
        self.browser_patch_button.clicked.connect(self._patch_browser_node)
        self.browser_mode_combo.currentTextChanged.connect(self._reload_current_browser_node)
        self.mcp_start_button.clicked.connect(self._start_mcp_server)
        self.mcp_stop_button.clicked.connect(self._stop_mcp_server)
        self.mcp_refresh_button.clicked.connect(self._refresh_mcp_config)
        self.mcp_open_log_button.clicked.connect(self._open_mcp_log)
        self.mcp_transport_combo.currentTextChanged.connect(self._refresh_mcp_config)
        self.mcp_host_input.textChanged.connect(self._refresh_mcp_config)
        self.mcp_port_input.textChanged.connect(self._refresh_mcp_config)
        self.output_input.textChanged.connect(self._refresh_mcp_config)
        self.tools_input.textChanged.connect(self._refresh_mcp_config)
        self._refresh_profiles()
        self._refresh_mcp_config()

    def _mcp_options(self) -> dict:
        output_root = self.output_input.text().strip() or str((Path.cwd() / "analysis_output").resolve())
        tools_root = self.tools_input.text().strip() or str((Path.cwd() / "tools").resolve())
        return {
            "workspace_root": Path.cwd(),
            "output_root": Path(output_root),
            "tools_root": Path(tools_root),
            "transport": self.mcp_transport_combo.currentText().strip() or "streamable-http",
            "host": self.mcp_host_input.text().strip() or "127.0.0.1",
            "port": self._parse_int(self.mcp_port_input.text().strip(), default=8000),
            "plugin_dirs": [],
        }

    def _refresh_mcp_config(self) -> None:
        try:
            details = build_mcp_launch_details(**self._mcp_options())
        except Exception as exc:
            self.mcp_config_text.setPlainText(str(exc))
            return
        if self._mcp_details and self._mcp_details.get("pid"):
            details.update(
                {
                    "pid": self._mcp_details.get("pid"),
                    "log_path": self._mcp_details.get("log_path"),
                    "client_config_path": self._mcp_details.get("client_config_path"),
                    "state": self._mcp_details.get("state", "running"),
                }
            )
        self.mcp_config_text.setPlainText(json.dumps(details, indent=2))

    def _start_mcp_server(self) -> None:
        if self._mcp_details and self._mcp_details.get("pid"):
            self.statusBar().showMessage("MCP server is already running.")
            return
        try:
            self._mcp_details = start_mcp_server_process(**self._mcp_options())
        except Exception as exc:
            QMessageBox.critical(self, "MCP server failed", str(exc))
            return
        self.mcp_status_label.setText(
            f"Running pid={self._mcp_details.get('pid')} "
            f"url={self._mcp_details.get('url', 'stdio')} "
            f"log={self._mcp_details.get('log_path', '')}"
        )
        self.mcp_start_button.setEnabled(False)
        self.mcp_stop_button.setEnabled(True)
        self.mcp_open_log_button.setEnabled(True)
        self._refresh_mcp_config()
        self.statusBar().showMessage("MCP server started.")

    def _stop_mcp_server(self) -> None:
        pid = int((self._mcp_details or {}).get("pid") or 0)
        if not pid:
            return
        result = stop_mcp_server_process(pid)
        if not result.get("ok"):
            QMessageBox.warning(self, "MCP server stop failed", json.dumps(result, indent=2))
            return
        self._mcp_details = None
        self.mcp_status_label.setText("MCP server is not running.")
        self.mcp_start_button.setEnabled(True)
        self.mcp_stop_button.setEnabled(False)
        self.mcp_open_log_button.setEnabled(False)
        self._refresh_mcp_config()
        self.statusBar().showMessage("MCP server stopped.")

    def _open_mcp_log(self) -> None:
        log_path = str((self._mcp_details or {}).get("log_path", "")).strip()
        if log_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(log_path))

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select executable or file")
        if path:
            self.target_input.setText(path)

    def _browse_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select application directory")
        if path:
            self.target_input.setText(path)

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select output directory")
        if path:
            self.output_input.setText(path)

    def _start_analysis(self) -> None:
        target = self.target_input.text().strip()
        output_root = self.output_input.text().strip()
        if not target and self.live_process_checkbox.isChecked():
            try:
                process = resolve_live_process(
                    pid=max(0, self._parse_int(self.live_pid_input.text().strip(), default=0)),
                    process_name=self.live_name_input.text().strip(),
                )
                target = str(process.get("executable_path") or Path.cwd())
                self.target_input.setText(target)
            except Exception as exc:
                QMessageBox.warning(self, "Missing live process", str(exc))
                return
        if not target:
            QMessageBox.warning(self, "Missing target", "Select a file or directory to analyze.")
            return

        self.log_text.clear()
        self.summary_text.clear()
        self.findings_table.setRowCount(0)
        self.artifacts_list.clear()
        self.artifact_text_preview.clear()
        self.artifact_image_preview.clear()
        self.preview_label.setText("Preview")
        self.frameworks_list.clear()
        self.sources_tree.clear()
        self.browser_tree.clear()
        self.browser_editor.clear()
        self.browser_status_label.setText("Analysis running; browser will populate when the report is ready.")
        self._browser_manifest = None
        self._current_browser_node_id = ""
        self.json_text.clear()
        self.runtime_text.clear()
        self.porting_text.clear()
        self.llm_text.clear()
        self.index_summary_text.clear()
        self.index_table.setRowCount(0)
        self.index_detail_text.clear()
        self.index_workflow_summary.clear()
        self.index_related_list.clear()
        self._current_index_payload = None
        self._current_index_workflow = None
        self._clear_background_job_paths()
        self.analyze_button.setEnabled(False)
        self.statusBar().showMessage("Analyzing...")

        run_ghidra = self.ghidra_checkbox.isChecked()
        self.worker = AnalysisWorker(
            target=target,
            output_root=output_root,
            run_external_tools=self.external_tools_checkbox.isChecked() or run_ghidra,
            run_ghidra=run_ghidra,
            llm_settings=self._current_llm_settings(),
            porting_settings=self._current_porting_settings(),
            runtime_trace_settings=self._current_runtime_trace_settings(),
            live_process_settings=self._current_live_process_settings(),
            frontend_settings=self._current_frontend_settings(),
        )
        self.worker.progress.connect(self._append_log)
        self.worker.completed.connect(self._handle_report)
        self.worker.failed.connect(self._handle_error)
        self.worker.start()

    def _install_tooling(self) -> None:
        self.log_text.clear()
        self.install_tools_button.setEnabled(False)
        self.analyze_button.setEnabled(False)
        self.statusBar().showMessage("Installing tooling...")
        self.tool_worker = ToolInstallWorker(self.tools_input.text().strip())
        self.tool_worker.progress.connect(self._append_log)
        self.tool_worker.completed.connect(self._handle_tool_install_complete)
        self.tool_worker.failed.connect(self._handle_tool_install_failed)
        self.tool_worker.start()

    def _append_log(self, message: str) -> None:
        self.log_text.appendPlainText(message)

    def _handle_report(self, report: dict) -> None:
        self.analyze_button.setEnabled(True)
        self.statusBar().showMessage(f"Analysis complete: {report.get('output_dir', '')}")
        self._current_report = report
        self._history.insert(0, report)
        self.history_list.insertItem(0, f"{Path(report.get('target', '')).name} -> {report.get('output_dir', '')}")
        profile_path = self._save_analysis_profile(report=report)
        if profile_path is not None:
            self.statusBar().showMessage(f"Analysis complete: {report.get('output_dir', '')} | Profile: {profile_path}")
        self._display_report(report)
        self._auto_open_active_background_logs()
        self._refresh_profiles()

    def _handle_error(self, error: str) -> None:
        self.analyze_button.setEnabled(True)
        self.install_tools_button.setEnabled(True)
        self.statusBar().showMessage("Analysis failed")
        QMessageBox.critical(self, "Analysis failed", error)

    def _handle_tool_install_complete(self, result: dict) -> None:
        self.install_tools_button.setEnabled(True)
        self.analyze_button.setEnabled(True)
        self.statusBar().showMessage(f"Tooling installed: {result.get('tools_root', '')}")
        QMessageBox.information(self, "Tooling installed", f"Installed tools into {result.get('tools_root', '')}")

    def _handle_tool_install_failed(self, error: str) -> None:
        self.install_tools_button.setEnabled(True)
        self.analyze_button.setEnabled(True)
        self.statusBar().showMessage("Tooling install failed")
        QMessageBox.critical(self, "Tooling install failed", error)

    def _populate_summary(self, report: dict) -> None:
        frameworks = ", ".join(report.get("frameworks") or []) or "None"
        notes = "\n".join(f"- {note}" for note in report.get("notes") or []) or "- None"
        findings_count = len(report.get("findings") or [])
        artifacts_count = len(report.get("artifacts") or [])
        recovered_count = len(report.get("recovered_sources") or [])
        text = (
            f"Target: {report.get('target')}\n"
            f"Type: {report.get('target_type')}\n"
            f"Output: {report.get('output_dir')}\n"
            f"Frameworks: {frameworks}\n"
            f"Findings: {findings_count}\n"
            f"Artifacts: {artifacts_count}\n"
            f"Recovered Sources: {recovered_count}\n\n"
            f"Notes:\n{notes}"
        )
        self.summary_text.setPlainText(text)

    def _populate_frameworks(self, report: dict) -> None:
        self.frameworks_list.clear()
        for framework in report.get("frameworks") or []:
            self.frameworks_list.addItem(framework)

    def _populate_runtime(self, report: dict) -> None:
        parts: list[str] = []
        observation = self._load_artifact_json(report, "Runtime observation manifest")
        if observation:
            parts.extend(["Runtime Observation", "", json.dumps(observation, indent=2)])
        frida_status = self._load_artifact_json(report, "Frida helper status")
        if frida_status:
            if parts:
                parts.extend(["", ""])
            parts.extend(["Frida Helper Status", "", json.dumps(frida_status, indent=2)])
        frida_events = self._load_artifact_json(report, "Frida runtime hook events")
        if frida_events:
            if parts:
                parts.extend(["", ""])
            parts.extend(["Frida Events", "", json.dumps(frida_events, indent=2)])
        frida_stderr = self._load_artifact_text(report, "Frida helper stderr")
        if frida_stderr:
            if parts:
                parts.extend(["", ""])
            parts.extend(["Frida Helper Stderr", "", frida_stderr])
        live_manifest = self._load_artifact_json(report, "Live process attach manifest")
        if live_manifest:
            if parts:
                parts.extend(["", ""])
            parts.extend(["Live Process Attach", "", json.dumps(live_manifest, indent=2)])
        self.runtime_text.setPlainText("\n".join(parts))

    def _populate_porting(self, report: dict) -> None:
        self.porting_text.setPlainText(self._load_artifact_text(report, "Porting guidance"))

    def _populate_llm(self, report: dict) -> None:
        parts: list[str] = []
        summary = self._load_artifact_text(report, "LLM reconstruction summary")
        status = self._load_artifact_text(report, "LLM reconstruction status")
        log_text = self._load_artifact_text(report, "LLM reconstruction log")
        if summary:
            parts.extend(["## LLM Reconstruction Output", "", summary.strip()])
        if status:
            parts.extend(["", "## LLM Status", "", "```json", status.strip(), "```"])
        if log_text:
            parts.extend(["", "## LLM Log", "", "```text", log_text.strip(), "```"])
        self._set_markdown_text(self.llm_text, "\n".join(parts).strip())

    def _refresh_llm_live_view(self) -> None:
        if not self._llm_job_paths:
            self.llm_refresh_timer.stop()
            return
        self._set_markdown_text(self.llm_text, self._build_llm_live_markdown(self._llm_job_paths))
        if not self._is_background_job_active(self._llm_job_paths):
            self.llm_refresh_timer.stop()

    def _build_llm_live_markdown(self, job_paths: dict[str, str]) -> str:
        status_path = self._path_or_none(job_paths.get("status"))
        status_payload = self._read_json_file(status_path)
        llm_dir = self._path_or_none(job_paths.get("llm_dir"))
        if llm_dir is None and status_payload:
            llm_dir = self._path_or_none(str(status_payload.get("llm_dir", "")))

        log_path = self._path_or_none(job_paths.get("log"))
        summary_path = self._path_or_none(job_paths.get("summary"))
        if llm_dir is not None:
            log_path = log_path or llm_dir / "llm.log"
            summary_path = summary_path or llm_dir / "assistant_summary.md"
            transcript_path = llm_dir / "codex_cli_transcript.log"
            writes_path = llm_dir / "written_files.json"
            validation_path = llm_dir / "validation_results.json"
        else:
            transcript_path = self._path_or_none(job_paths.get("transcript"))
            writes_path = self._path_or_none(job_paths.get("written_files"))
            validation_path = self._path_or_none(job_paths.get("validation"))

        parts: list[str] = ["## LLM Live Reconstruction", ""]
        if status_payload:
            parts.extend(["### Status", "", "```json", json.dumps(status_payload, indent=2), "```"])
        elif status_path is not None:
            parts.extend(["### Status", "", f"Waiting for status file: `{status_path}`"])
        else:
            parts.extend(["### Status", "", "No LLM status artifact is available for this run."])

        if log_path is not None:
            parts.extend(["", "### Live Log", "", "```text", BackgroundLogWindow._tail_text(log_path).strip(), "```"])
        if transcript_path is not None and transcript_path.exists():
            parts.extend(
                [
                    "",
                    "### Codex Transcript",
                    "",
                    "```text",
                    BackgroundLogWindow._tail_text(transcript_path).strip(),
                    "```",
                ]
            )
        if summary_path is not None and summary_path.exists():
            parts.extend(["", "### Assistant Summary", "", self._read_text_file(summary_path).strip()])
        if writes_path is not None and writes_path.exists():
            parts.extend(["", "### Written Files", "", "```json", self._read_text_file(writes_path).strip(), "```"])
        if validation_path is not None and validation_path.exists():
            parts.extend(["", "### Validation", "", "```json", self._read_text_file(validation_path).strip(), "```"])
        return "\n".join(parts).strip()

    @staticmethod
    def _path_or_none(value: str | Path | None) -> Path | None:
        if value is None:
            return None
        text = str(value).strip()
        return Path(text) if text else None

    @staticmethod
    def _read_json_file(path: Path | None) -> dict | None:
        if path is None or not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _read_text_file(path: Path, *, max_bytes: int = 240_000) -> str:
        return BackgroundLogWindow._tail_text(path, max_bytes=max_bytes)

    @staticmethod
    def _set_markdown_text(widget: QTextEdit, text: str) -> None:
        if hasattr(widget, "setMarkdown"):
            widget.setMarkdown(text)
        else:
            widget.setPlainText(text)

    def _populate_findings(self, report: dict) -> None:
        findings = report.get("findings") or []
        self.findings_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            self.findings_table.setItem(row, 0, QTableWidgetItem(finding.get("severity", "")))
            self.findings_table.setItem(row, 1, QTableWidgetItem(finding.get("title", "")))
            self.findings_table.setItem(row, 2, QTableWidgetItem(finding.get("summary", "")))
        self.findings_table.resizeColumnsToContents()

    def _populate_artifacts(self, report: dict) -> None:
        self.artifacts_list.clear()
        for artifact in report.get("artifacts") or []:
            item = QListWidgetItem(f"[{artifact.get('category')}] {artifact.get('description')} - {artifact.get('path')}")
            item.setData(Qt.UserRole, artifact.get("path"))
            self.artifacts_list.addItem(item)

    def _populate_sources(self, report: dict) -> None:
        self.sources_tree.clear()
        for source in report.get("recovered_sources") or []:
            item = QTreeWidgetItem([source.get("original_path", ""), source.get("restored_path", "")])
            item.setData(0, Qt.UserRole, source.get("restored_path"))
            self.sources_tree.addTopLevelItem(item)

    def _populate_browser(self, report: dict) -> None:
        self.browser_tree.clear()
        self.browser_editor.clear()
        self._browser_manifest = None
        self._current_browser_node_id = ""
        output_dir = str(report.get("output_dir", "")).strip()
        if not output_dir:
            self.browser_status_label.setText("No output directory is available for this report.")
            return
        try:
            manifest = build_browser_workspace(Path(output_dir))
        except Exception as exc:
            self.browser_status_label.setText(f"Browser workspace failed: {exc}")
            return
        self._browser_manifest = manifest
        summary = manifest.get("summary") or {}
        self.browser_status_label.setText(
            f"Browser workspace: {manifest.get('workspace_root')} | "
            f"{summary.get('node_count', 0)} nodes, {summary.get('editable_count', 0)} editable"
        )
        folders: dict[str, QTreeWidgetItem] = {}
        for node in manifest.get("nodes") or []:
            relative_path = str(node.get("relative_path", "")).replace("\\", "/").strip("/")
            if not relative_path:
                continue
            parts = relative_path.split("/")
            parent: QTreeWidgetItem | None = None
            key_parts: list[str] = []
            for part in parts[:-1]:
                key_parts.append(part)
                key = "/".join(key_parts)
                folder_item = folders.get(key)
                if folder_item is None:
                    folder_item = QTreeWidgetItem([part, "folder", "", ""])
                    folder_item.setData(0, Qt.UserRole, "")
                    folders[key] = folder_item
                    if parent is None:
                        self.browser_tree.addTopLevelItem(folder_item)
                    else:
                        parent.addChild(folder_item)
                parent = folder_item
            file_item = QTreeWidgetItem(
                [
                    parts[-1],
                    str(node.get("view_mode", "")),
                    str(node.get("origin", "")),
                    str(node.get("size", "")),
                ]
            )
            file_item.setData(0, Qt.UserRole, node.get("id"))
            file_item.setData(0, Qt.UserRole + 1, node.get("path"))
            if parent is None:
                self.browser_tree.addTopLevelItem(file_item)
            else:
                parent.addChild(file_item)
        for index in range(min(4, self.browser_tree.topLevelItemCount())):
            self.browser_tree.topLevelItem(index).setExpanded(True)
        self.browser_tree.resizeColumnToContents(0)

    def _refresh_browser(self) -> None:
        if self._current_report is None:
            self.browser_status_label.setText("No report is loaded.")
            return
        self._populate_browser(self._current_report)

    def _preview_browser_node(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        del previous
        if current is None:
            return
        node_id = str(current.data(0, Qt.UserRole) or "")
        if not node_id:
            return
        self._current_browser_node_id = node_id
        self._reload_current_browser_node()

    def _reload_current_browser_node(self, *_args) -> None:
        node_id = self._current_browser_node_id
        if not node_id or self._current_report is None:
            return
        mode = self.browser_mode_combo.currentText().strip() or "auto"
        offset = self._parse_browser_offset()
        try:
            result = read_browser_node(
                self._current_report.get("output_dir", ""),
                node_id,
                mode=mode,
                offset=offset,
                max_bytes=256 * 1024,
            )
        except Exception as exc:
            self.browser_editor.setReadOnly(True)
            self.browser_editor.setPlainText(str(exc))
            return
        node = result.get("node") or {}
        self.browser_editor.setReadOnly(not bool(node.get("editable")))
        self.browser_editor.setPlainText(str(result.get("content", "")))
        self.browser_status_label.setText(
            f"{node.get('relative_path')} | mode={result.get('view_mode')} | "
            f"bytes={result.get('returned_bytes')}/{result.get('total_bytes')} | editable={node.get('editable')}"
        )

    def _save_browser_node(self) -> None:
        if not self._current_browser_node_id or self._current_report is None:
            return
        mode = self.browser_mode_combo.currentText().strip() or "auto"
        if mode == "auto":
            node = self._browser_node_by_id(self._current_browser_node_id) or {}
            mode = str(node.get("view_mode") or "text")
            if mode == "image":
                mode = "hex"
        try:
            result = write_browser_node(
                self._current_report.get("output_dir", ""),
                self._current_browser_node_id,
                self.browser_editor.toPlainText(),
                mode=mode,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Browser save failed", str(exc))
            return
        rebuild = result.get("rebuild") or {}
        rebuild_target = rebuild.get("rebuilt_artifact") or rebuild.get("staged_path") or rebuild.get("workspace_root") or ""
        self.browser_status_label.setText(
            f"Saved {result.get('written_bytes')} byte(s); "
            f"rebuild={rebuild.get('kind', 'unknown')} ok={rebuild.get('ok')} {rebuild_target}"
        )
        self._reload_current_browser_node()

    def _patch_browser_node(self) -> None:
        if not self._current_browser_node_id or self._current_report is None:
            return
        hex_bytes = self.browser_patch_bytes_input.text().strip()
        if not hex_bytes:
            return
        try:
            result = patch_browser_node_bytes(
                self._current_report.get("output_dir", ""),
                self._current_browser_node_id,
                self._parse_browser_offset(),
                hex_bytes,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Hex patch failed", str(exc))
            return
        rebuild = result.get("rebuild") or {}
        rebuild_target = rebuild.get("rebuilt_artifact") or rebuild.get("staged_path") or rebuild.get("workspace_root") or ""
        self.browser_status_label.setText(
            f"Patched {result.get('written_bytes')} byte(s) at offset {result.get('offset')}; "
            f"rebuild={rebuild.get('kind', 'unknown')} ok={rebuild.get('ok')} {rebuild_target}"
        )
        self._reload_current_browser_node()

    def _open_browser_item_path(self, item: QTreeWidgetItem) -> None:
        path = str(item.data(0, Qt.UserRole + 1) or "")
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _open_current_browser_node_path(self) -> None:
        node = self._browser_node_by_id(self._current_browser_node_id)
        if node and node.get("path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(node.get("path"))))

    def _browser_node_by_id(self, node_id: str) -> dict | None:
        manifest = self._browser_manifest or {}
        for node in manifest.get("nodes") or []:
            if node.get("id") == node_id:
                return node
        return None

    def _parse_browser_offset(self) -> int:
        text = self.browser_offset_input.text().strip().lower()
        if not text:
            return 0
        try:
            return int(text, 16 if text.startswith("0x") else 10)
        except ValueError:
            return 0

    def _preview_artifact(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        del previous
        if current is None:
            self.artifact_text_preview.clear()
            self.artifact_image_preview.clear()
            self.preview_label.setText("Preview")
            return
        path = current.data(Qt.UserRole)
        self._load_preview(path)

    def _preview_source(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        del previous
        if current is None:
            return
        path = current.data(0, Qt.UserRole)
        self._load_preview(path)

    def _load_preview(self, path: str | None) -> None:
        if not path:
            self.artifact_text_preview.clear()
            self.artifact_image_preview.clear()
            self.preview_label.setText("Preview")
            return
        candidate = Path(path)
        self.preview_label.setText(str(candidate))
        if not candidate.exists():
            self.artifact_preview_stack.setCurrentIndex(0)
            self.artifact_text_preview.setPlainText(f"Path does not exist:\n{path}")
            return
        if candidate.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".ico"}:
            pixmap = QPixmap(str(candidate))
            if not pixmap.isNull():
                self.artifact_preview_stack.setCurrentIndex(1)
                self.artifact_image_preview.setPixmap(pixmap)
                return
        if candidate.is_dir():
            children = sorted(child.name for child in candidate.iterdir())
            preview = "\n".join(children[:200])
            self.artifact_preview_stack.setCurrentIndex(0)
            self.artifact_text_preview.setPlainText(f"Directory: {candidate}\n\n{preview}")
            return
        if candidate.stat().st_size > 1_000_000:
            self.artifact_preview_stack.setCurrentIndex(0)
            self.artifact_text_preview.setPlainText(
                f"Large file preview skipped.\n\nPath: {candidate}\nSize: {candidate.stat().st_size} bytes"
            )
            return
        if candidate.suffix.lower() in {".txt", ".md", ".json", ".js", ".css", ".html", ".xml", ".log", ".map", ".py"}:
            try:
                self.artifact_preview_stack.setCurrentIndex(0)
                self.artifact_text_preview.setPlainText(candidate.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                self.artifact_preview_stack.setCurrentIndex(0)
                self.artifact_text_preview.setPlainText(f"Preview unavailable for non-UTF-8 file:\n{candidate}")
            return
        self.artifact_preview_stack.setCurrentIndex(0)
        self.artifact_text_preview.setPlainText(f"Binary or unsupported preview type:\n{candidate}\nSize: {candidate.stat().st_size} bytes")

    def _show_history_report(self, index: int) -> None:
        if index < 0 or index >= len(self._history):
            return
        report = self._history[index]
        self._display_report(report)
        self._current_report = report

    def _display_report(self, report: dict) -> None:
        self._populate_summary(report)
        self._populate_runtime(report)
        self._populate_frameworks(report)
        self._populate_porting(report)
        self._populate_llm(report)
        self._populate_findings(report)
        self._populate_artifacts(report)
        self._populate_sources(report)
        self._populate_browser(report)
        self._populate_index(report)
        self._populate_function_evidence(report)
        self._populate_quality(report)
        self._populate_job_center(report)
        self._update_background_job_views(report)
        self.json_text.setPlainText(json.dumps(report, indent=2))
        self._current_report = report

    def _clear_background_job_paths(self) -> None:
        self._ghidra_job_paths = {}
        self._pe_job_paths = {}
        self._llm_job_paths = {}
        self.llm_refresh_timer.stop()
        self.open_ghidra_log_button.setEnabled(False)
        self.open_pe_log_button.setEnabled(False)
        if self.ghidra_log_window is not None:
            self.ghidra_log_window.set_job_paths(None, None)
        if self.pe_log_window is not None:
            self.pe_log_window.set_job_paths(None, None)

    def _update_background_job_views(self, report: dict) -> None:
        self._ghidra_job_paths = {
            "log": self._find_artifact_path(report, "Ghidra headless log"),
            "status": self._find_artifact_path(report, "Ghidra headless status"),
        }
        self._pe_job_paths = {
            "log": self._find_artifact_path(report, "PE tools background log"),
            "status": self._find_artifact_path(report, "PE tools background status"),
        }
        llm_status = self._find_artifact_path(report, "LLM reconstruction status")
        llm_log = self._find_artifact_path(report, "LLM reconstruction log")
        llm_summary = self._find_artifact_path(report, "LLM reconstruction summary")
        llm_dir = ""
        status_payload = self._read_json_file(self._path_or_none(llm_status))
        if status_payload:
            llm_dir = str(status_payload.get("llm_dir", "")).strip()
        elif llm_status:
            llm_dir = str(Path(llm_status).parent)
        self._llm_job_paths = {
            "log": llm_log,
            "status": llm_status,
            "summary": llm_summary,
            "llm_dir": llm_dir,
        }
        self.open_ghidra_log_button.setEnabled(bool(self._ghidra_job_paths["log"] or self._ghidra_job_paths["status"]))
        self.open_pe_log_button.setEnabled(bool(self._pe_job_paths["log"] or self._pe_job_paths["status"]))
        if self.ghidra_log_window is not None:
            self.ghidra_log_window.set_job_paths(self._ghidra_job_paths["log"], self._ghidra_job_paths["status"])
        if self.pe_log_window is not None:
            self.pe_log_window.set_job_paths(self._pe_job_paths["log"], self._pe_job_paths["status"])
        if self._llm_job_paths["status"] or self._llm_job_paths["log"] or self._llm_job_paths["summary"]:
            self._refresh_llm_live_view()
            if self._is_background_job_active(self._llm_job_paths):
                self.llm_refresh_timer.start()
            else:
                self.llm_refresh_timer.stop()

    def _auto_open_active_background_logs(self) -> None:
        if self._is_background_job_active(self._ghidra_job_paths):
            self._open_ghidra_log_window()
        if self._is_background_job_active(self._pe_job_paths):
            self._open_pe_log_window()

    def _open_ghidra_log_window(self) -> None:
        if not (self._ghidra_job_paths.get("log") or self._ghidra_job_paths.get("status")):
            return
        if self.ghidra_log_window is None:
            self.ghidra_log_window = BackgroundLogWindow("Ghidra Background Log", self)
        self.ghidra_log_window.set_job_paths(self._ghidra_job_paths.get("log"), self._ghidra_job_paths.get("status"))
        self.ghidra_log_window.show()
        self.ghidra_log_window.raise_()
        self.ghidra_log_window.activateWindow()

    def _open_pe_log_window(self) -> None:
        if not (self._pe_job_paths.get("log") or self._pe_job_paths.get("status")):
            return
        if self.pe_log_window is None:
            self.pe_log_window = BackgroundLogWindow("PE Tools Background Log", self)
        self.pe_log_window.set_job_paths(self._pe_job_paths.get("log"), self._pe_job_paths.get("status"))
        self.pe_log_window.show()
        self.pe_log_window.raise_()
        self.pe_log_window.activateWindow()

    @staticmethod
    def _find_artifact_path(report: dict, description_contains: str) -> str:
        for artifact in report.get("artifacts") or []:
            description = str(artifact.get("description", ""))
            path = str(artifact.get("path", "")).strip()
            if path and description_contains.lower() in description.lower():
                return path
        return ""

    @staticmethod
    def _is_background_job_active(job_paths: dict[str, str]) -> bool:
        status_path = str(job_paths.get("status", "")).strip()
        if not status_path:
            return False
        candidate = Path(status_path)
        if not candidate.exists():
            return True
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return True
        if not isinstance(payload, dict):
            return True
        return str(payload.get("state", "")).strip().lower() in {"queued", "running"}

    def _current_llm_settings(self) -> LlmAssistSettings:
        return LlmAssistSettings(
            enabled=self.llm_checkbox.isChecked(),
            auto=self.llm_auto_checkbox.isChecked(),
            model=self.llm_model_input.text().strip() or "gpt-5.4",
            auth_provider=self.llm_auth_combo.currentText().strip() or "auto",
            codex_auth_path=self.codex_auth_input.text().strip(),
            reasoning_effort=self.llm_reasoning_combo.currentText(),
            verbosity=self.llm_verbosity_combo.currentText(),
            background=self.llm_background_checkbox.isChecked(),
            max_output_tokens=self._parse_int(self.llm_max_output_input.text().strip(), default=128000),
            user_task=self.llm_task_input.toPlainText().strip(),
            allow_dependency_installs=self.llm_install_checkbox.isChecked(),
            run_recompile_checks=self.llm_build_checkbox.isChecked(),
        )

    def _current_runtime_trace_settings(self) -> RuntimeTraceSettings:
        return RuntimeTraceSettings(
            enabled=self.runtime_trace_checkbox.isChecked(),
            duration_seconds=max(1, self._parse_int(self.runtime_trace_seconds_input.text().strip(), default=8)),
            use_frida=self.runtime_trace_frida_checkbox.isChecked(),
        )

    def _current_live_process_settings(self) -> LiveProcessSettings:
        max_total_mb = max(1, self._parse_int(self.live_max_total_input.text().strip(), default=256))
        return LiveProcessSettings(
            enabled=self.live_process_checkbox.isChecked(),
            pid=max(0, self._parse_int(self.live_pid_input.text().strip(), default=0)),
            process_name=self.live_name_input.text().strip(),
            dump_memory=self.live_memory_checkbox.isChecked(),
            max_region_bytes=8 * 1024 * 1024,
            max_total_bytes=max_total_mb * 1024 * 1024,
        )

    def _current_porting_settings(self) -> PortingSettings:
        target_arch = self.porting_target_arch_combo.currentText().strip()
        return PortingSettings(
            enabled=self.porting_enabled_checkbox.isChecked() or bool(target_arch),
            source_arch=self.porting_source_arch_input.text().strip(),
            target_arch=target_arch,
            mode=self.porting_mode_combo.currentText().strip() or "heuristic",
        )

    def _current_frontend_settings(self) -> FrontendSettings:
        return FrontendSettings(
            beautify_bundles=self.frontend_beautify_checkbox.isChecked(),
        )

    def _save_analysis_profile(self, report: dict | None = None) -> str | None:
        target = self.target_input.text().strip()
        output_root = self.output_input.text().strip()
        if not target and self.live_process_checkbox.isChecked():
            target = self.live_name_input.text().strip() or str(self.live_pid_input.text().strip()) or "live-process"
        if not target:
            return None
        profile_name = self.profile_name_input.text().strip() or Path(target).stem
        profile_path = save_profile(
            build_analysis_profile(
                name=profile_name,
                target=target,
                output_root=output_root,
                run_external_tools=self.external_tools_checkbox.isChecked() or self.ghidra_checkbox.isChecked(),
                run_ghidra=self.ghidra_checkbox.isChecked(),
                llm_settings=self._current_llm_settings(),
                porting_settings=self._current_porting_settings(),
                runtime_trace_settings=self._current_runtime_trace_settings(),
                live_process_settings=self._current_live_process_settings(),
                frontend_settings=self._current_frontend_settings(),
                report=report,
                output_dir=str((report or {}).get("output_dir", "")),
            )
        )
        return str(profile_path)

    def _save_profile_from_form(self) -> None:
        profile_path = self._save_analysis_profile(report=self._current_report)
        if profile_path is None:
            QMessageBox.warning(self, "Missing target", "Select a file or directory before saving a profile.")
            return
        self._refresh_profiles()
        self.statusBar().showMessage(f"Profile saved: {profile_path}")

    def _refresh_profiles(self) -> None:
        query = self.profile_search_input.text().strip()
        selected_kind = self.profile_kind_combo.currentText().strip()
        if selected_kind == "All":
            selected_kind = ""
        self._profile_entries = list_profiles(query=query, profile_type=selected_kind.lower())
        self.profiles_list.clear()
        for entry in self._profile_entries:
            label = (
                f"[{entry.get('profile_type')}] {entry.get('name')} "
                f"-> {entry.get('primary_target') or entry.get('secondary_target')}"
            )
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, entry.get("path"))
            self.profiles_list.addItem(item)
        if not self._profile_entries:
            self.profile_detail_text.setPlainText("No saved profiles matched the current filter.")
            self._current_profile = None

    def _show_selected_profile(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        del previous
        if current is None:
            self.profile_detail_text.clear()
            self._current_profile = None
            return
        path = current.data(Qt.UserRole)
        if not path:
            self.profile_detail_text.clear()
            self._current_profile = None
            return
        try:
            profile = load_profile(path)
        except (OSError, ValueError) as exc:
            self.profile_detail_text.setPlainText(str(exc))
            self._current_profile = None
            return
        self._current_profile = profile
        self.profile_detail_text.setPlainText(json.dumps(profile, indent=2))

    def _load_selected_profile(self) -> None:
        profile = self._current_profile
        if profile is None:
            return
        if str(profile.get("profile_type", "")).strip().lower() != "analysis":
            QMessageBox.information(self, "Profile type", "Only analysis profiles can be loaded into the analysis form.")
            return
        settings = analysis_settings_from_profile(profile)
        self.target_input.setText(str(settings.get("target", "")))
        self.output_input.setText(str(settings.get("output_root", "")))
        self.external_tools_checkbox.setChecked(bool(settings.get("run_external_tools", False)))
        self.ghidra_checkbox.setChecked(bool(settings.get("run_ghidra", False)))
        llm_settings = settings.get("llm_settings") or LlmAssistSettings()
        porting_settings = settings.get("porting_settings") or PortingSettings()
        runtime_settings = settings.get("runtime_trace_settings") or RuntimeTraceSettings()
        live_settings = settings.get("live_process_settings") or LiveProcessSettings()
        frontend_settings = settings.get("frontend_settings") or FrontendSettings()
        self.frontend_beautify_checkbox.setChecked(frontend_settings.beautify_bundles)
        self.llm_checkbox.setChecked(llm_settings.enabled)
        self.llm_auto_checkbox.setChecked(llm_settings.auto)
        self.llm_background_checkbox.setChecked(llm_settings.background)
        self.llm_install_checkbox.setChecked(llm_settings.allow_dependency_installs)
        self.llm_build_checkbox.setChecked(llm_settings.run_recompile_checks)
        self.llm_model_input.setText(llm_settings.model)
        self.llm_auth_combo.setCurrentText(llm_settings.auth_provider)
        self.codex_auth_input.setText(llm_settings.codex_auth_path)
        self.llm_reasoning_combo.setCurrentText(llm_settings.reasoning_effort)
        self.llm_verbosity_combo.setCurrentText(llm_settings.verbosity)
        self.llm_max_output_input.setText(str(llm_settings.max_output_tokens))
        self.llm_task_input.setPlainText(llm_settings.user_task)
        self.porting_enabled_checkbox.setChecked(porting_settings.enabled)
        self.porting_source_arch_input.setText(porting_settings.source_arch)
        self.porting_target_arch_combo.setCurrentText(porting_settings.target_arch)
        self.porting_mode_combo.setCurrentText(porting_settings.mode)
        self.runtime_trace_checkbox.setChecked(runtime_settings.enabled)
        self.runtime_trace_seconds_input.setText(str(runtime_settings.duration_seconds))
        self.runtime_trace_frida_checkbox.setChecked(runtime_settings.use_frida)
        self.live_process_checkbox.setChecked(live_settings.enabled)
        self.live_pid_input.setText(str(live_settings.pid or ""))
        self.live_name_input.setText(live_settings.process_name)
        self.live_memory_checkbox.setChecked(live_settings.dump_memory)
        self.live_max_total_input.setText(str(max(1, live_settings.max_total_bytes // (1024 * 1024))))
        self.profile_name_input.setText(str(profile.get("name", "")))
        self._load_selected_profile_report()
        self.statusBar().showMessage(f"Loaded profile: {profile.get('name', '')}")

    def _load_selected_profile_report(self) -> None:
        profile = self._current_profile
        if profile is None:
            return
        last_run = profile.get("last_run") or {}
        output_dir = Path(str(last_run.get("output_dir", "")).strip())
        report_path = output_dir / "report.json"
        if not report_path.exists():
            return
        try:
            report = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return
        if isinstance(report, dict):
            self._display_report(report)

    def _open_selected_profile_output(self) -> None:
        profile = self._current_profile
        if profile is None:
            return
        if str(profile.get("profile_type", "")).strip().lower() == "analysis":
            output_dir = str((profile.get("last_run") or {}).get("output_dir", "")).strip()
            if output_dir:
                QDesktopServices.openUrl(QUrl.fromLocalFile(output_dir))
                return
        settings = profile.get("settings") or {}
        workspace_root = str(settings.get("workspace_root", "")).strip()
        if workspace_root:
            QDesktopServices.openUrl(QUrl.fromLocalFile(workspace_root))

    def _open_item_path(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _open_tree_item_path(self, item: QTreeWidgetItem) -> None:
        path = item.data(0, Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    @staticmethod
    def _parse_int(value: str, *, default: int) -> int:
        try:
            return int(value)
        except ValueError:
            return default

    @staticmethod
    def _load_artifact_text(report: dict, description_contains: str) -> str:
        for artifact in report.get("artifacts") or []:
            description = artifact.get("description", "")
            path = artifact.get("path", "")
            if description_contains.lower() not in description.lower():
                continue
            candidate = Path(path)
            if not candidate.exists() or not candidate.is_file():
                continue
            try:
                return candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
        return ""

    def _populate_index(self, report: dict) -> None:
        payload = self._load_artifact_json(report, "Unified analysis index")
        self._current_index_payload = payload
        if not payload:
            self.index_summary_text.setPlainText("No analysis index available for this report.")
            self.index_table.setRowCount(0)
            self.index_detail_text.clear()
            self.index_workflow_summary.clear()
            self.index_related_list.clear()
            self._current_index_workflow = None
            return
        summary = payload.get("summary") or {}
        entity_counts = summary.get("entity_counts") or {}
        lines = [f"{kind}: {count}" for kind, count in sorted(entity_counts.items())]
        summary_text = (
            f"Entities: {sum(entity_counts.values())}\n"
            f"Relations: {summary.get('relation_count', 0)}\n"
            + ("\n".join(lines) if lines else "")
        )
        self.index_summary_text.setPlainText(summary_text)
        self._refresh_index_table()

    def _populate_quality(self, report: dict) -> None:
        dashboard = self._load_artifact_text(report, "Recovery quality dashboard")
        manifest = self._load_artifact_json(report, "Recovery quality manifest")
        graph = self._load_artifact_json(report, "Evidence graph manifest")
        parts: list[str] = []
        if dashboard:
            parts.append(dashboard.strip())
        if manifest:
            parts.extend(["", "## Machine Manifest", "", "```json", json.dumps(manifest, indent=2), "```"])
        if graph:
            parts.extend(["", "## Evidence Graph", "", "```json", json.dumps(graph, indent=2), "```"])
        if not parts:
            parts.append("No recovery quality manifest is available for this report.")
        self._set_markdown_text(self.quality_text, "\n".join(parts).strip())

    def _populate_job_center(self, report: dict) -> None:
        rows: list[dict] = []
        for artifact in report.get("artifacts") or []:
            description = str(artifact.get("description", ""))
            path = str(artifact.get("path", ""))
            if "status" not in description.lower():
                continue
            payload = self._read_json_file(self._path_or_none(path)) or {}
            rows.append(
                {
                    "type": self._job_type_from_description(description),
                    "state": str(payload.get("state", "artifact")),
                    "priority": "",
                    "label": description,
                    "path": path,
                    "detail": payload,
                }
            )
        stub_queue = self._load_artifact_json(report, "Stub elimination queue") or {}
        for target in stub_queue.get("targets") or []:
            path = str(target.get("path") or target.get("source_path") or "")
            rows.append(
                {
                    "type": f"stub:{target.get('kind', 'target')}",
                    "state": "queued",
                    "priority": str(target.get("priority", "")),
                    "label": str(target.get("label") or target.get("entity_id") or path),
                    "path": path,
                    "detail": target,
                }
            )
        self._job_center_rows = rows
        self.job_center_table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            values = [item["type"], item["state"], item["priority"], item["label"], item["path"]]
            for column, value in enumerate(values):
                table_item = QTableWidgetItem(str(value))
                table_item.setData(Qt.UserRole, row)
                self.job_center_table.setItem(row, column, table_item)
        self.job_center_table.resizeColumnsToContents()
        if rows:
            self.job_center_table.selectRow(0)
        else:
            self.job_center_detail.setPlainText("No background jobs or stub targets are available for this report.")

    def _populate_function_evidence(self, report: dict) -> None:
        del report
        payload = self._current_index_payload or {}
        entities = payload.get("entities") or []
        functions = []
        for entity in entities:
            if entity.get("kind") != "function":
                continue
            attrs = entity.get("attributes") or {}
            functions.append(
                {
                    "entity_id": f"{entity.get('kind')}:{entity.get('key')}",
                    "entity": entity,
                    "label": str(entity.get("label", "")),
                    "address": str(attrs.get("address") or ""),
                    "class_name": str(attrs.get("class_name") or attrs.get("namespace") or ""),
                    "tool": str(attrs.get("tool") or ""),
                    "confidence": self._function_confidence(entity),
                    "provenance": self._function_provenance(entity),
                    "has_decompiled_body": bool(attrs.get("decompiled_c")),
                    "is_generic_name": self._is_generic_function_name(str(entity.get("label", ""))),
                }
            )
        functions.sort(key=lambda item: (item["confidence"] == "low", item["label"].lower(), item["address"]))
        self._function_evidence_entities = functions
        self._refresh_function_evidence_table()

    def _refresh_function_evidence_table(self) -> None:
        query = self.function_search_input.text().strip().lower()
        confidence_filter = self.function_confidence_combo.currentText().strip().lower()
        if confidence_filter == "all":
            confidence_filter = ""
        rows = []
        for item in self._function_evidence_entities:
            if confidence_filter and item["confidence"] != confidence_filter:
                continue
            haystack = " ".join(
                [
                    item["label"],
                    item["address"],
                    item["class_name"],
                    item["tool"],
                    item["confidence"],
                    item["provenance"],
                    json.dumps((item["entity"].get("attributes") or {}), ensure_ascii=False),
                ]
            ).lower()
            if query and query not in haystack:
                continue
            rows.append(item)
        self.function_evidence_table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            values = [item["label"], item["address"], item["class_name"], item["tool"], item["confidence"], item["provenance"]]
            for column, value in enumerate(values):
                table_item = QTableWidgetItem(str(value))
                table_item.setData(Qt.UserRole, item["entity_id"])
                self.function_evidence_table.setItem(row, column, table_item)
        self.function_evidence_table.resizeColumnsToContents()
        if rows:
            self.function_evidence_table.selectRow(0)
        else:
            self.function_evidence_detail.setPlainText("No functions matched the current filter.")

    def _show_selected_function_evidence(self) -> None:
        if self._current_report is None or self._current_index_payload is None:
            return
        items = self.function_evidence_table.selectedItems()
        if not items:
            return
        entity_id = str(items[0].data(Qt.UserRole) or "")
        if not entity_id:
            return
        entity = next(
            (
                item["entity"]
                for item in self._function_evidence_entities
                if item["entity_id"] == entity_id
            ),
            None,
        )
        if entity is None:
            return
        workflow = build_entity_workflow(self._current_report, self._current_index_payload, entity_id)
        attrs = entity.get("attributes") or {}
        detail = {
            "entity_id": entity_id,
            "label": entity.get("label"),
            "confidence": self._function_confidence(entity),
            "provenance": self._function_provenance(entity),
            "address": attrs.get("address"),
            "class_name": attrs.get("class_name"),
            "signature": attrs.get("signature"),
            "decompile_success": attrs.get("decompile_success"),
            "workflow_summary": workflow.get("workflow_summary"),
            "artifact_candidates": workflow.get("artifact_candidates"),
            "recovered_sources": workflow.get("recovered_sources"),
            "callers": attrs.get("callers"),
            "callees": attrs.get("callees"),
        }
        lines = [json.dumps(detail, indent=2)]
        decompiled_c = str(attrs.get("decompiled_c") or "").strip()
        if decompiled_c:
            lines.extend(["", "Decompiled body:", "", decompiled_c])
        self.function_evidence_detail.setPlainText("\n".join(lines))

    def _show_selected_job_center_item(self) -> None:
        row = self._selected_job_center_row()
        if row is None:
            return
        self.job_center_detail.setPlainText(json.dumps(row, indent=2))

    def _open_selected_job_center_item(self) -> None:
        row = self._selected_job_center_row()
        if row and row.get("path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(row["path"])))

    def _preview_selected_job_center_item(self) -> None:
        row = self._selected_job_center_row()
        if not row or not row.get("path"):
            return
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.artifacts_tab_widget))
        self._load_preview(str(row["path"]))

    def _selected_job_center_row(self) -> dict | None:
        items = self.job_center_table.selectedItems()
        if not items:
            return None
        row_index = items[0].data(Qt.UserRole)
        if not isinstance(row_index, int) or row_index < 0 or row_index >= len(self._job_center_rows):
            return None
        return self._job_center_rows[row_index]

    @staticmethod
    def _job_type_from_description(description: str) -> str:
        lowered = description.lower()
        if "llm" in lowered:
            return "llm"
        if "ghidra" in lowered:
            return "ghidra"
        if "pe tools" in lowered:
            return "pe-tools"
        if "jadx" in lowered:
            return "jadx"
        if "frida" in lowered or "runtime" in lowered:
            return "runtime"
        return "background"

    @staticmethod
    def _function_provenance(entity: dict) -> str:
        attrs = entity.get("attributes") or {}
        key = str(entity.get("key") or "")
        if attrs.get("decompiled_c"):
            return "decompiler-backed"
        if key.startswith("msvc_rtti:") or attrs.get("vtable_rva"):
            return "rtti-vtable"
        if attrs.get("class_name"):
            return "class-context"
        return str(attrs.get("tool") or "analysis-index")

    @staticmethod
    def _function_confidence(entity: dict) -> str:
        attrs = entity.get("attributes") or {}
        label = str(entity.get("label") or "")
        if attrs.get("decompiled_c") and not MainWindow._is_generic_function_name(label):
            return "high"
        if attrs.get("decompiled_c") or attrs.get("class_name") or attrs.get("vtable_rva"):
            return "medium"
        return "low" if MainWindow._is_generic_function_name(label) else "medium"

    @staticmethod
    def _is_generic_function_name(name: str) -> bool:
        return name.startswith(("sub_", "FUN_", "thunk_", "vf_"))

    def _refresh_index_table(self) -> None:
        payload = self._current_index_payload or {}
        entities = payload.get("entities") or []
        query = self.index_search_input.text().strip().lower()
        selected_kind = self.index_kind_combo.currentText().strip().lower()
        if selected_kind == "all":
            selected_kind = ""
        filtered = []
        for entity in entities:
            kind = str(entity.get("kind", ""))
            if selected_kind and kind.lower() != selected_kind:
                continue
            haystack = " ".join(
                [
                    kind,
                    str(entity.get("label", "")),
                    str(entity.get("key", "")),
                    json.dumps(entity.get("attributes") or {}, ensure_ascii=False),
                ]
            ).lower()
            if query and query not in haystack:
                continue
            filtered.append(entity)

        self.index_table.setRowCount(len(filtered))
        for row, entity in enumerate(filtered):
            entity_id = f"{entity.get('kind')}:{entity.get('key')}"
            self.index_table.setItem(row, 0, QTableWidgetItem(str(entity.get("kind", ""))))
            self.index_table.setItem(row, 1, QTableWidgetItem(str(entity.get("label", ""))))
            self.index_table.setItem(row, 2, QTableWidgetItem(str(entity.get("key", ""))))
            self.index_table.setItem(row, 3, QTableWidgetItem(self._format_attributes(entity.get("attributes") or {})))
            for column in range(4):
                item = self.index_table.item(row, column)
                if item is not None:
                    item.setData(Qt.UserRole, entity_id)
        self.index_table.resizeColumnsToContents()
        if not filtered:
            self.index_detail_text.setPlainText("No entities matched the current filter.")
            self.index_workflow_summary.clear()
            self.index_related_list.clear()
            self._current_index_workflow = None

    def _show_selected_index_entity(self) -> None:
        payload = self._current_index_payload or {}
        items = self.index_table.selectedItems()
        if not items:
            return
        entity_id = items[0].data(Qt.UserRole)
        if not entity_id:
            return
        entity = None
        for candidate in payload.get("entities") or []:
            candidate_id = f"{candidate.get('kind')}:{candidate.get('key')}"
            if candidate_id == entity_id:
                entity = candidate
                break
        if entity is None:
            self.index_detail_text.clear()
            self.index_workflow_summary.clear()
            self.index_related_list.clear()
            self._current_index_workflow = None
            return
        related = [
            relation
            for relation in payload.get("relations") or []
            if relation.get("source") == entity_id or relation.get("target") == entity_id
        ][:200]
        detail = {
            "entity_id": entity_id,
            "entity": entity,
            "related_relations": related,
        }
        self.index_detail_text.setPlainText(json.dumps(detail, indent=2))
        if self._current_report is None:
            self.index_workflow_summary.clear()
            self.index_related_list.clear()
            self._current_index_workflow = None
            return
        workflow = build_entity_workflow(self._current_report, payload, entity_id)
        self._current_index_workflow = workflow
        self.index_workflow_summary.setPlainText(str(workflow.get("workflow_summary", "")))
        self._populate_index_related_list(workflow)

    def _populate_index_related_list(self, workflow: dict) -> None:
        self.index_related_list.clear()
        added_paths: set[str] = set()
        for artifact in workflow.get("artifact_candidates") or []:
            path = str(artifact.get("path", "")).strip()
            if not path or path in added_paths:
                continue
            added_paths.add(path)
            label = str(artifact.get("label", "")) or Path(path).name
            item = QListWidgetItem(f"[artifact] {label} - {path}")
            item.setData(Qt.UserRole, path)
            item.setData(Qt.UserRole + 1, "artifact")
            self.index_related_list.addItem(item)
        for source in workflow.get("recovered_sources") or []:
            path = str(source.get("restored_path", "")).strip()
            if not path or path in added_paths:
                continue
            added_paths.add(path)
            label = str(source.get("original_path", "")) or Path(path).name
            item = QListWidgetItem(f"[source] {label} -> {path}")
            item.setData(Qt.UserRole, path)
            item.setData(Qt.UserRole + 1, "source")
            self.index_related_list.addItem(item)
        action_targets = workflow.get("action_targets") or {}
        for label, path, role in [
            ("Porting guidance", action_targets.get("porting_notes_path"), "porting"),
            ("Prepared sources", action_targets.get("prepared_sources_path"), "porting"),
            ("Recompile workspace", action_targets.get("recompile_workspace_path"), "recompile"),
            ("Recompile manifest", action_targets.get("recompile_manifest_path"), "recompile"),
            ("LLM summary", action_targets.get("llm_summary_path"), "llm"),
        ]:
            if not path or path in added_paths:
                continue
            added_paths.add(path)
            item = QListWidgetItem(f"[{role}] {label} - {path}")
            item.setData(Qt.UserRole, path)
            item.setData(Qt.UserRole + 1, role)
            self.index_related_list.addItem(item)

    def _open_index_related_item(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _open_selected_index_related_item(self) -> None:
        item = self.index_related_list.currentItem()
        if item is not None:
            self._open_index_related_item(item)

    def _preview_selected_index_related_item(self) -> None:
        item = self.index_related_list.currentItem()
        if item is None:
            return
        path = item.data(Qt.UserRole)
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.artifacts_tab_widget))
        self._load_preview(path)

    def _show_index_workflow_artifacts(self) -> None:
        workflow = self._current_index_workflow or {}
        for path in (workflow.get("action_targets") or {}).get("artifact_paths") or []:
            if self._select_artifact_path(path):
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.artifacts_tab_widget))
                return

    def _show_index_workflow_sources(self) -> None:
        workflow = self._current_index_workflow or {}
        for path in (workflow.get("action_targets") or {}).get("recovered_source_paths") or []:
            if self._select_source_path(path):
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.sources_tab_widget))
                return

    def _open_index_porting_target(self) -> None:
        workflow = self._current_index_workflow or {}
        action_targets = workflow.get("action_targets") or {}
        for path in [action_targets.get("porting_notes_path"), action_targets.get("prepared_sources_path")]:
            if path:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
                return

    def _open_index_recompile_target(self) -> None:
        workflow = self._current_index_workflow or {}
        action_targets = workflow.get("action_targets") or {}
        for path in [action_targets.get("recompile_workspace_path"), action_targets.get("recompile_manifest_path")]:
            if path:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
                return

    def _select_artifact_path(self, path: str) -> bool:
        for row in range(self.artifacts_list.count()):
            item = self.artifacts_list.item(row)
            if item.data(Qt.UserRole) == path:
                self.artifacts_list.setCurrentItem(item)
                return True
        return False

    def _select_source_path(self, path: str) -> bool:
        for row in range(self.sources_tree.topLevelItemCount()):
            item = self.sources_tree.topLevelItem(row)
            if item.data(0, Qt.UserRole) == path:
                self.sources_tree.setCurrentItem(item)
                return True
        return False

    @staticmethod
    def _format_attributes(attributes: dict) -> str:
        preview = []
        for key, value in list(attributes.items())[:4]:
            preview.append(f"{key}={value}")
        return ", ".join(preview)

    @staticmethod
    def _load_artifact_json(report: dict, description_contains: str) -> dict | None:
        for artifact in report.get("artifacts") or []:
            description = artifact.get("description", "")
            path = artifact.get("path", "")
            if description_contains.lower() not in description.lower():
                continue
            candidate = Path(path)
            if not candidate.exists() or not candidate.is_file():
                continue
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
        return None


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
