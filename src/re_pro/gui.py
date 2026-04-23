from __future__ import annotations

import json
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, Qt, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
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
from .models import LlmAssistSettings
from .models import RuntimeTraceSettings


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
        runtime_trace_settings: RuntimeTraceSettings,
    ) -> None:
        super().__init__()
        self.target = target
        self.output_root = output_root
        self.run_external_tools = run_external_tools
        self.run_ghidra = run_ghidra
        self.llm_settings = llm_settings
        self.runtime_trace_settings = runtime_trace_settings

    def run(self) -> None:
        try:
            engine = ReverseEngineeringEngine(
                output_root=self.output_root,
                logger=self.progress.emit,
                run_external_tools=self.run_external_tools,
                run_ghidra=self.run_ghidra,
                llm_settings=self.llm_settings,
                runtime_trace_settings=self.runtime_trace_settings,
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


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("RE-Pro")
        self.resize(1280, 840)
        self.worker: AnalysisWorker | None = None
        self.tool_worker: ToolInstallWorker | None = None
        self._history: list[dict] = []
        self._current_report: dict | None = None
        self._current_index_payload: dict | None = None
        self._current_index_workflow: dict | None = None
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

        action_row = QHBoxLayout()
        self.analyze_button = QPushButton("Run Analysis")
        self.install_tools_button = QPushButton("Install Tooling")
        self.external_tools_checkbox = QCheckBox("Run RE Tools")
        self.ghidra_checkbox = QCheckBox("Run Ghidra")
        self.tools_input = QLineEdit(str((Path.cwd() / "tools").resolve()))
        action_row.addWidget(self.analyze_button)
        action_row.addWidget(self.install_tools_button)
        action_row.addWidget(self.external_tools_checkbox)
        action_row.addWidget(self.ghidra_checkbox)
        controls_layout.addRow("Target", target_row)
        controls_layout.addRow("Output Root", output_row)
        controls_layout.addRow("Tools Root", self.tools_input)

        llm_options = QHBoxLayout()
        self.llm_checkbox = QCheckBox("Run GPT-5.4")
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

        llm_params = QHBoxLayout()
        self.llm_model_input = QLineEdit("gpt-5.4")
        self.llm_reasoning_combo = QComboBox()
        self.llm_reasoning_combo.addItems(["none", "low", "medium", "high", "xhigh"])
        self.llm_reasoning_combo.setCurrentText("high")
        self.llm_verbosity_combo = QComboBox()
        self.llm_verbosity_combo.addItems(["low", "medium", "high"])
        self.llm_verbosity_combo.setCurrentText("medium")
        self.llm_max_output_input = QLineEdit("12000")
        llm_params.addWidget(QLabel("Model"))
        llm_params.addWidget(self.llm_model_input)
        llm_params.addWidget(QLabel("Reasoning"))
        llm_params.addWidget(self.llm_reasoning_combo)
        llm_params.addWidget(QLabel("Verbosity"))
        llm_params.addWidget(self.llm_verbosity_combo)
        llm_params.addWidget(QLabel("Max Output"))
        llm_params.addWidget(self.llm_max_output_input)
        controls_layout.addRow("LLM Params", llm_params)

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
        self.llm_text = QPlainTextEdit()
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

        self.sources_tree = QTreeWidget()
        self.sources_tree.setHeaderLabels(["Recovered Source", "Restored Path"])
        self.sources_tree.itemDoubleClicked.connect(self._open_tree_item_path)
        self.sources_tree.currentItemChanged.connect(self._preview_source)

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

        self.json_text = QPlainTextEdit()
        self.json_text.setReadOnly(True)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)

        self.history_list = QListWidget()
        self.history_list.currentRowChanged.connect(self._show_history_report)

        self.tabs.addTab(self.summary_text, "Summary")
        self.tabs.addTab(self.runtime_text, "Runtime")
        self.tabs.addTab(self.porting_text, "Porting")
        self.tabs.addTab(self.llm_text, "LLM")
        self.tabs.addTab(self.frameworks_list, "Frameworks")
        self.tabs.addTab(self.findings_table, "Findings")
        self.tabs.addTab(artifacts_splitter, "Artifacts")
        self.tabs.addTab(self.sources_tree, "Recovered Sources")
        self.tabs.addTab(index_panel, "Analysis Index")
        self.tabs.addTab(self.json_text, "JSON")
        self.tabs.addTab(self.history_list, "History")
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
        self.index_search_input.textChanged.connect(self._refresh_index_table)
        self.index_kind_combo.currentTextChanged.connect(self._refresh_index_table)
        self.index_open_button.clicked.connect(self._open_selected_index_related_item)
        self.index_preview_button.clicked.connect(self._preview_selected_index_related_item)
        self.index_artifacts_button.clicked.connect(self._show_index_workflow_artifacts)
        self.index_sources_button.clicked.connect(self._show_index_workflow_sources)
        self.index_porting_button.clicked.connect(self._open_index_porting_target)
        self.index_recompile_button.clicked.connect(self._open_index_recompile_target)

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
        self.analyze_button.setEnabled(False)
        self.statusBar().showMessage("Analyzing...")

        run_ghidra = self.ghidra_checkbox.isChecked()
        self.worker = AnalysisWorker(
            target=target,
            output_root=output_root,
            run_external_tools=self.external_tools_checkbox.isChecked() or run_ghidra,
            run_ghidra=run_ghidra,
            llm_settings=LlmAssistSettings(
                enabled=self.llm_checkbox.isChecked(),
                auto=self.llm_auto_checkbox.isChecked(),
                model=self.llm_model_input.text().strip() or "gpt-5.4",
                reasoning_effort=self.llm_reasoning_combo.currentText(),
                verbosity=self.llm_verbosity_combo.currentText(),
                background=self.llm_background_checkbox.isChecked(),
                max_output_tokens=self._parse_int(self.llm_max_output_input.text().strip(), default=12000),
                user_task=self.llm_task_input.toPlainText().strip(),
                allow_dependency_installs=self.llm_install_checkbox.isChecked(),
                run_recompile_checks=self.llm_build_checkbox.isChecked(),
            ),
            runtime_trace_settings=RuntimeTraceSettings(
                enabled=self.runtime_trace_checkbox.isChecked(),
                duration_seconds=max(1, self._parse_int(self.runtime_trace_seconds_input.text().strip(), default=8)),
                use_frida=self.runtime_trace_frida_checkbox.isChecked(),
            ),
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
        self._populate_summary(report)
        self._populate_runtime(report)
        self._populate_frameworks(report)
        self._populate_porting(report)
        self._populate_llm(report)
        self._populate_findings(report)
        self._populate_artifacts(report)
        self._populate_sources(report)
        self._populate_index(report)
        self.json_text.setPlainText(json.dumps(report, indent=2))

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
        self.runtime_text.setPlainText("\n".join(parts))

    def _populate_porting(self, report: dict) -> None:
        self.porting_text.setPlainText(self._load_artifact_text(report, "Porting guidance"))

    def _populate_llm(self, report: dict) -> None:
        text = self._load_artifact_text(report, "LLM reconstruction summary")
        if not text:
            text = self._load_artifact_text(report, "LLM reconstruction status")
        self.llm_text.setPlainText(text)

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
        self._populate_summary(report)
        self._populate_runtime(report)
        self._populate_frameworks(report)
        self._populate_porting(report)
        self._populate_llm(report)
        self._populate_findings(report)
        self._populate_artifacts(report)
        self._populate_sources(report)
        self._populate_index(report)
        self.json_text.setPlainText(json.dumps(report, indent=2))
        self._current_report = report

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
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.widget(5)))
        self._load_preview(path)

    def _show_index_workflow_artifacts(self) -> None:
        workflow = self._current_index_workflow or {}
        for path in (workflow.get("action_targets") or {}).get("artifact_paths") or []:
            if self._select_artifact_path(path):
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.widget(5)))
                return

    def _show_index_workflow_sources(self) -> None:
        workflow = self._current_index_workflow or {}
        for path in (workflow.get("action_targets") or {}).get("recovered_source_paths") or []:
            if self._select_source_path(path):
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.widget(6)))
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
