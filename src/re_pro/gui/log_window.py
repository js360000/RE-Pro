from __future__ import annotations

import json
from pathlib import Path

from PyQt5.QtCore import QTimer, QUrl
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


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
