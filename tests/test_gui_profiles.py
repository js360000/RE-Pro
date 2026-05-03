from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

from re_pro.gui import MainWindow
import re_pro.profiles as profile_module
from re_pro.profiles import build_analysis_profile
from re_pro.profiles import save_profile


class GuiProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_gui_can_refresh_and_load_saved_analysis_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profiles_root = root / "profiles"
            output_dir = root / "analysis_output" / "demo_20260423_180500"
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "report.json").write_text(
                '{"target":"demo.exe","target_type":"portable-executable","output_dir":"'
                + str(output_dir).replace("\\", "\\\\")
                + '","frameworks":["Electron"],"findings":[],"artifacts":[],"recovered_sources":[],"notes":[]}',
                encoding="utf-8",
            )
            save_profile(
                build_analysis_profile(
                    name="GUI Demo",
                    target=str(root / "demo.exe"),
                    output_root=str(root / "analysis_output"),
                    run_external_tools=True,
                    report={
                        "target": str(root / "demo.exe"),
                        "output_dir": str(output_dir),
                        "frameworks": ["Electron"],
                        "findings": [],
                        "artifacts": [],
                        "recovered_sources": [],
                    },
                ),
                profiles_root=profiles_root,
            )

            with patch(
                "re_pro.gui.list_profiles",
                side_effect=lambda **kwargs: profile_module.list_profiles(
                    profiles_root=profiles_root,
                    query=kwargs.get("query", ""),
                    profile_type=kwargs.get("profile_type", ""),
                ),
            ):
                with patch("re_pro.gui.load_profile", side_effect=lambda identifier: profile_module.load_profile(identifier, profiles_root=profiles_root)):
                    window = MainWindow()
                    window._refresh_profiles()
                    self.assertGreater(window.profiles_list.count(), 0)
                    window.profiles_list.setCurrentRow(0)
                    window._load_selected_profile()
                    self.assertEqual(window.target_input.text(), str(root / "demo.exe"))
                    self.assertTrue(window.external_tools_checkbox.isChecked())
                    self.assertIn("Frameworks: Electron", window.summary_text.toPlainText())
                    window.close()

    def test_gui_exposes_background_log_windows_for_async_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "analysis_output" / "demo_async"
            output_dir.mkdir(parents=True, exist_ok=True)
            ghidra_dir = output_dir / "ghidra"
            pe_tools_dir = output_dir / "pe_tools"
            ghidra_dir.mkdir(parents=True, exist_ok=True)
            pe_tools_dir.mkdir(parents=True, exist_ok=True)

            ghidra_log = ghidra_dir / "ghidra_headless.log"
            ghidra_status = ghidra_dir / "status.json"
            pe_log = pe_tools_dir / "pe_tools.log"
            pe_status = pe_tools_dir / "status.json"
            ghidra_log.write_text("[ghidra] still running\n", encoding="utf-8")
            ghidra_status.write_text('{"state":"running","target":"demo.exe","warning_counts":{"unable_to_read_bytes":12}}', encoding="utf-8")
            pe_log.write_text("[pe] export running\n", encoding="utf-8")
            pe_status.write_text('{"state":"queued","target":"demo.exe"}', encoding="utf-8")

            report = {
                "target": str(root / "demo.exe"),
                "target_type": "portable-executable",
                "output_dir": str(output_dir),
                "frameworks": [],
                "findings": [],
                "artifacts": [
                    {"path": str(ghidra_log), "category": "log", "description": "Ghidra headless log"},
                    {"path": str(ghidra_status), "category": "metadata", "description": "Ghidra headless status"},
                    {"path": str(pe_log), "category": "log", "description": "PE tools background log"},
                    {"path": str(pe_status), "category": "metadata", "description": "PE tools background status"},
                ],
                "recovered_sources": [],
                "notes": [],
            }

            window = MainWindow()
            window._display_report(report)

            self.assertTrue(window.open_ghidra_log_button.isEnabled())
            self.assertTrue(window.open_pe_log_button.isEnabled())

            window._open_ghidra_log_window()
            window._open_pe_log_window()

            self.assertIsNotNone(window.ghidra_log_window)
            self.assertIsNotNone(window.pe_log_window)
            self.assertIn("State: running", window.ghidra_log_window.status_text.toPlainText())
            self.assertIn("unable_to_read_bytes=12", window.ghidra_log_window.status_text.toPlainText())
            self.assertIn("[ghidra] still running", window.ghidra_log_window.log_text.toPlainText())
            self.assertIn("State: queued", window.pe_log_window.status_text.toPlainText())
            self.assertIn("[pe] export running", window.pe_log_window.log_text.toPlainText())

            window.ghidra_log_window.close()
            window.pe_log_window.close()
            window.close()


if __name__ == "__main__":
    unittest.main()
