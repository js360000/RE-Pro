"""RE-Pro PyQt5 desktop frontend.

This package was split out of a single ~2,500-line module. The public
surface is preserved:

- ``from re_pro.gui import MainWindow, main`` continues to work.
- Tests that ``patch("re_pro.gui.list_profiles", ...)`` /
  ``patch("re_pro.gui.load_profile", ...)`` continue to work because
  those names are re-exported here and ``main_window`` accesses them via
  a late-binding ``import re_pro.gui as _pkg`` indirection.
"""

from __future__ import annotations

# Names that may be patched on the ``re_pro.gui`` namespace MUST be imported
# here BEFORE ``main_window`` is imported, so the package attribute lookup
# from ``main_window._pkg.list_profiles`` resolves to the (patchable)
# attribute and not to an internal capture.
from ..dependency_installer import DependencyInstaller
from ..engine import ReverseEngineeringEngine
from ..index_workflows import build_entity_workflow
from ..live_process import resolve_live_process
from ..mcp_launch import build_mcp_launch_details, start_mcp_server_process, stop_mcp_server_process
from ..models import (
    FrontendSettings,
    LiveProcessSettings,
    LlmAssistSettings,
    OutputSettings,
    PortingSettings,
    RuntimeTraceSettings,
)
from ..profiles import (
    analysis_settings_from_profile,
    build_analysis_profile,
    list_profiles,
    load_profile,
    save_profile,
)
from ..workspace_browser import (
    build_browser_workspace,
    patch_browser_node_bytes,
    read_browser_node,
    write_browser_node,
)
from .log_window import BackgroundLogWindow
from .main_window import MainWindow, main
from .workers import AnalysisWorker, ToolInstallWorker

__all__ = [
    "AnalysisWorker",
    "BackgroundLogWindow",
    "MainWindow",
    "ToolInstallWorker",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
