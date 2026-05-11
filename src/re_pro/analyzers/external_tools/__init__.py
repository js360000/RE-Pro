"""External RE tool orchestration (Ghidra, rizin, radare2).

This package was split out of a single 1,100-line module. The public
surface is unchanged — ``from re_pro.analyzers.external_tools import
ExternalToolAnalyzer`` still works — and existing test ``patch()`` sites
targeting module-level names (``resolve_command``, ``list_ghidra_languages``)
continue to function because those names are re-exported here.
"""

from __future__ import annotations

from ...api_semantics import refine_targeted_decompilation
from ...background_launch import (
    build_re_pro_background_command,
    build_re_pro_background_env,
    re_pro_background_cwd,
)
from ...msvc_pseudo_cpp import enrich_recovered_classes, write_pseudo_class_sources
from ...tooling import (
    get_ghidra_install_root,
    list_ghidra_languages,
    resolve_command,
    run_command_logged,
)
from ...utils import ensure_dir, safe_slug

# Names that tests patch via ``patch("re_pro.analyzers.external_tools.X", ...)``
# MUST be imported into this package namespace BEFORE ``analyzer`` is imported,
# so the ``import re_pro.analyzers.external_tools as _pkg`` indirection in
# ``analyzer`` resolves to the populated namespace.
from ..base import Analyzer
from .analyzer import ExternalToolAnalyzer

__all__ = ["ExternalToolAnalyzer"]
