"""Frontend bundle reconstruction (Electron / Tauri / generic SPA).

This package was split out of a single 1,300-line module. The public API
is unchanged — ``from re_pro.frontend_reconstruct import
reconstruct_bundled_frontend_assets`` still works.

Layout:

- ``helpers`` — pure leaves (PurePosixPath utilities, identifier
  casing, beautifier). No internal imports.
- ``lifting`` — JS/CSS bundle lifting passes, AST validation, LLM
  source-grade scaffolding. Imports from ``helpers``.
- ``core`` — orchestration entry point + manifest loading + path map
  building + reference rewriting. Imports from ``helpers`` and
  ``lifting``.
"""

from __future__ import annotations

from .core import reconstruct_bundled_frontend_assets

__all__ = ["reconstruct_bundled_frontend_assets"]
