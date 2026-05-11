"""MSVC RTTI class recovery: pseudo-C++ header/source synthesis.

This package was split out of a single 2,583-line module. The public
surface is unchanged — every import that worked against
``re_pro.msvc_pseudo_cpp`` continues to work:

- ``RECOVERY_CAPABILITIES``
- ``GENERIC_FUNCTION_PREFIXES``
- ``CALLING_CONVENTION_TOKENS``
- ``write_pseudo_class_sources``
- ``enrich_recovered_classes``
- ``class_output_paths``
- ``render_class_header``
- ``render_class_source``

Layout:

- ``_text`` — pure stdlib leaves (address/identifier/type/signature
  parsing) shared across the rest of the package.
- ``_internals`` — class rendering, method inference, member inference,
  layout estimation, and recovery-feature annotation. The bulk of the
  implementation lives here pending further per-theme extraction in
  follow-up PRs.
"""

from __future__ import annotations

from ._internals import (
    GENERIC_FUNCTION_PREFIXES,
    RECOVERY_CAPABILITIES,
    class_output_paths,
    enrich_recovered_classes,
    render_class_header,
    render_class_source,
    write_pseudo_class_sources,
)
from ._text import CALLING_CONVENTION_TOKENS

__all__ = [
    "CALLING_CONVENTION_TOKENS",
    "GENERIC_FUNCTION_PREFIXES",
    "RECOVERY_CAPABILITIES",
    "class_output_paths",
    "enrich_recovered_classes",
    "render_class_header",
    "render_class_source",
    "write_pseudo_class_sources",
]
