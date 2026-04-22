from __future__ import annotations

from collections import Counter

from ..pe_resources import extract_pe_resources
from .base import Analyzer


class PEResourceAnalyzer(Analyzer):
    name = "PE resource extraction"

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or context.pe_metadata is None:
            return

        entries, manifest_path = extract_pe_resources(context.target, context.output_dir)
        if not entries:
            return

        report.add_artifact(str(manifest_path), "manifest", "PE resource manifest")
        type_counts = Counter(entry.type_name for entry in entries)
        summary = ", ".join(f"{resource_type}={count}" for resource_type, count in type_counts.most_common(8))
        report.add_finding(
            "PE resources extracted",
            f"Recovered {len(entries)} embedded Windows resources.",
            severity="info",
            details=summary or None,
        )
        report.add_note(f"Recovered PE resources by type: {summary}.")

        limits = {
            "ICO": 8,
            "MANIFEST": 4,
            "HTML": 4,
            "VERSION": 4,
            "GROUP_ICON": 6,
            "ICON": 8,
            "RCDATA": 12,
        }
        counts: dict[str, int] = {}
        for entry in entries:
            limit = limits.get(entry.type_name)
            if limit is None:
                continue
            current = counts.get(entry.type_name, 0)
            if current >= limit:
                continue
            counts[entry.type_name] = current + 1
            report.add_artifact(entry.path, "resource", f"{entry.type_name} resource: {entry.name} (lang {entry.language})")
