from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisReport
from .utils import sanitize_text


def write_json_report(report: AnalysisReport, destination: Path) -> Path:
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    destination.write_text(sanitize_text(payload), encoding="utf-8")
    return destination


def write_markdown_report(report: AnalysisReport, destination: Path) -> Path:
    lines = [
        "# RE-Pro Analysis Report",
        "",
        f"- Target: `{report.target}`",
        f"- Type: `{report.target_type}`",
        f"- Output: `{report.output_dir}`",
        "",
        "## Frameworks",
        "",
    ]
    if report.frameworks:
        lines.extend(f"- {framework}" for framework in report.frameworks)
    else:
        lines.append("- None detected")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings:
            lines.append(f"- [{finding.severity.upper()}] {finding.title}: {finding.summary}")
            if finding.details:
                lines.append(f"  Details: {finding.details}")
    else:
        lines.append("- No findings")

    lines.extend(["", "## Artifacts", ""])
    if report.artifacts:
        lines.extend(f"- `{artifact.path}` ({artifact.category}): {artifact.description}" for artifact in report.artifacts)
    else:
        lines.append("- No artifacts")

    lines.extend(["", "## Recovered Sources", ""])
    if report.recovered_sources:
        lines.extend(
            f"- `{source.original_path}` -> `{source.restored_path}`"
            for source in report.recovered_sources
        )
    else:
        lines.append("- No recovered sources")

    lines.extend(["", "## Notes", ""])
    if report.notes:
        lines.extend(f"- {note}" for note in report.notes)
    else:
        lines.append("- No notes")

    destination.write_text(sanitize_text("\n".join(lines) + "\n"), encoding="utf-8")
    return destination
