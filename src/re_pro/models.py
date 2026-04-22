from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class LlmAssistSettings:
    enabled: bool = False
    auto: bool = False
    model: str = "gpt-5.4"
    reasoning_effort: str = "high"
    verbosity: str = "medium"
    background: bool = True
    max_output_tokens: int = 12000
    user_task: str = ""
    allow_dependency_installs: bool = True
    run_recompile_checks: bool = True


@dataclass
class AnalysisFinding:
    title: str
    summary: str
    severity: str = "info"
    details: str | None = None


@dataclass
class Artifact:
    path: str
    category: str
    description: str


@dataclass
class RecoveredSource:
    original_path: str
    restored_path: str
    source_map: str


@dataclass
class AnalysisReport:
    target: str
    target_type: str = "unknown"
    output_dir: str = ""
    fingerprints: dict[str, object] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    findings: list[AnalysisFinding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    recovered_sources: list[RecoveredSource] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_framework(self, framework: str) -> None:
        if framework not in self.frameworks:
            self.frameworks.append(framework)

    def add_finding(
        self,
        title: str,
        summary: str,
        severity: str = "info",
        details: str | None = None,
    ) -> None:
        self.findings.append(
            AnalysisFinding(
                title=title,
                summary=summary,
                severity=severity,
                details=details,
            )
        )

    def add_artifact(self, path: str, category: str, description: str) -> None:
        self.artifacts.append(Artifact(path=path, category=category, description=description))

    def add_recovered_source(self, original_path: str, restored_path: str, source_map: str) -> None:
        self.recovered_sources.append(
            RecoveredSource(
                original_path=original_path,
                restored_path=restored_path,
                source_map=source_map,
            )
        )

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
