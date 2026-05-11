from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class LlmAssistSettings:
    enabled: bool = False
    auto: bool = False
    model: str = "gpt-5.4"
    auth_provider: str = "auto"
    codex_auth_path: str = ""
    reasoning_effort: str = "high"
    verbosity: str = "medium"
    background: bool = True
    max_output_tokens: int = 128000
    user_task: str = ""
    allow_dependency_installs: bool = True
    run_recompile_checks: bool = True

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> LlmAssistSettings:
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            auto=bool(payload.get("auto", False)),
            model=str(payload.get("model", "gpt-5.4")),
            auth_provider=str(payload.get("auth_provider", "auto") or "auto"),
            codex_auth_path=str(payload.get("codex_auth_path", "")),
            reasoning_effort=str(payload.get("reasoning_effort", "high")),
            verbosity=str(payload.get("verbosity", "medium")),
            background=bool(payload.get("background", True)),
            max_output_tokens=int(payload.get("max_output_tokens", 128000) or 128000),
            user_task=str(payload.get("user_task", "")),
            allow_dependency_installs=bool(payload.get("allow_dependency_installs", True)),
            run_recompile_checks=bool(payload.get("run_recompile_checks", True)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class RuntimeTraceSettings:
    enabled: bool = False
    duration_seconds: int = 8
    use_frida: bool = True

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> RuntimeTraceSettings:
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            duration_seconds=int(payload.get("duration_seconds", 8) or 8),
            use_frida=bool(payload.get("use_frida", True)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class LiveProcessSettings:
    enabled: bool = False
    pid: int = 0
    process_name: str = ""
    dump_memory: bool = True
    max_region_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    include_mapped_images: bool = False
    include_all_readable: bool = False

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> LiveProcessSettings:
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            pid=int(payload.get("pid", 0) or 0),
            process_name=str(payload.get("process_name", "")),
            dump_memory=bool(payload.get("dump_memory", True)),
            max_region_bytes=int(payload.get("max_region_bytes", 8 * 1024 * 1024) or 8 * 1024 * 1024),
            max_total_bytes=int(payload.get("max_total_bytes", 256 * 1024 * 1024) or 256 * 1024 * 1024),
            include_mapped_images=bool(payload.get("include_mapped_images", False)),
            include_all_readable=bool(payload.get("include_all_readable", False)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class PortingSettings:
    enabled: bool = False
    source_arch: str = ""
    target_arch: str = ""
    mode: str = "heuristic"

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> PortingSettings:
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            source_arch=str(payload.get("source_arch", "")),
            target_arch=str(payload.get("target_arch", "")),
            mode=str(payload.get("mode", "heuristic") or "heuristic"),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class FrontendSettings:
    beautify_bundles: bool = False

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> FrontendSettings:
        payload = payload or {}
        return cls(
            beautify_bundles=bool(payload.get("beautify_bundles", False)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class OutputSettings:
    enabled: bool = False
    profile: str = "full"
    view_name: str = "operator_view"
    mode: str = "reference"
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    folder_map: dict[str, str] = field(default_factory=dict)
    max_copy_bytes: int = 512 * 1024 * 1024
    analyzer_include: list[str] = field(default_factory=list)
    analyzer_exclude: list[str] = field(default_factory=list)
    max_run_artifact_bytes: int = 0
    max_run_artifact_count: int = 0

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> OutputSettings:
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            profile=str(payload.get("profile", "full") or "full"),
            view_name=str(payload.get("view_name", "operator_view") or "operator_view"),
            mode=str(payload.get("mode", "reference") or "reference"),
            include=_string_list(payload.get("include")),
            exclude=_string_list(payload.get("exclude")),
            folder_map=_string_map(payload.get("folder_map")),
            max_copy_bytes=int(payload.get("max_copy_bytes", 512 * 1024 * 1024) or 512 * 1024 * 1024),
            analyzer_include=_string_list(payload.get("analyzer_include")),
            analyzer_exclude=_string_list(payload.get("analyzer_exclude")),
            max_run_artifact_bytes=max(0, int(payload.get("max_run_artifact_bytes", 0) or 0)),
            max_run_artifact_count=max(0, int(payload.get("max_run_artifact_count", 0) or 0)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _string_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).strip(): str(item).strip() for key, item in value.items() if str(key).strip() and str(item).strip()}


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
