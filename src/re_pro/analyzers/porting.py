from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..recompile import create_recompile_workspace
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class PortingAdvisorAnalyzer(Analyzer):
    name = "Porting preparation"
    MAX_COPIED_SOURCES = 400

    def analyze(self, context, report) -> None:
        if not self._should_prepare(context, report):
            return
        porting_dir = ensure_dir(context.output_dir / "porting")
        prepared_dir = ensure_dir(porting_dir / "prepared_sources")
        llm_dir = context.output_dir / "llm_assist" / "reconstructed_src"

        copied_sources = self._copy_recovered_sources(report, prepared_dir / "recovered_sources")
        copied_llm = self._copy_directory(llm_dir, prepared_dir / "llm_reconstruction") if llm_dir.exists() else 0
        self._copy_key_manifests(report, prepared_dir / "manifests")
        recompile_metadata = create_recompile_workspace(porting_dir, report.to_dict(), report.frameworks)
        recompile_root = Path(recompile_metadata["workspace_root"])
        recompile_src = Path(recompile_metadata["source_root"])
        self._copy_directory(prepared_dir, recompile_src)

        recommendations = self._recommend_platforms(report)
        manifest = {
            "target": report.target,
            "target_type": report.target_type,
            "frameworks": report.frameworks,
            "recovered_source_count": len(report.recovered_sources),
            "copied_recovered_sources": copied_sources,
            "copied_llm_files": copied_llm,
            "recommended_targets": recommendations,
            "entrypoint_candidates": self._entrypoint_candidates(report),
            "recompile_workspace": recompile_metadata,
        }
        manifest_path = porting_dir / "porting_manifest.json"
        notes_path = porting_dir / "PORTING_NOTES.md"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        notes_path.write_text(self._build_notes(report, manifest), encoding="utf-8")

        report.add_artifact(str(manifest_path), "manifest", "Porting readiness manifest")
        report.add_artifact(str(notes_path), "report", "Porting guidance")
        report.add_artifact(str(prepared_dir), "directory", "Prepared sources for porting work")
        report.add_artifact(str(recompile_root), "directory", "Recompile workspace")
        report.add_artifact(str(recompile_root / "workspace_manifest.json"), "manifest", "Recompile workspace manifest")
        report.add_finding(
            "Porting preparation generated",
            "RE-Pro generated a prepared source bundle and platform-porting guidance from the recovered analysis artifacts.",
            severity="info",
        )

    @staticmethod
    def _should_prepare(context, report) -> bool:
        if report.recovered_sources:
            return True
        if any(artifact.category == "manifest" for artifact in report.artifacts):
            return True
        if report.frameworks:
            return True
        return context.probable_binary

    def _copy_recovered_sources(self, report, destination_root: Path) -> int:
        ensure_dir(destination_root)
        copied = 0
        for source in report.recovered_sources[: self.MAX_COPIED_SOURCES]:
            source_path = Path(source.restored_path)
            if not source_path.exists() or not source_path.is_file():
                continue
            relative = safe_slug(Path(source.original_path).name)
            target = destination_root / relative
            if not target.suffix:
                target = target.with_suffix(source_path.suffix)
            if target.exists():
                target = destination_root / f"{target.stem}_{copied}{target.suffix}"
            ensure_dir(target.parent)
            shutil.copy2(source_path, target)
            copied += 1
        return copied

    @staticmethod
    def _copy_directory(source: Path, destination: Path) -> int:
        ensure_dir(destination)
        copied = 0
        for file_path in source.rglob("*"):
            if not file_path.is_file():
                continue
            relative = file_path.relative_to(source)
            target = destination / relative
            ensure_dir(target.parent)
            shutil.copy2(file_path, target)
            copied += 1
        return copied

    @staticmethod
    def _copy_key_manifests(report, destination: Path) -> None:
        ensure_dir(destination)
        for artifact in report.artifacts:
            if artifact.category != "manifest":
                continue
            path = Path(artifact.path)
            if not path.exists() or not path.is_file():
                continue
            target = destination / path.name
            if target.exists():
                target = destination / f"{target.stem}_{safe_slug(artifact.description)}{target.suffix}"
            shutil.copy2(path, target)

    @staticmethod
    def _recommend_platforms(report) -> list[dict[str, object]]:
        frameworks = {framework.lower() for framework in report.frameworks}
        recommendations: list[dict[str, object]] = []
        if any("electron" in framework for framework in frameworks):
            recommendations.append(
                {
                    "target": "Windows/macOS/Linux desktop",
                    "confidence": 0.95,
                    "strategy": "Reuse recovered Electron/Node source and rebuild packaging layers per platform.",
                }
            )
        if any("react native" in framework for framework in frameworks):
            recommendations.append(
                {
                    "target": "Android and iOS/mobile web",
                    "confidence": 0.8,
                    "strategy": "Recover JS/TS app logic first, then replace native bridges and platform modules incrementally.",
                }
            )
        if any("flutter" in framework for framework in frameworks):
            recommendations.append(
                {
                    "target": "Android/iOS/desktop/web",
                    "confidence": 0.75,
                    "strategy": "Prioritize Dart recovery or UI flow reconstruction, then recreate plugin bindings per platform.",
                }
            )
        if any("qt" in framework for framework in frameworks):
            recommendations.append(
                {
                    "target": "Windows/macOS/Linux desktop",
                    "confidence": 0.7,
                    "strategy": "Preserve Qt UI/resource structure and reimplement platform-specific services around it.",
                }
            )
        if any(marker in framework for framework in frameworks for marker in ("tauri", "web framework", "vite", "webpack")):
            recommendations.append(
                {
                    "target": "Cross-platform desktop/web",
                    "confidence": 0.85,
                    "strategy": "Treat recovered web frontend as portable and isolate native host, updater, and sidecar dependencies.",
                }
            )
        if not recommendations:
            recommendations.append(
                {
                    "target": "Manual portability assessment required",
                    "confidence": 0.35,
                    "strategy": "Use recovered strings, manifests, and reconstructed files to identify platform APIs before rewriting entrypoints.",
                }
            )
        return recommendations

    @staticmethod
    def _entrypoint_candidates(report) -> list[str]:
        candidates: list[str] = []
        for source in report.recovered_sources:
            name = Path(source.restored_path).name.lower()
            if name.startswith(("main", "app", "index", "bootstrap")) or "entry" in name:
                candidates.append(source.restored_path)
        return candidates[:20]

    @staticmethod
    def _build_notes(report, manifest: dict[str, object]) -> str:
        lines = [
            "# Porting Notes",
            "",
            f"- Target: `{report.target}`",
            f"- Type: `{report.target_type}`",
            f"- Frameworks: {', '.join(report.frameworks) or 'None'}",
            f"- Recovered sources: {len(report.recovered_sources)}",
            f"- Copied recovered sources: {manifest['copied_recovered_sources']}",
            f"- Copied LLM reconstructions: {manifest['copied_llm_files']}",
            "",
            "## Recommended Targets",
            "",
        ]
        for recommendation in manifest["recommended_targets"]:
            lines.append(
                f"- {recommendation['target']} (confidence {recommendation['confidence']}): {recommendation['strategy']}"
            )
        lines.extend(["", "## Porting Workflow", ""])
        lines.append("- Start from `prepared_sources/` to avoid re-triaging the full analysis tree.")
        lines.append("- Prefer recovered original sources over reconstructed LLM files when both exist.")
        lines.append("- Treat updater integrations, IPC, filesystem paths, OS credential storage, and native plugins as the first portability blockers.")
        if manifest["entrypoint_candidates"]:
            lines.extend(["", "## Entrypoint Candidates", ""])
            lines.extend(f"- `{candidate}`" for candidate in manifest["entrypoint_candidates"])
        return "\n".join(lines) + "\n"
