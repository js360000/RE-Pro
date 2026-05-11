from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from ..elf import parse_elf_metadata
from ..models import AnalysisFinding, AnalysisReport, Artifact, PortingSettings, RecoveredSource
from ..recompile import create_recompile_workspace
from ..reporting import write_json_report, write_markdown_report
from ..utils import ensure_dir, parse_pe_metadata, safe_slug
from .base import Analyzer


def generate_architecture_port_from_run(
    run_output_dir: str | Path,
    *,
    source_arch: str = "",
    target_arch: str = "arm64",
    mode: str = "heuristic",
    logger: Callable[[str], None] | None = None,
) -> dict[str, object]:
    run_dir = Path(run_output_dir).resolve()
    report_path = run_dir / "report.json"
    if not report_path.exists():
        raise FileNotFoundError(report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected report JSON object in {report_path}")
    report = _report_from_dict(payload, run_dir=run_dir)
    target_path = Path(report.target)
    pe_metadata = None
    elf_metadata = None
    if target_path.exists() and target_path.is_file():
        pe_metadata = parse_pe_metadata(target_path)
        elf_metadata = parse_elf_metadata(target_path)
    context = SimpleNamespace(
        target=target_path,
        output_dir=run_dir,
        pe_metadata=pe_metadata,
        elf_metadata=elf_metadata,
        fingerprints=report.fingerprints,
        probable_binary=True,
        porting_settings=PortingSettings(
            enabled=True,
            source_arch=source_arch,
            target_arch=target_arch or "arm64",
            mode=mode or "heuristic",
        ),
        log=logger or (lambda _message: None),
    )
    PortingAdvisorAnalyzer().analyze(context, report)
    _dedupe_report(report)
    write_json_report(report, report_path)
    write_markdown_report(report, run_dir / "report.md")
    manifest_path = run_dir / "porting" / "porting_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    return {
        "ok": True,
        "run_output_dir": str(run_dir),
        "report_path": str(report_path),
        "porting_manifest_path": str(manifest_path),
        "architecture_ports": manifest.get("architecture_ports") or [],
    }


class PortingAdvisorAnalyzer(Analyzer):
    name = "Porting preparation"
    MAX_COPIED_SOURCES = 400
    CODE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".rs", ".go", ".zig", ".js", ".ts", ".tsx", ".java", ".kt", ".cs", ".py"}

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

        manifest_path = porting_dir / "porting_manifest.json"
        notes_path = porting_dir / "PORTING_NOTES.md"
        recommendations = self._recommend_platforms(report)
        architecture_ports: list[dict[str, object]] = []
        if self._should_create_architecture_port(context):
            architecture_ports.append(
                self._create_architecture_port(
                    context=context,
                    report=report,
                    prepared_dir=prepared_dir,
                    porting_dir=porting_dir,
                )
            )
        architecture_ports = self._merge_architecture_ports(
            self._load_existing_architecture_ports(manifest_path),
            architecture_ports,
        )
        manifest = {
            "target": report.target,
            "target_type": report.target_type,
            "frameworks": report.frameworks,
            "recovered_source_count": len(report.recovered_sources),
            "copied_recovered_sources": copied_sources,
            "copied_llm_files": copied_llm,
            "recommended_targets": recommendations,
            "architecture_ports": architecture_ports,
            "entrypoint_candidates": self._entrypoint_candidates(report),
            "recompile_workspace": recompile_metadata,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        notes_path.write_text(self._build_notes(report, manifest), encoding="utf-8")

        report.add_artifact(str(manifest_path), "manifest", "Porting readiness manifest")
        report.add_artifact(str(notes_path), "report", "Porting guidance")
        report.add_artifact(str(prepared_dir), "directory", "Prepared sources for porting work")
        report.add_artifact(str(recompile_root), "directory", "Recompile workspace")
        report.add_artifact(str(recompile_root / "workspace_manifest.json"), "manifest", "Recompile workspace manifest")
        for architecture_port in architecture_ports:
            workspace_root = str(architecture_port.get("workspace_root", "")).strip()
            manifest_file = str(architecture_port.get("manifest_path", "")).strip()
            plan_file = str(architecture_port.get("plan_path", "")).strip()
            if workspace_root:
                report.add_artifact(workspace_root, "directory", "Architecture-targeted source port workspace")
            if manifest_file:
                report.add_artifact(manifest_file, "manifest", "Architecture port manifest")
            if plan_file:
                report.add_artifact(plan_file, "report", "Architecture porting plan")
        for template in recompile_metadata.get("project_templates") or []:
            template_path = str(template.get("path", "")).strip()
            template_name = str(template.get("name", "")).strip() or "project template"
            if template_path:
                report.add_artifact(template_path, "directory", f"Project template: {template_name}")
        for key, description in (
            ("rebuild_plan_path", "Rebuild plan"),
            ("signing_plan_path", "Signing plan"),
            ("patch_plan_path", "Patch plan"),
        ):
            path = str(recompile_metadata.get(key, "")).strip()
            if path:
                report.add_artifact(path, "manifest", description)
        report.add_finding(
            "Porting preparation generated",
            "RE-Pro generated a prepared source bundle and platform-porting guidance from the recovered analysis artifacts.",
            severity="info",
        )
        if architecture_ports:
            report.add_finding(
                "Architecture port workspace generated",
                "RE-Pro generated target-architecture source scaffolding, heuristics, and blocker manifests for the requested port.",
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

    @staticmethod
    def _load_existing_architecture_ports(manifest_path: Path) -> list[dict[str, object]]:
        if not manifest_path.exists():
            return []
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(payload, dict):
            return []
        ports = payload.get("architecture_ports") or []
        return [port for port in ports if isinstance(port, dict)]

    @staticmethod
    def _merge_architecture_ports(
        existing_ports: list[dict[str, object]],
        new_ports: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        merged: dict[tuple[str, str, str], dict[str, object]] = {}
        for port in existing_ports + new_ports:
            key = (
                str(port.get("source_arch", "")).strip(),
                str(port.get("target_arch", "")).strip(),
                str(port.get("mode", "")).strip(),
            )
            if not any(key):
                continue
            merged[key] = port
        return list(merged.values())

    @staticmethod
    def _should_create_architecture_port(context) -> bool:
        settings = getattr(context, "porting_settings", None)
        if settings is None:
            return False
        return bool(settings.enabled or settings.target_arch)

    def _create_architecture_port(self, *, context, report, prepared_dir: Path, porting_dir: Path) -> dict[str, object]:
        settings = context.porting_settings
        source_arch = self._normalize_arch(settings.source_arch or self._infer_source_arch(context))
        target_arch = self._normalize_arch(settings.target_arch or "arm64")
        port_slug = safe_slug(f"{source_arch or 'unknown'}_to_{target_arch}")
        workspace_root = ensure_dir(porting_dir / "architecture_ports" / port_slug)
        source_root = ensure_dir(workspace_root / "source")
        include_root = ensure_dir(workspace_root / "include")
        copied_files = self._copy_directory(prepared_dir, source_root)
        blockers = self._scan_architecture_blockers(source_root)
        blocker_summary = self._summarize_blockers(blockers)
        source_inventory = self._source_inventory(source_root)
        transformations = self._architecture_transformations(source_arch, target_arch)
        header_path = include_root / "repro_arch_port.h"
        header_path.write_text(self._build_arch_header(source_arch, target_arch), encoding="utf-8")
        cmake_presets_path = workspace_root / "CMakePresets.json"
        cmake_presets_path.write_text(json.dumps(self._build_cmake_presets(target_arch), indent=2), encoding="utf-8")
        manifest_path = workspace_root / "ARCH_PORT_MANIFEST.json"
        plan_path = workspace_root / "ARCHITECTURE_PORTING_PLAN.md"
        manifest = {
            "source_arch": source_arch,
            "target_arch": target_arch,
            "mode": settings.mode,
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "copied_files": copied_files,
            "source_inventory": source_inventory,
            "heuristic_transformations": transformations,
            "blockers": blockers,
            "blocker_summary": blocker_summary,
            "llm_recommended": settings.mode in {"llm", "hybrid"} or bool(target_arch),
            "notes": [
                "This workspace is source-level porting scaffolding, not a binary translator.",
                "Prefer recovered original source names and LLM/RTTI-derived names over anonymous decompiler labels.",
            ],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        plan_path.write_text(self._build_architecture_plan(report, manifest), encoding="utf-8")
        context.log(f"Prepared architecture port workspace: {workspace_root}")
        return {
            "source_arch": source_arch,
            "target_arch": target_arch,
            "mode": settings.mode,
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "manifest_path": str(manifest_path),
            "plan_path": str(plan_path),
            "blocker_count": len(blockers),
            "copied_files": copied_files,
        }

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

    @classmethod
    def _scan_architecture_blockers(cls, source_root: Path) -> list[dict[str, str]]:
        blockers: list[dict[str, str]] = []
        checks = [
            ("inline_assembly", ["__asm", "asm(", "asm volatile", "__emit"], "Rewrite as portable code or target-specific intrinsics."),
            ("x86_simd_intrinsics", ["<immintrin.h>", "<xmmintrin.h>", "<emmintrin.h>", "__m128", "__m256", "__m512", "_mm_"], "Replace with portable SIMD, ARM NEON, or scalar fallback."),
            ("x86_register_or_calling_convention", ["__fastcall", "__thiscall", "__vectorcall", "EAX", "EBX", "ECX", "EDX", "RAX", "RCX", "RDX", "RSP", "RBP"], "Re-express ABI details through normal function signatures."),
            ("pointer_width_or_abi", ["DWORD_PTR", "LONG_PTR", "ULONG_PTR", "uintptr_t", "intptr_t", "size_t", "ptrdiff_t"], "Audit all casts, serialization, and structure layouts for target pointer width."),
            ("win32_platform_api", ["#include <windows.h>", "LoadLibrary", "GetProcAddress", "VirtualAlloc", "CreateFile", "RegOpenKey", "CoCreateInstance"], "Isolate OS APIs behind a platform adapter before porting."),
            ("unaligned_or_endian_sensitive_access", ["reinterpret_cast<", "*(uint", "memcpy(", "byteorder", "bswap", "_byteswap"], "Verify alignment and endian behavior on the target architecture."),
        ]
        for path in source_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in cls.CODE_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
            except OSError:
                continue
            lowered = text.lower()
            for kind, markers, recommendation in checks:
                matched = ""
                for marker in markers:
                    if marker.lower() in lowered:
                        matched = marker
                        break
                if matched:
                    blockers.append(
                        {
                            "file": str(path),
                            "kind": kind,
                            "evidence": matched,
                            "recommendation": recommendation,
                        }
                    )
        return blockers[:512]

    @classmethod
    def _source_inventory(cls, source_root: Path) -> dict[str, object]:
        by_extension: dict[str, int] = {}
        total_files = 0
        code_files = 0
        for path in source_root.rglob("*"):
            if not path.is_file():
                continue
            total_files += 1
            extension = path.suffix.lower() or "<none>"
            by_extension[extension] = by_extension.get(extension, 0) + 1
            if path.suffix.lower() in cls.CODE_SUFFIXES:
                code_files += 1
        return {
            "total_files": total_files,
            "code_files": code_files,
            "by_extension": dict(sorted(by_extension.items())),
        }

    @staticmethod
    def _summarize_blockers(blockers: list[dict[str, str]]) -> dict[str, object]:
        by_kind: dict[str, int] = {}
        file_counts: dict[str, dict[str, object]] = {}
        for blocker in blockers:
            kind = str(blocker.get("kind", "unknown"))
            file_path = str(blocker.get("file", ""))
            by_kind[kind] = by_kind.get(kind, 0) + 1
            entry = file_counts.setdefault(file_path, {"file": file_path, "count": 0, "kinds": set()})
            entry["count"] = int(entry["count"]) + 1
            cast_kinds = entry["kinds"]
            if isinstance(cast_kinds, set):
                cast_kinds.add(kind)
        top_files = sorted(file_counts.values(), key=lambda item: int(item["count"]), reverse=True)[:25]
        normalized_top_files = [
            {
                "file": str(item["file"]),
                "count": int(item["count"]),
                "kinds": sorted(str(kind) for kind in item["kinds"]) if isinstance(item["kinds"], set) else [],
            }
            for item in top_files
        ]
        return {
            "total": len(blockers),
            "by_kind": dict(sorted(by_kind.items())),
            "top_files": normalized_top_files,
        }

    @staticmethod
    def _infer_source_arch(context) -> str:
        pe_metadata = context.pe_metadata or {}
        machine = str(pe_metadata.get("machine", "") or pe_metadata.get("machine_type", "")).lower()
        if machine:
            if "amd64" in machine or "x64" in machine or "8664" in machine:
                return "x86_64"
            if "i386" in machine or "x86" in machine or "14c" in machine:
                return "x86"
            if "arm64" in machine or "aa64" in machine:
                return "arm64"
            if "arm" in machine:
                return "arm"
        elf_metadata = context.elf_metadata or {}
        elf_machine = str(elf_metadata.get("machine", "")).lower()
        if "x86-64" in elf_machine or "amd64" in elf_machine:
            return "x86_64"
        if "aarch64" in elf_machine or "arm64" in elf_machine:
            return "arm64"
        if "80386" in elf_machine or "i386" in elf_machine:
            return "x86"
        fingerprints = getattr(context, "fingerprints", {}) or {}
        fingerprint_machine = str(fingerprints.get("machine", "") or fingerprints.get("arch", "")).lower()
        if "x64" in fingerprint_machine or "amd64" in fingerprint_machine or "x86_64" in fingerprint_machine:
            return "x86_64"
        if "arm64" in fingerprint_machine or "aarch64" in fingerprint_machine:
            return "arm64"
        if "x86" in fingerprint_machine or "i386" in fingerprint_machine:
            return "x86"
        return "unknown"

    @staticmethod
    def _normalize_arch(value: str) -> str:
        normalized = str(value or "").strip().lower().replace("-", "_")
        aliases = {
            "amd64": "x86_64",
            "x64": "x86_64",
            "x86_64": "x86_64",
            "i386": "x86",
            "i686": "x86",
            "aarch64": "arm64",
            "armv8": "arm64",
            "arm64": "arm64",
        }
        return aliases.get(normalized, normalized or "unknown")

    @staticmethod
    def _architecture_transformations(source_arch: str, target_arch: str) -> list[dict[str, str]]:
        transformations = [
            {
                "area": "calling_conventions",
                "action": "Normalize decompiler output to ordinary typed function signatures before mapping target ABI.",
            },
            {
                "area": "data_layout",
                "action": "Keep recovered field offsets as comments and revalidate packing/alignment under the target compiler.",
            },
            {
                "area": "os_services",
                "action": "Move platform APIs behind adapters so Windows/Linux/macOS and CPU differences do not leak into app logic.",
            },
        ]
        if source_arch.startswith("x86") and target_arch == "arm64":
            transformations.extend(
                [
                    {
                        "area": "simd",
                        "action": "Map SSE/AVX intrinsics to ARM NEON equivalents only when semantics are explicit; otherwise emit scalar reference code first.",
                    },
                    {
                        "area": "memory_ordering",
                        "action": "Audit lock-free code, atomics, and volatile memory patterns because ARM64 is less strongly ordered than x86/x64.",
                    },
                    {
                        "area": "inline_assembly",
                        "action": "Replace inline x86/x64 assembly with portable C/C++ or target-specific ARM64 shims isolated under include/repro_arch_port.h.",
                    },
                ]
            )
        return transformations

    @staticmethod
    def _build_arch_header(source_arch: str, target_arch: str) -> str:
        macro_arch = target_arch.upper().replace("-", "_")
        return "\n".join(
            [
                "#pragma once",
                "",
                "/* Generated by RE-Pro architecture-port scaffolding. */",
                f"/* Source architecture: {source_arch}; target architecture: {target_arch}. */",
                "",
                f"#define REPRO_SOURCE_ARCH_{source_arch.upper().replace('-', '_')} 1",
                f"#define REPRO_TARGET_ARCH_{macro_arch} 1",
                "",
                "#if defined(__aarch64__) || defined(_M_ARM64)",
                "#define REPRO_HOST_IS_ARM64 1",
                "#endif",
                "",
                "#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)",
                "#define REPRO_HOST_IS_X86_FAMILY 1",
                "#endif",
                "",
                "/* Add target-specific adapters here only after preserving a portable reference implementation. */",
                "",
            ]
        )

    @staticmethod
    def _build_cmake_presets(target_arch: str) -> dict[str, object]:
        architecture = "arm64" if target_arch == "arm64" else target_arch
        return {
            "version": 6,
            "configurePresets": [
                {
                    "name": f"{target_arch}-port",
                    "displayName": f"RE-Pro {target_arch} source port",
                    "generator": "Ninja",
                    "binaryDir": "${sourceDir}/build/${presetName}",
                    "cacheVariables": {
                        "CMAKE_BUILD_TYPE": "RelWithDebInfo",
                        "CMAKE_SYSTEM_PROCESSOR": architecture,
                    },
                }
            ],
        }

    @staticmethod
    def _build_architecture_plan(report, manifest: dict[str, object]) -> str:
        lines = [
            "# Architecture Porting Plan",
            "",
            f"- Target binary: `{report.target}`",
            f"- Source architecture: `{manifest['source_arch']}`",
            f"- Target architecture: `{manifest['target_arch']}`",
            f"- Mode: `{manifest['mode']}`",
            f"- Source workspace: `{manifest['source_root']}`",
            f"- Copied files: {manifest['copied_files']}",
            "",
            "## Source Inventory",
            "",
        ]
        inventory = manifest.get("source_inventory") or {}
        lines.extend(
            [
                f"- Total files: {inventory.get('total_files', 0)}",
                f"- Code files: {inventory.get('code_files', 0)}",
            ]
        )
        by_extension = inventory.get("by_extension") or {}
        if by_extension:
            lines.append("- File extensions: " + ", ".join(f"{extension}={count}" for extension, count in by_extension.items()))
        lines.extend(
            [
                "",
                "## Required Rewrite Order",
                "",
                "1. Stabilize source names from recovered symbols, RTTI, vtables, debug paths, and LLM naming hints.",
                "2. Convert decompiler artifacts into normal typed source before adding target-architecture conditionals.",
                "3. Replace x86/x64 ABI, register, inline assembly, SIMD, and pointer-width assumptions with portable reference code.",
                "4. Add target-specific adapters only after the portable implementation is clear and testable.",
                "5. Build with target compiler warnings enabled and use recovered behavior/tests as regression checks.",
                "",
                "## Heuristic Transformations",
                "",
            ]
        )
        for item in manifest.get("heuristic_transformations") or []:
            lines.append(f"- `{item['area']}`: {item['action']}")
        blockers = manifest.get("blockers") or []
        lines.extend(["", "## Architecture Blockers", ""])
        blocker_summary = manifest.get("blocker_summary") or {}
        by_kind_summary = blocker_summary.get("by_kind") or {}
        if by_kind_summary:
            lines.append("Summary by kind: " + ", ".join(f"{kind}={count}" for kind, count in by_kind_summary.items()))
            lines.append("")
        top_files = blocker_summary.get("top_files") or []
        if top_files:
            lines.append("Hotspot files:")
            for item in top_files[:10]:
                lines.append(f"- `{item.get('file')}`: {item.get('count')} blocker(s), kinds={', '.join(item.get('kinds') or [])}")
            lines.append("")
        if blockers:
            for blocker in blockers[:80]:
                lines.append(
                    f"- `{blocker['kind']}` in `{blocker['file']}` via `{blocker['evidence']}`: {blocker['recommendation']}"
                )
        else:
            lines.append("- No obvious architecture-specific blockers were found in the copied source bundle.")
        lines.extend(
            [
                "",
                "## LLM Assistance Guidance",
                "",
                "- Ask the LLM to rewrite one recovered class/module at a time, preserving file/function/class names from the analysis index.",
                "- Require evidence references for every renamed function or generated module.",
                "- For x86_64 to arm64, ask for portable source first, then NEON/ARM64 adapters only for hot or intrinsically vectorized paths.",
            ]
        )
        return "\n".join(lines) + "\n"

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
        lines.append("- Use the generated project templates and rebuild/signing manifests under `recompile/` as the first build-oriented starting point.")
        if manifest["entrypoint_candidates"]:
            lines.extend(["", "## Entrypoint Candidates", ""])
            lines.extend(f"- `{candidate}`" for candidate in manifest["entrypoint_candidates"])
        architecture_ports = manifest.get("architecture_ports") or []
        if architecture_ports:
            lines.extend(["", "## Architecture Ports", ""])
            for architecture_port in architecture_ports:
                lines.append(
                    f"- `{architecture_port.get('source_arch')}` -> `{architecture_port.get('target_arch')}` "
                    f"({architecture_port.get('mode')}): `{architecture_port.get('workspace_root')}`; "
                    f"blockers={architecture_port.get('blocker_count')}"
                )
        workspace = manifest.get("recompile_workspace") or {}
        templates = workspace.get("project_templates") or []
        if templates:
            lines.extend(["", "## Project Templates", ""])
            for template in templates:
                lines.append(f"- `{template.get('name')}` -> `{template.get('path')}`")
        return "\n".join(lines) + "\n"


def _report_from_dict(payload: dict[str, object], *, run_dir: Path) -> AnalysisReport:
    report = AnalysisReport(
        target=str(payload.get("target", "")),
        target_type=str(payload.get("target_type", "unknown") or "unknown"),
        output_dir=str(payload.get("output_dir") or run_dir),
        fingerprints=dict(payload.get("fingerprints") or {}),
        frameworks=[str(item) for item in (payload.get("frameworks") or [])],
        notes=[str(item) for item in (payload.get("notes") or [])],
    )
    report.findings = [
        AnalysisFinding(
            title=str(item.get("title", "")),
            summary=str(item.get("summary", "")),
            severity=str(item.get("severity", "info") or "info"),
            details=item.get("details"),
        )
        for item in (payload.get("findings") or [])
        if isinstance(item, dict)
    ]
    report.artifacts = [
        Artifact(
            path=str(item.get("path", "")),
            category=str(item.get("category", "")),
            description=str(item.get("description", "")),
        )
        for item in (payload.get("artifacts") or [])
        if isinstance(item, dict)
    ]
    report.recovered_sources = [
        RecoveredSource(
            original_path=str(item.get("original_path", "")),
            restored_path=str(item.get("restored_path", "")),
            source_map=str(item.get("source_map", "")),
        )
        for item in (payload.get("recovered_sources") or [])
        if isinstance(item, dict)
    ]
    return report


def _dedupe_report(report: AnalysisReport) -> None:
    seen_artifacts: set[tuple[str, str, str]] = set()
    artifacts: list[Artifact] = []
    for artifact in report.artifacts:
        key = (artifact.path, artifact.category, artifact.description)
        if key in seen_artifacts:
            continue
        seen_artifacts.add(key)
        artifacts.append(artifact)
    report.artifacts = artifacts

    seen_findings: set[tuple[str, str, str, str]] = set()
    findings: list[AnalysisFinding] = []
    for finding in report.findings:
        key = (finding.title, finding.summary, finding.severity, finding.details or "")
        if key in seen_findings:
            continue
        seen_findings.add(key)
        findings.append(finding)
    report.findings = findings

    seen_notes: set[str] = set()
    notes: list[str] = []
    for note in report.notes:
        if note in seen_notes:
            continue
        seen_notes.add(note)
        notes.append(note)
    report.notes = notes
