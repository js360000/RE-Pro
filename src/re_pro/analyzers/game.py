from __future__ import annotations

import json
from pathlib import Path

from ..ddl import (
    index_ddl_results,
    looks_like_ddl,
    parse_ddl_from_file,
    write_ddl_manifest,
    write_ddl_struct_sources,
)
from ..gdeflate import NVCOMP_PYTHON_PACKAGE, nvcomp_available, try_decompress_file
from ..utils import ensure_dir
from .base import Analyzer


class GameNativeAnalyzer(Analyzer):
    name = "Game/UI heuristics"
    GRAPHICS_SIGNATURES = {
        "Direct3D 9": {
            "imports": {"d3d9.dll"},
            "strings": ("direct3dcreate9", "imgui_impl_dx9", "direct3d 9"),
        },
        "Direct3D 11": {
            "imports": {"d3d11.dll", "d3dcompiler_47.dll", "d3dcompiler_43.dll"},
            "strings": ("d3d11createdevice", "imgui_impl_dx11", "direct3d 11"),
        },
        "Direct3D 12": {
            "imports": {"d3d12.dll"},
            "strings": ("d3d12createdevice", "imgui_impl_dx12", "direct3d 12"),
        },
        "DXGI": {
            "imports": {"dxgi.dll"},
            "strings": ("createdxgifactory", "createdxgifactory2"),
        },
        "Vulkan": {
            "imports": {"vulkan-1.dll"},
            "strings": ("vkcreateinstance", "vkcreateswapchainkhr", "imgui_impl_vulkan"),
        },
        "OpenGL": {
            "imports": {"opengl32.dll"},
            "strings": ("wglcreatecontext", "imgui_impl_opengl3", "imgui_impl_opengl2"),
        },
        "SDL2": {
            "imports": {"sdl2.dll"},
            "strings": ("sdl_init", "sdl_gamecontrolleropen", "imgui_impl_sdl2"),
            "siblings": ("sdl2.dll",),
        },
        "SDL3": {
            "imports": {"sdl3.dll"},
            "strings": ("sdl_init", "sdl_getcurrentvideo_driver", "imgui_impl_sdl3"),
            "siblings": ("sdl3.dll",),
        },
        "GLFW": {
            "strings": ("glfwinit", "glfwcreatewindow", "imgui_impl_glfw"),
            "siblings": ("glfw3.dll",),
        },
        "DirectStorage": {
            "imports": {"dstorage.dll", "dstoragecore.dll"},
            "strings": ("directstorage", "dstorage.dll", "dstoragecore.dll"),
            "siblings": ("dstorage.dll", "dstoragecore.dll"),
        },
    }
    MIDDLEWARE_SIGNATURES = {
        "Dear ImGui": {
            "strings": (
                "dear imgui",
                "imgui_impl_",
                "imguicontext",
                "imguidrawdata",
                "imdrawlist",
                "imguiwindow",
                "imguiviewport",
                "imguistyle",
            ),
        },
        "Steamworks": {
            "imports": {"steam_api64.dll", "steam_api.dll"},
            "strings": ("steam_api64.dll", "steam_api.dll", "steamapps", "isteamuser"),
            "siblings": ("steam_api64.dll", "steam_api.dll"),
        },
        "FMOD": {
            "imports": {"fmod.dll", "fmod64.dll", "fmodstudio.dll", "fmodstudio64.dll"},
            "strings": ("fmod_system_create", "fmod studio", "fmod::system"),
            "siblings": ("fmod.dll", "fmod64.dll", "fmodstudio.dll", "fmodstudio64.dll"),
        },
        "Bink": {
            "imports": {"bink2w64.dll", "binkw64.dll"},
            "strings": ("bink2", "binkopen", "binkcopytobuffer"),
            "siblings": ("bink2w64.dll", "binkw64.dll"),
        },
        "NVIDIA GDeflate": {
            "strings": ("gdeflate", "nvcomp", "rtx io"),
            "imports": {"dstorage.dll", "dstoragecore.dll"},
        },
    }
    GDEFLATE_SUFFIXES = {".gdeflate", ".gdf"}
    GDEFLATE_NAME_MARKERS = ("gdeflate", ".gdf")
    GDEFLATE_SCAN_DIRS = ("data", "assets", "content", "pak", "paks")
    MAX_GDEFLATE_CANDIDATES = 16
    DDL_SCAN_DIRS = ("data", "assets", "content", "pak", "paks", "schema", "schemas", "ddl", "config")
    MAX_DDL_CANDIDATES = 64

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or (not context.probable_binary and context.pe_metadata is None):
            return

        strings_lower = [value.lower() for value in context.ascii_strings]
        imports_lower = {value.lower() for value in context.pe_imports}
        sibling_names = (
            {path.name.lower() for path in context.target.parent.iterdir()}
            if context.target.parent.exists()
            else set()
        )

        stack_hits: list[str] = []
        for framework, signature in self.GRAPHICS_SIGNATURES.items():
            if self._matches(signature, strings_lower, imports_lower, sibling_names):
                report.add_framework(framework)
                stack_hits.append(framework)

        middleware_hits: list[str] = []
        for framework, signature in self.MIDDLEWARE_SIGNATURES.items():
            if self._matches(signature, strings_lower, imports_lower, sibling_names):
                report.add_framework(framework)
                middleware_hits.append(framework)

        if stack_hits or middleware_hits:
            summary = ", ".join(stack_hits + middleware_hits[:4])
            report.add_finding(
                "Native graphics/game stack detected",
                "The executable exposes graphics, UI, or game middleware markers that can guide deeper reverse-engineering and porting work.",
                severity="info",
                details=summary,
            )
            report.add_note(f"Detected game/UI stack markers: {summary}.")

        decompressed_assets = self._attempt_gdeflate_recovery(context, report, stack_hits, middleware_hits)
        self._attempt_ddl_recovery(context, report, decompressed_assets)

    @staticmethod
    def _matches(
        signature: dict[str, object],
        strings_lower: list[str],
        imports_lower: set[str],
        sibling_names: set[str],
    ) -> bool:
        import_hits = any(value in imports_lower for value in signature.get("imports", set()))
        sibling_hits = any(value in sibling_names for value in signature.get("siblings", ()))
        string_hits = any(marker in value for value in strings_lower for marker in signature.get("strings", ()))
        return import_hits or sibling_hits or string_hits

    def _attempt_gdeflate_recovery(self, context, report, stack_hits: list[str], middleware_hits: list[str]) -> list[Path]:
        candidates = self._find_gdeflate_candidates(context.target.parent)
        if not candidates:
            if "NVIDIA GDeflate" in middleware_hits or "DirectStorage" in stack_hits:
                report.add_note("DirectStorage or GDeflate markers were detected, but no nearby GDeflate-named asset files were found to probe.")
            return []

        report.add_note(f"Found {len(candidates)} nearby GDeflate candidate files for extraction probes.")
        available, version = nvcomp_available()
        if not available:
            report.add_note(
                "Install the NVIDIA nvCOMP Python package "
                f"(`pip install {NVCOMP_PYTHON_PACKAGE}`) on a CUDA-capable system to enable automatic GDeflate extraction."
            )
            return []

        output_dir = ensure_dir(context.output_dir / "gdeflate")
        success_count = 0
        decompressed_assets: list[Path] = []
        for candidate in candidates:
            relative_name = candidate.relative_to(context.target.parent)
            destination = output_dir / relative_name.parent / f"{relative_name.name}.decompressed.bin"
            success, message = try_decompress_file(candidate, destination)
            if success and destination.exists():
                success_count += 1
                decompressed_assets.append(destination)
                report.add_artifact(str(destination), "binary", f"GDeflate-decompressed asset from {candidate.name}")
                context.log(f"GDeflate decoded {candidate} to {destination}")
            else:
                report.add_note(f"GDeflate probe failed for {candidate.name}: {message}")

        if success_count:
            report.add_finding(
                "GDeflate assets recovered",
                "The analysis recovered one or more GDeflate-compressed assets with NVIDIA nvCOMP.",
                severity="info",
                details=f"Recovered {success_count} assets with nvCOMP {version}.",
            )
            report.add_framework("NVIDIA GDeflate")
        return decompressed_assets

    def _attempt_ddl_recovery(self, context, report, extra_candidates: list[Path] | None = None) -> None:
        candidates = self._find_ddl_candidates(context.target.parent)
        seen = {candidate.resolve() for candidate in candidates if candidate.exists()}
        for candidate in extra_candidates or []:
            if candidate.exists() and candidate.resolve() not in seen:
                candidates.append(candidate)
                seen.add(candidate.resolve())
        if not candidates:
            return

        parsed_results: list[dict[str, object]] = []
        generated_sources: list[Path] = []
        source_dir = ensure_dir(context.output_dir / "ddl" / "recovered_structs")
        for candidate in candidates:
            parsed = parse_ddl_from_file(candidate)
            if not parsed.get("ok"):
                continue
            parsed_results.append(parsed)
            prefix = candidate.stem if candidate.parent != context.output_dir else ""
            generated_sources.extend(write_ddl_struct_sources(parsed, source_dir, prefix=prefix))

        if not parsed_results:
            return

        manifest_path = write_ddl_manifest(parsed_results, context.output_dir / "ddl" / "ddl_structs.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        summary = manifest.get("summary") or {}
        report.add_framework("Game DDL schemas")
        report.add_artifact(str(manifest_path), "manifest", "Recovered game DDL struct manifest")
        if generated_sources:
            report.add_artifact(str(source_dir), "source", "Recovered game DDL struct pseudo-source")
            for source_path in generated_sources:
                report.add_recovered_source(
                    f"ddl/{source_path.name}",
                    str(source_path),
                    str(manifest_path),
                )
        report.add_finding(
            "Game DDL structs recovered",
            "The analysis recovered game data-definition structs from sidecar assets or GDeflate-expanded payloads.",
            severity="info",
            details=(
                f"sources={summary.get('source_count', len(parsed_results))}; "
                f"structs={summary.get('struct_count', 0)}; "
                f"fields={summary.get('field_count', 0)}; "
                f"enums={summary.get('enum_count', 0)}"
            ),
        )
        report.add_note(
            "Recovered DDL schemas were rendered as pseudo C++ headers so class/data layouts can feed porting and source reconstruction."
        )
        index_ddl_results(
            context.analysis_index,
            target_path=str(context.target),
            manifest_path=manifest_path,
            results=parsed_results,
        )

    def _find_gdeflate_candidates(self, root: Path) -> list[Path]:
        candidates: list[Path] = []
        seen: set[Path] = set()
        if root.exists():
            for candidate in root.iterdir():
                if len(candidates) >= self.MAX_GDEFLATE_CANDIDATES:
                    return candidates
                if not candidate.is_file():
                    continue
                if self._is_gdeflate_candidate(candidate):
                    candidates.append(candidate)
                    seen.add(candidate)
        for subdir in self.GDEFLATE_SCAN_DIRS:
            base = root / subdir if subdir else root
            if not base.exists() or not base.is_dir():
                continue
            for candidate in base.rglob("*"):
                if len(candidates) >= self.MAX_GDEFLATE_CANDIDATES:
                    return candidates
                if not candidate.is_file() or candidate in seen:
                    continue
                if self._is_gdeflate_candidate(candidate):
                    candidates.append(candidate)
                    seen.add(candidate)
        return candidates

    def _is_gdeflate_candidate(self, candidate: Path) -> bool:
        name = candidate.name.lower()
        suffix = candidate.suffix.lower()
        return suffix in self.GDEFLATE_SUFFIXES or any(marker in name for marker in self.GDEFLATE_NAME_MARKERS)

    def _find_ddl_candidates(self, root: Path) -> list[Path]:
        candidates: list[Path] = []
        seen: set[Path] = set()
        if root.exists():
            for candidate in root.iterdir():
                if len(candidates) >= self.MAX_DDL_CANDIDATES:
                    return candidates
                if candidate.is_file() and self._is_ddl_candidate(candidate):
                    candidates.append(candidate)
                    seen.add(candidate)
        for subdir in self.DDL_SCAN_DIRS:
            base = root / subdir
            if not base.exists() or not base.is_dir():
                continue
            for candidate in base.rglob("*"):
                if len(candidates) >= self.MAX_DDL_CANDIDATES:
                    return candidates
                if not candidate.is_file() or candidate in seen:
                    continue
                if self._is_ddl_candidate(candidate):
                    candidates.append(candidate)
                    seen.add(candidate)
        return candidates

    @staticmethod
    def _is_ddl_candidate(candidate: Path) -> bool:
        try:
            head = candidate.read_bytes()[:512_000]
        except OSError:
            return False
        return looks_like_ddl(candidate, head)
