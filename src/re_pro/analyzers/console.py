from __future__ import annotations

import json
from pathlib import Path

from ..console_formats import detect_console_formats
from ..psarc import PsarcFormatError, extract_psarc, parse_psarc
from ..psp import PspFormatError, extract_pbp, parse_data_psar, parse_data_psp, parse_param_sfo_file, parse_pbp
from ..psp_tools import attempt_psp_tooling, write_psp_tool_manifest
from ..sce_decrypt import attempt_sce_unpack, write_sce_unpack_manifest
from ..utils import ensure_dir
from .base import Analyzer


class ConsoleFormatAnalyzer(Analyzer):
    name = "Console binary/archive formats"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return
        detections = detect_console_formats(
            context.target,
            context.binary_head,
            elf_metadata=getattr(context, "elf_metadata", None),
        )
        if not detections:
            return

        console_dir = ensure_dir(context.output_dir / "console")
        manifest_path = console_dir / "console_formats.json"
        manifest = {
            "target": str(context.target),
            "detections": detections,
            "summary": {
                "count": len(detections),
                "platforms": sorted({str(item.get("platform", "")) for item in detections if item.get("platform")}),
                "families": sorted({str(item.get("family", "")) for item in detections if item.get("family")}),
            },
            "next_steps": self._build_next_steps(detections),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        primary = detections[0]
        target_type = str(primary.get("target_type", "")).strip()
        if target_type and report.target_type in {"unknown", "file", context.target.suffix.lstrip(".").lower()}:
            report.target_type = target_type

        for detection in detections:
            display_name = str(detection.get("display_name", "")).strip()
            platform = str(detection.get("platform", "")).strip()
            if display_name:
                report.add_framework(display_name)
            if platform:
                report.add_framework(platform)
            self._index_detection(context, report, detection, manifest_path)

        names = ", ".join(str(item.get("display_name")) for item in detections[:5])
        report.add_artifact(str(manifest_path), "manifest", "Console binary/archive format manifest")
        report.add_finding(
            "Console binary/archive format detected",
            "RE-Pro identified one or more console-specific executable, ROM, disc, compression, or archive formats.",
            severity="info",
            details=names,
        )
        report.add_note(f"Console format support detected: {names}.")
        self._attempt_sce_unpack(context, report, detections, console_dir)
        self._attempt_psarc_index(context, report, detections, console_dir)
        self._attempt_psp_index(context, report, detections, console_dir)

    @staticmethod
    def _build_next_steps(detections: list[dict[str, object]]) -> list[str]:
        steps: list[str] = []
        format_ids = {str(item.get("format_id", "")) for item in detections}
        if "nintendo-dol" in format_ids:
            steps.append("Load DOL sections at their PowerPC virtual addresses before decompilation.")
        if "nintendo-gc-wii-disc" in format_ids:
            steps.append("Use disc header DOL/FST offsets to extract the main executable and filesystem tree.")
        if "sony-psx-exe" in format_ids:
            steps.append("Map the PS-X EXE payload at text_load_address and use the entry_point as the initial PC.")
        if "sony-sce-self" in format_ids:
            steps.append("SELF/SPRX payloads are commonly encrypted/signed; preserve SCE header metadata and unpack with platform keys/tools when available.")
        if "sony-pkg" in format_ids:
            steps.append("PKG payload metadata is useful for triage, but retail content usually requires NPDRM decryption before file extraction.")
        if "sony-psarc" in format_ids:
            steps.append("Parse the PSARC manifest/file table to recover mounted asset paths and per-file compression state.")
        if "sony-psp-pbp" in format_ids:
            steps.append("Split the PBP into PARAM.SFO, DATA.PSP, DATA.PSAR, and media sections; edit through the browser to rebuild the fixed-section PBP.")
        if "sony-psp-param-sfo" in format_ids:
            steps.append("Open PARAM.SFO as structured JSON for metadata edits, then rebuild the binary SFO payload.")
        if "sony-psp-data-psp" in format_ids:
            steps.append("Treat DATA.PSP as the signed PSP executable payload; preserve raw bytes unless a legal PSP decryptor is configured.")
        if "sony-psp-data-psar" in format_ids:
            steps.append("Treat DATA.PSAR as PSP firmware PSAR, not PSARC; recover markers and preserve bytes for rebuilds.")
        if {"nintendo-u8", "nintendo-rarc", "nintendo-sarc"} & format_ids:
            steps.append("Archive file tables can be expanded into recovered asset trees for later source/asset reconstruction.")
        if "nintendo-yaz0" in format_ids:
            steps.append("Yaz0 is a wrapper; decompress first, then rerun analysis on the decoded payload.")
        if {"cri-cpk", "cri-afs"} & format_ids:
            steps.append("CRI archives often hold audio, movies, scripts, and model assets; enumerate entries before decompilation.")
        if not steps:
            steps.append("Use the console format manifest to choose the correct loader, architecture, and archive unpacking strategy.")
        return steps

    @staticmethod
    def _attempt_sce_unpack(context, report, detections: list[dict[str, object]], console_dir: Path) -> None:
        format_ids = {str(item.get("format_id", "")) for item in detections}
        if not ({"sony-sce-self", "sony-pkg"} & format_ids):
            return
        output_dir = ensure_dir(console_dir / "sce_unpack")
        result = attempt_sce_unpack(
            context.target,
            output_dir,
            detections,
            run_external_tools=bool(getattr(context, "run_external_tools", False)),
            logger=getattr(context, "log", None),
        )
        status_path = write_sce_unpack_manifest(output_dir / "sce_unpack_manifest.json", result)
        report.add_artifact(str(status_path), "manifest", "SCE decryption/extraction manifest")
        for item in result.get("results") or []:
            if not isinstance(item, dict):
                continue
            if item.get("kind") == "self" and item.get("ok") and item.get("output_path"):
                report.add_artifact(str(item["output_path"]), "binary", "SCE decrypted SELF ELF payload")
                report.add_finding(
                    "SCE SELF payload recovered",
                    "RE-Pro recovered an ELF payload from a Sony SELF/SPRX executable using an embedded debug ELF or configured legal decryptor.",
                    severity="info",
                    details=str(item.get("method", "")),
                )
            elif item.get("kind") == "pkg" and item.get("ok") and item.get("output_dir"):
                report.add_artifact(str(item["output_dir"]), "directory", "SCE PKG extracted payload directory")
                report.add_finding(
                    "SCE PKG payload extracted",
                    "RE-Pro extracted files from a Sony PKG package using a configured legal local extractor.",
                    severity="info",
                    details=f"{item.get('extracted_file_count', 0)} file(s)",
                )
            elif item.get("message"):
                report.add_note(str(item["message"]))

    @staticmethod
    def _attempt_psarc_index(context, report, detections: list[dict[str, object]], console_dir: Path) -> None:
        format_ids = {str(item.get("format_id", "")) for item in detections}
        if "sony-psarc" not in format_ids:
            return
        output_dir = ensure_dir(console_dir / "psarc")
        try:
            archive = parse_psarc(context.target, inspect_blocks=True)
            toc_path = output_dir / "psarc_toc.json"
            toc_path.write_text(json.dumps(archive.to_manifest(), indent=2), encoding="utf-8")
            report.add_artifact(str(toc_path), "manifest", "PSARC table-of-contents and compression manifest")
            extraction = extract_psarc(context.target, output_dir / "extract")
            report.add_artifact(str(extraction["manifest_path"]), "manifest", "PSARC extraction manifest")
            if extraction.get("extracted_file_count"):
                report.add_artifact(str(extraction["output_dir"]), "directory", "PSARC extracted editable asset tree")
            report.add_finding(
                "PSARC ToC recovered",
                "RE-Pro parsed the PSARC manifest, file order, block table, and zlib/lzma compression profile for editable archive reconstruction.",
                severity="info",
                details=f"{archive.entry_count} entries, {extraction.get('extracted_file_count', 0)} extracted files",
            )
        except (OSError, PsarcFormatError) as exc:
            report.add_note(f"PSARC ToC parse skipped: {exc}")

    @staticmethod
    def _attempt_psp_index(context, report, detections: list[dict[str, object]], console_dir: Path) -> None:
        format_ids = {str(item.get("format_id", "")) for item in detections}
        if not ({"sony-psp-pbp", "sony-psp-param-sfo", "sony-psp-data-psp", "sony-psp-data-psar"} & format_ids):
            return
        output_dir = ensure_dir(console_dir / "psp")
        try:
            if "sony-psp-pbp" in format_ids:
                archive = parse_pbp(context.target)
                toc_path = output_dir / "pbp_manifest.json"
                toc_path.write_text(json.dumps(archive.to_manifest(), indent=2), encoding="utf-8")
                report.add_artifact(str(toc_path), "manifest", "PSP PBP section manifest")
                extraction = extract_pbp(context.target, output_dir / "extract")
                report.add_artifact(str(extraction["manifest_path"]), "manifest", "PSP PBP extraction manifest")
                report.add_artifact(str(extraction["output_dir"]), "directory", "PSP PBP extracted editable sections")
                tool_result = attempt_psp_tooling(
                    context.target,
                    output_dir / "tooling",
                    detections,
                    run_external_tools=bool(getattr(context, "run_external_tools", False)),
                    logger=getattr(context, "log", None),
                )
                tool_manifest = write_psp_tool_manifest(output_dir / "psp_tooling_manifest.json", tool_result)
                report.add_artifact(str(tool_manifest), "manifest", "PSP decrypt/extract tooling manifest")
                for item in tool_result.get("results") or []:
                    if not isinstance(item, dict) or not item.get("ok"):
                        continue
                    if item.get("kind") == "data_psp_decrypt" and item.get("output_path"):
                        report.add_artifact(str(item["output_path"]), "binary", "PSP DATA.PSP decrypted payload")
                    elif item.get("kind") == "data_psar_extract" and item.get("output_dir"):
                        report.add_artifact(str(item["output_dir"]), "directory", "PSP DATA.PSAR extracted payload tree")
                param_sfo = archive.section("PARAM.SFO")
                data_psp = archive.section("DATA.PSP")
                data_psar = archive.section("DATA.PSAR")
                details = (
                    f"sections={len(archive.sections)}, "
                    f"PARAM.SFO={param_sfo.size if param_sfo else 0} bytes, "
                    f"DATA.PSP={data_psp.size if data_psp else 0} bytes, "
                    f"DATA.PSAR={data_psar.size if data_psar else 0} bytes"
                )
                report.add_finding(
                    "PSP PBP sections recovered",
                    "RE-Pro split the fixed PBP section table and exposed PARAM.SFO, DATA.PSP, and DATA.PSAR for editable rebuilds.",
                    severity="info",
                    details=details,
                )
                return
            if "sony-psp-param-sfo" in format_ids:
                manifest = parse_param_sfo_file(context.target)
                manifest_path = output_dir / "param_sfo.json"
                manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
                report.add_artifact(str(manifest_path), "manifest", "PSP PARAM.SFO structured metadata")
                report.add_finding(
                    "PARAM.SFO metadata parsed",
                    "RE-Pro decoded PARAM.SFO into editable JSON while preserving field formats and lengths for rebuild.",
                    severity="info",
                    details=str((manifest.get("values") or {}).get("TITLE", "")),
                )
            elif "sony-psp-data-psp" in format_ids:
                manifest = parse_data_psp(context.target.read_bytes(), source_path=str(context.target))
                manifest_path = output_dir / "data_psp_manifest.json"
                manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                report.add_artifact(str(manifest_path), "manifest", "PSP DATA.PSP executable manifest")
                tool_result = attempt_psp_tooling(
                    context.target,
                    output_dir / "tooling",
                    detections,
                    run_external_tools=bool(getattr(context, "run_external_tools", False)),
                    logger=getattr(context, "log", None),
                )
                report.add_artifact(
                    str(write_psp_tool_manifest(output_dir / "psp_tooling_manifest.json", tool_result)),
                    "manifest",
                    "PSP decrypt/extract tooling manifest",
                )
            elif "sony-psp-data-psar" in format_ids:
                manifest = parse_data_psar(context.target.read_bytes(), source_path=str(context.target))
                manifest_path = output_dir / "data_psar_manifest.json"
                manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                report.add_artifact(str(manifest_path), "manifest", "PSP DATA.PSAR firmware payload manifest")
                tool_result = attempt_psp_tooling(
                    context.target,
                    output_dir / "tooling",
                    detections,
                    run_external_tools=bool(getattr(context, "run_external_tools", False)),
                    logger=getattr(context, "log", None),
                )
                report.add_artifact(
                    str(write_psp_tool_manifest(output_dir / "psp_tooling_manifest.json", tool_result)),
                    "manifest",
                    "PSP decrypt/extract tooling manifest",
                )
        except (OSError, PspFormatError, ValueError) as exc:
            report.add_note(f"PSP payload parse skipped: {exc}")

    @staticmethod
    def _index_detection(context, report, detection: dict[str, object], manifest_path: Path) -> None:
        index = getattr(context, "analysis_index", None)
        if index is None:
            return
        target_id = index.ensure_target(str(context.target), report.target_type)
        format_id = index.add_entity(
            "format",
            f"console:{detection.get('format_id')}:{context.target.name}",
            str(detection.get("display_name", detection.get("format_id"))),
            attributes=detection,
        )
        index.add_relation(target_id, "has_format", format_id)
        artifact_id = index.add_entity(
            "artifact",
            str(manifest_path),
            "Console binary/archive format manifest",
            attributes={"category": "manifest"},
        )
        index.add_relation(format_id, "documented_by", artifact_id)
