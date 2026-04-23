from __future__ import annotations

from pathlib import Path

from ..sourcemap import restore_sources_from_map
from ..tooling import resolve_command, run_command
from ..utils import ensure_dir
from .base import Analyzer


class LinuxPackageAnalyzer(Analyzer):
    name = "Linux package recovery"
    APPIMAGE_MAGIC = b"AI\x02"
    SQUASHFS_MAGIC = b"hsqs"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return

        family = self._detect_family(context)
        if family is None:
            return

        if family == "AppImage":
            report.target_type = "linux-appimage"
            report.add_framework("Linux AppImage")
        else:
            report.target_type = "squashfs-image"
            report.add_framework("SquashFS image")
        report.add_finding(
            f"{family} package detected",
            "The target looks like a Linux application container that can often be unpacked for deeper static analysis.",
            severity="info",
        )

        carved_path = None
        if family == "AppImage":
            carved_path = self._carve_embedded_squashfs(context.target, context)
            if carved_path is not None:
                report.add_artifact(str(carved_path), "archive", "Embedded SquashFS image carved from AppImage")
        image_path = carved_path or context.target
        extracted_dir = self._extract_rootfs(image_path, context)
        if extracted_dir is None:
            report.add_note("Automatic AppImage/SquashFS extraction requires 7-Zip or unsquashfs on this system.")
            return

        report.add_artifact(str(extracted_dir), "directory", f"Extracted {family} filesystem")
        extracted_files = [path for path in extracted_dir.rglob("*") if path.is_file()]
        report.add_note(f"{family} extraction produced {len(extracted_files)} files.")

        app_run = extracted_dir / "AppRun"
        if app_run.exists():
            report.add_note("AppImage AppRun launcher recovered from extracted rootfs.")
            report.add_artifact(str(app_run), "binary", "Recovered AppRun launcher")
        desktop_entries = sorted(extracted_dir.rglob("*.desktop"))
        if desktop_entries:
            report.add_artifact(str(desktop_entries[0]), "manifest", "Recovered desktop entry")
        if (extracted_dir / "usr" / "bin").exists():
            report.add_artifact(str(extracted_dir / "usr" / "bin"), "directory", "Recovered Linux application binaries")
        if any(path.name == "app.asar" for path in extracted_files):
            report.add_framework("Electron")
            report.add_note("Extracted Linux package includes app.asar, suggesting an Electron application.")

        self._restore_source_maps(extracted_dir, report, context)
        self._index_package(context, report, family, image_path, extracted_dir)

    def _detect_family(self, context) -> str | None:
        suffix = context.target.suffix.lower()
        if suffix == ".appimage":
            return "AppImage"
        if suffix in {".squashfs", ".sqsh"}:
            return "SquashFS"
        if context.binary_head.startswith(b"\x7fELF") and context.binary_head[8:11] == self.APPIMAGE_MAGIC:
            return "AppImage"
        if self.SQUASHFS_MAGIC in context.binary_head[:256]:
            return "SquashFS"
        return None

    def _carve_embedded_squashfs(self, target: Path, context) -> Path | None:
        offset = self._find_magic_offset(target, self.SQUASHFS_MAGIC)
        if offset is None:
            context.log(f"No embedded SquashFS magic found in {target}")
            return None
        carved_dir = ensure_dir(context.output_dir / "appimage")
        carved_path = carved_dir / "embedded_rootfs.squashfs"
        with target.open("rb") as source, carved_path.open("wb") as destination:
            source.seek(offset)
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)
        context.log(f"Carved embedded SquashFS from {target} at offset {offset} into {carved_path}")
        return carved_path

    @staticmethod
    def _find_magic_offset(path: Path, magic: bytes) -> int | None:
        overlap = len(magic) - 1
        chunk_size = 1024 * 1024
        offset = 0
        tail = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    return None
                haystack = tail + chunk
                position = haystack.find(magic)
                if position != -1:
                    return offset - len(tail) + position
                offset += len(chunk)
                tail = haystack[-overlap:] if overlap > 0 else b""

    @staticmethod
    def _extract_rootfs(image_path: Path, context) -> Path | None:
        destination = ensure_dir(context.output_dir / "linux_package_extract")
        command = resolve_command(
            [
                ["unsquashfs", "-d", str(destination), str(image_path)],
                ["7z", "x", "-y", f"-o{destination}", str(image_path)],
            ]
        )
        if command is None:
            return None
        code, _, stderr = run_command(command, cwd=image_path.parent, timeout=1800)
        if code == 0:
            context.log(f"Extracted Linux package filesystem into {destination}")
            return destination
        context.log(f"Linux package extraction failed: {stderr.strip()}")
        return None

    @staticmethod
    def _restore_source_maps(extracted_dir: Path, report, context) -> None:
        map_files = sorted(extracted_dir.rglob("*.map"))
        if not map_files:
            return
        recovered_root = ensure_dir(context.output_dir / "recovered_sources")
        restored_total = 0
        for map_file in map_files:
            restored_sources, notes = restore_sources_from_map(map_file, recovered_root)
            for source in restored_sources:
                report.add_recovered_source(
                    original_path=source.original_path,
                    restored_path=source.restored_path,
                    source_map=source.source_map,
                )
            restored_total += len(restored_sources)
            report.notes.extend(notes)
        if restored_total:
            report.add_finding(
                "Linux package source map restoration succeeded",
                f"Recovered {restored_total} original source files from Linux package web assets.",
                severity="info",
            )

    @staticmethod
    def _index_package(context, report, family: str, image_path: Path, extracted_dir: Path) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        format_id = context.analysis_index.add_entity(
            "format",
            f"{family.lower()}:{context.target.name}",
            family,
            attributes={"path": str(image_path), "suffix": context.target.suffix.lower()},
        )
        context.analysis_index.add_relation(target_id, "has_format", format_id)
        rootfs_id = context.analysis_index.add_entity(
            "artifact",
            str(extracted_dir),
            extracted_dir.name,
            attributes={"path": str(extracted_dir), "category": "directory"},
        )
        context.analysis_index.add_relation(target_id, "produced_artifact", rootfs_id)
