from __future__ import annotations

import zipfile
from pathlib import Path

from ..utils import ensure_dir
from .base import Analyzer


class PythonPackagedAnalyzer(Analyzer):
    name = "Python packaged application recovery"

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or (not context.probable_binary and context.pe_metadata is None):
            return

        strings_lower = [value.lower() for value in context.ascii_strings]
        pyinstaller_markers = ("pyinstaller", "_meipass", "pyi-runtime-tmpdir", "pyi-windows-manifest-filename")
        nuitka_markers = ("nuitka", "__nuitka_binary_dir", "__compiled__")

        detected = False
        if any(marker in value for value in strings_lower for marker in pyinstaller_markers):
            report.add_framework("Python (PyInstaller)")
            report.add_finding(
                "PyInstaller markers detected",
                "The executable appears to have been built with PyInstaller.",
                severity="info",
            )
            detected = True

        if any(marker in value for value in strings_lower for marker in nuitka_markers):
            report.add_framework("Python (Nuitka)")
            report.add_finding(
                "Nuitka markers detected",
                "The executable appears to have been built with Nuitka.",
                severity="info",
            )
            detected = True

        target_stem = context.target.stem.lower()
        sibling_archives = list(context.target.parent.glob("*.pyz"))
        if detected:
            sibling_archives.extend(
                archive
                for archive in context.target.parent.glob("*.zip")
                if archive.stem.lower().startswith(target_stem) or target_stem.startswith(archive.stem.lower())
            )
        for archive in sibling_archives[:10]:
            report.add_artifact(str(archive), "archive", "Sibling Python runtime archive")
            if archive.suffix.lower() == ".zip":
                self._extract_zip(archive, context, report)
                detected = True

        if detected:
            report.add_note(
                "Python application recovery is most effective when adjacent runtime archives or unpacked folders are present."
            )

    @staticmethod
    def _extract_zip(archive: Path, context, report) -> None:
        destination = ensure_dir(context.output_dir / "python_runtime" / archive.stem)
        try:
            with zipfile.ZipFile(archive) as handle:
                handle.extractall(destination)
        except (OSError, zipfile.BadZipFile):
            report.add_note(f"Failed to extract sibling archive {archive}.")
            return
        report.add_artifact(str(destination), "directory", f"Extracted sibling archive {archive.name}")
