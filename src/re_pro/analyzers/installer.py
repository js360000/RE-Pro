from __future__ import annotations

from pathlib import Path

from ..tooling import resolve_command, run_command
from ..utils import ensure_dir
from .base import Analyzer


class InstallerAnalyzer(Analyzer):
    name = "Installer detection and extraction"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return
        if context.target.suffix.lower() not in {".msi", ".cab"} and (not context.probable_binary and context.pe_metadata is None):
            return

        family = self._detect_installer_family(context)
        if family is None:
            return

        report.add_framework(f"Installer: {family}")
        report.add_finding(
            f"{family} installer detected",
            "The target looks like an installer wrapper rather than the final application payload.",
            severity="info",
        )
        report.add_note("Installer stubs should usually be extracted first, then the embedded application binaries analyzed separately.")

        extracted_dir = self._extract_payload(context.target, family, context)
        if extracted_dir is None:
            report.add_note("Automatic installer extraction was unavailable or failed. Install 7-Zip to enable archive extraction, and use Windows Installer for MSI admin extraction.")
            return

        report.add_artifact(str(extracted_dir), "directory", f"Extracted {family} payload")
        extracted_files = [path for path in extracted_dir.rglob("*") if path.is_file()]
        report.add_note(f"Installer extraction produced {len(extracted_files)} files.")

        payloads = [
            path
            for path in extracted_files
            if path.suffix.lower() in {".exe", ".dll", ".asar", ".map", ".json", ".cab", ".msi", ".mui", ".xml", ".appimage", ".squashfs"}
            or path.name.lower() == "package.json"
        ]
        for payload in payloads[:20]:
            report.add_artifact(str(payload), "payload", f"Extracted payload candidate: {payload.name}")

        if any("tauri" in path.name.lower() for path in extracted_files):
            report.add_note("Extracted installer payload includes Tauri-related files, suggesting a Tauri desktop application.")
        if any(path.name.lower() == "app.asar" for path in extracted_files):
            report.add_note("Extracted installer payload includes app.asar, suggesting an Electron-based application.")

    @staticmethod
    def _detect_installer_family(context) -> str | None:
        if context.target.suffix.lower() == ".msi":
            return "MSI"
        if context.target.suffix.lower() == ".cab":
            return "CAB"
        try:
            header = context.target.read_bytes()[:8]
        except OSError:
            header = b""
        if header.startswith(b"MSCF"):
            return "CAB"
        strings_lower = [value.lower() for value in context.ascii_strings]
        if any(marker in value for value in strings_lower for marker in ("nullsoft", "nsis", "makensis")):
            return "NSIS"
        if any(marker in value for value in strings_lower for marker in ("inno setup", "innoextract", "setup data")):
            return "Inno Setup"
        if any(marker in value for value in strings_lower for marker in ("squirrel", "update.exe --processstart")):
            return "Squirrel"
        return None

    @classmethod
    def _extract_payload(cls, target: Path, family: str, context) -> Path | None:
        if family == "MSI":
            extracted = cls._extract_msi_admin(target, context)
            if extracted is not None:
                return extracted
        if family == "CAB":
            extracted = cls._extract_cab(target, context)
            if extracted is not None:
                return extracted
        return cls._extract_with_7z(target, context)

    @staticmethod
    def _extract_msi_admin(target: Path, context) -> Path | None:
        destination = ensure_dir(context.output_dir / "installer_extract")
        command = resolve_command([["msiexec", "/a", str(target), "/qn", f"TARGETDIR={destination}"]])
        if command is None:
            return None
        code, stdout, stderr = run_command(command, cwd=target.parent, timeout=1800)
        extracted_files = [path for path in destination.rglob("*") if path.is_file()]
        if code == 0 and extracted_files:
            context.log(f"msiexec administrative extraction wrote {len(extracted_files)} files into {destination}")
            return destination
        message = stderr.strip() or stdout.strip()
        if message:
            context.log(f"msiexec administrative extraction failed: {message}")
        return None

    @staticmethod
    def _extract_with_7z(target: Path, context) -> Path | None:
        destination = ensure_dir(context.output_dir / "installer_extract")
        command = resolve_command([["7z", "x", "-y", f"-o{destination}", str(target)]])
        if command is None:
            return None
        code, _, stderr = run_command(command, cwd=target.parent, timeout=1200)
        if code == 0:
            context.log(f"7-Zip extracted installer payload into {destination}")
            return destination
        context.log(f"7-Zip extraction failed: {stderr.strip()}")
        return None

    @staticmethod
    def _extract_cab(target: Path, context) -> Path | None:
        destination = ensure_dir(context.output_dir / "installer_extract")
        command = resolve_command([["expand", str(target), "-F:*", str(destination)]])
        if command is None:
            return None
        code, stdout, stderr = run_command(command, cwd=target.parent, timeout=1200)
        extracted_files = [path for path in destination.rglob("*") if path.is_file()]
        if code == 0 and extracted_files:
            context.log(f"expand.exe extracted CAB payload into {destination}")
            return destination
        message = stderr.strip() or stdout.strip()
        if message:
            context.log(f"expand.exe CAB extraction failed: {message}")
        return None
