from __future__ import annotations

from pathlib import Path

from ..symbol_acquisition import acquire_pdbs_from_symbol_servers, download_with_dotnet_symbol
from ..tooling import resolve_command, run_command
from ..utils import ensure_dir, safe_slug
from .base import Analyzer


class PDBAnalyzer(Analyzer):
    name = "PDB / DIA recovery"

    def analyze(self, context, report) -> None:
        if not context.target.is_file() or context.pe_metadata is None:
            return

        candidates = self._find_pdb_candidates(context)
        output_dir = ensure_dir(context.output_dir / "pdb")
        if not candidates:
            candidates.extend(self._acquire_remote_candidates(context, output_dir, report))
        if not candidates and context.pe_cli_metadata is not None:
            self._attempt_dotnet_symbol_download(context, output_dir, report)
        if not candidates:
            if context.pe_codeview_records:
                report.add_note(
                    "The PE debug directory references a PDB, but no matching local or remote .pdb file was recovered."
                )
            return

        for candidate in candidates:
            description = "Recovered sibling PDB file"
            if candidate.parent == output_dir:
                description = "Downloaded PDB from remote symbol server"
            report.add_artifact(str(candidate), "debug", description)

        report.add_finding(
            "PDB file recovered",
            "A matching Program Database file was recovered, which can materially improve native symbol and source reconstruction.",
            severity="info",
            details="; ".join(str(path.name) for path in candidates[:3]),
        )

        exported = False
        for candidate in candidates[:2]:
            exported |= self._export_with_llvm_pdbutil(candidate, output_dir, context, report)
            if exported:
                continue
            exported |= self._export_with_dia(candidate, output_dir, report)

        if not exported:
            report.add_note(
                "Install LLVM with `llvm-pdbutil` or register the Microsoft DIA SDK COM class to export PDB summaries automatically."
            )

    def _acquire_remote_candidates(self, context, output_dir: Path, report) -> list[Path]:
        downloads = acquire_pdbs_from_symbol_servers(
            context.pe_codeview_records,
            output_dir,
            logger=context.log,
        )
        if not downloads:
            return []
        report.add_finding(
            "Remote PDB acquired",
            "RE-Pro downloaded a matching PDB from a configured symbol server using the PE CodeView GUID/age record.",
            severity="info",
            details="; ".join(
                f"{Path(item['path']).name} via {item['server']}"
                for item in downloads[:3]
            ),
        )
        report.add_note(
            "Downloaded remote debug symbols from: "
            + ", ".join(dict.fromkeys(item["server"] for item in downloads if item.get("server")))
            + "."
        )
        return [Path(item["path"]) for item in downloads]

    def _attempt_dotnet_symbol_download(self, context, output_dir: Path, report) -> None:
        destination = ensure_dir(output_dir / "dotnet-symbol")
        result = download_with_dotnet_symbol(context.target, destination, logger=context.log)
        if result is None:
            return
        if result.get("ok"):
            report.add_artifact(str(destination), "debug", "dotnet-symbol download directory")
            report.add_finding(
                "dotnet-symbol completed",
                "dotnet-symbol fetched external symbol artifacts for this managed or runtime-linked target.",
                severity="info",
            )
            stdout = str(result.get("stdout", "")).strip()
            if stdout:
                report.add_note(f"dotnet-symbol output: {stdout[:600]}")
        else:
            stderr = str(result.get("stderr", "")).strip() or str(result.get("stdout", "")).strip()
            if stderr:
                report.add_note(f"dotnet-symbol did not recover symbols: {stderr[:600]}")

    def _find_pdb_candidates(self, context) -> list[Path]:
        expected_names: list[str] = []
        for record in context.pe_codeview_records:
            pdb_path = str(record.get("pdb_path", "")).strip()
            if pdb_path:
                expected_names.append(Path(pdb_path).name)
        original_name = context.version_info.get("OriginalFilename", "").strip()
        if original_name:
            expected_names.append(Path(original_name).with_suffix(".pdb").name)
        expected_names.append(context.target.with_suffix(".pdb").name)

        found: list[Path] = []
        seen: set[Path] = set()
        for name in dict.fromkeys(value for value in expected_names if value.lower().endswith(".pdb")):
            candidate = context.target.parent / name
            if candidate.exists() and candidate.is_file() and candidate not in seen:
                found.append(candidate)
                seen.add(candidate)

        for candidate in context.target.parent.glob("*.pdb"):
            if candidate not in seen:
                found.append(candidate)
                seen.add(candidate)
        return found

    @staticmethod
    def _export_with_llvm_pdbutil(pdb_path: Path, output_dir: Path, context, report) -> bool:
        command = resolve_command([["llvm-pdbutil"]])
        if command is None:
            return False

        safe_name = safe_slug(pdb_path.stem)
        summary_path = output_dir / f"{safe_name}.summary.txt"
        publics_path = output_dir / f"{safe_name}.publics.txt"
        summary_command = command + ["dump", "-summary", str(pdb_path)]
        publics_command = command + ["dump", "-publics", "-globals", "-modules", str(pdb_path)]

        summary_code, summary_stdout, summary_stderr = run_command(summary_command, cwd=pdb_path.parent, timeout=1200)
        publics_code, publics_stdout, publics_stderr = run_command(publics_command, cwd=pdb_path.parent, timeout=1200)

        wrote_any = False
        if summary_code == 0 and summary_stdout.strip():
            summary_path.write_text(summary_stdout, encoding="utf-8", errors="ignore")
            report.add_artifact(str(summary_path), "text", "PDB summary from llvm-pdbutil")
            wrote_any = True
        elif summary_stderr.strip():
            report.add_note(f"llvm-pdbutil summary export failed for {pdb_path.name}: {summary_stderr.strip()}")

        if publics_code == 0 and publics_stdout.strip():
            publics_path.write_text(publics_stdout, encoding="utf-8", errors="ignore")
            report.add_artifact(str(publics_path), "text", "PDB public/global symbols from llvm-pdbutil")
            wrote_any = True
        elif publics_stderr.strip():
            report.add_note(f"llvm-pdbutil symbol export failed for {pdb_path.name}: {publics_stderr.strip()}")

        if wrote_any:
            context.log(f"PDB export completed for {pdb_path} with llvm-pdbutil")
            report.add_finding(
                "PDB symbols exported",
                "llvm-pdbutil exported structured PDB metadata and symbol summaries for the recovered debug database.",
                severity="info",
                details=pdb_path.name,
            )
        return wrote_any

    @staticmethod
    def _export_with_dia(pdb_path: Path, output_dir: Path, report) -> bool:
        try:
            import comtypes.client  # type: ignore
        except Exception:
            return False

        try:
            source = comtypes.client.CreateObject("Microsoft.DiaSource")
            source.loadDataFromPdb(str(pdb_path))
            session = source.openSession()
            global_scope = session.globalScope
            lines = [
                f"PDB: {pdb_path}",
                f"Global scope name: {getattr(global_scope, 'name', '')}",
                f"Age: {getattr(global_scope, 'age', '')}",
                f"GUID: {getattr(global_scope, 'guid', '')}",
                f"Symbols file name: {getattr(global_scope, 'symbolsFileName', '')}",
                f"Machine type: {getattr(global_scope, 'machineType', '')}",
            ]
        except Exception as exc:
            message = str(exc).strip()
            if message:
                report.add_note(f"DIA SDK export failed for {pdb_path.name}: {message}")
            return False

        destination = output_dir / f"{safe_slug(pdb_path.stem)}.dia.txt"
        destination.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="ignore")
        report.add_artifact(str(destination), "text", "PDB summary from DIA SDK")
        report.add_finding(
            "PDB opened through DIA SDK",
            "The recovered PDB was opened via Microsoft DIA, confirming that debugger-oriented symbol metadata is accessible.",
            severity="info",
            details=pdb_path.name,
        )
        return True
