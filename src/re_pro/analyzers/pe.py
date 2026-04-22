from __future__ import annotations

from .base import Analyzer


class PEAnalyzer(Analyzer):
    name = "PE metadata"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return
        if context.pe_metadata is None:
            return

        metadata = context.pe_metadata
        report.target_type = "portable-executable"
        report.add_framework("Portable Executable (PE)")
        report.fingerprints.update(metadata)
        if context.pe_imports:
            report.fingerprints["imports"] = context.pe_imports
        if context.pe_codeview_records:
            report.fingerprints["codeview"] = context.pe_codeview_records
        if context.version_info:
            report.fingerprints["version_info"] = context.version_info

        section_names = ", ".join(metadata.get("sections", [])) or "none"
        report.add_note(
            f"PE machine {metadata.get('machine')} with {metadata.get('number_of_sections')} sections: {section_names}."
        )
        if context.pe_imports:
            report.add_note(f"Imported DLLs: {', '.join(context.pe_imports[:12])}")
        if context.version_info:
            parts = []
            for key in ("ProductName", "FileDescription", "OriginalFilename", "ProductVersion"):
                value = context.version_info.get(key)
                if value:
                    parts.append(f"{key}={value}")
            if parts:
                report.add_note("Version info: " + ", ".join(parts))

        pdb_paths = [value for value in context.ascii_strings if value.lower().endswith(".pdb")]
        debug_pdb_paths = [str(record.get("pdb_path", "")) for record in context.pe_codeview_records if record.get("pdb_path")]
        all_pdb_paths = list(dict.fromkeys([*debug_pdb_paths, *pdb_paths]))
        if all_pdb_paths:
            report.add_finding(
                "Embedded PDB path recovered",
                "The executable contains at least one Program Database path, which may reveal build paths or original project names.",
                severity="info",
                details="; ".join(all_pdb_paths[:3]),
            )
        if context.pe_codeview_records:
            details = []
            for record in context.pe_codeview_records[:3]:
                path = record.get("pdb_path", "unknown")
                guid = record.get("guid")
                age = record.get("age")
                suffix = f" (GUID {guid}, age {age})" if guid else f" (age {age})" if age is not None else ""
                details.append(f"{path}{suffix}")
            report.add_note("PE debug directory records: " + "; ".join(details))
