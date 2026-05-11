from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.pdb import PDBAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from tests import _path_setup  # noqa: F401


class PDBAnalyzerTests(unittest.TestCase):
    def test_pdb_analyzer_exports_with_llvm_pdbutil_when_pdb_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            pdb = root / "sample.pdb"
            pdb.write_bytes(b"Microsoft C/C++ MSF 7.00\r\n")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_codeview_records=[{"format": "RSDS", "pdb_path": r"C:\build\sample.pdb", "guid": "GUID", "age": 1}],
            )

            def run_command_side_effect(command, **kwargs):
                if "-summary" in command:
                    return 0, "Summary\n", ""
                if "-publics" in command:
                    return 0, "public: void __cdecl Foo::Bar(void)\n", ""
                return 0, r"C:\src\Foo.cpp\n", ""

            with (
                patch("re_pro.analyzers.pdb.resolve_command", return_value=["llvm-pdbutil"]),
                patch("re_pro.analyzers.pdb.run_command", side_effect=run_command_side_effect),
            ):
                PDBAnalyzer().analyze(context, report)

            self.assertTrue(any(artifact.description == "Recovered sibling PDB file" for artifact in report.artifacts))
            self.assertTrue(any("llvm-pdbutil" in artifact.description for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "PDB symbols exported" for finding in report.findings))
            self.assertTrue(any(source.original_path.replace("\\", "/").endswith("C:/src/Foo.cpp") for source in report.recovered_sources))

    def test_pdb_analyzer_acquires_remote_pdb_when_local_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            remote_pdb = root / "out" / "pdb" / "sample.pdb"
            remote_pdb.parent.mkdir(parents=True, exist_ok=True)
            remote_pdb.write_bytes(b"Microsoft C/C++ MSF 7.00\r\n")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_codeview_records=[{"format": "RSDS", "pdb_path": r"C:\build\sample.pdb", "guid": "GUID", "age": 1}],
            )

            def run_command_side_effect(command, **kwargs):
                if "-summary" in command:
                    return 0, "Summary\n", ""
                if "-publics" in command:
                    return 0, "public: void __cdecl Foo::Bar(void)\n", ""
                return 0, r"C:\src\Foo.cpp\n", ""

            with (
                patch("re_pro.analyzers.pdb.acquire_pdbs_from_symbol_servers", return_value=[{"path": str(remote_pdb), "server": "https://msdl.microsoft.com/download/symbols/"}]),
                patch("re_pro.analyzers.pdb.resolve_command", return_value=["llvm-pdbutil"]),
                patch("re_pro.analyzers.pdb.run_command", side_effect=run_command_side_effect),
            ):
                PDBAnalyzer().analyze(context, report)

            self.assertTrue(any(artifact.description == "Downloaded PDB from remote symbol server" for artifact in report.artifacts))
            self.assertTrue(any(finding.title == "Remote PDB acquired" for finding in report.findings))
            self.assertTrue(any(finding.title == "PDB symbols exported" for finding in report.findings))


if __name__ == "__main__":
    unittest.main()
