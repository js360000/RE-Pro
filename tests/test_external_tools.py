from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.analyzers.external_tools import ExternalToolAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


class ExternalToolAnalyzerTests(unittest.TestCase):
    def test_ps2_external_tools_auto_enable_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "OPNPS2LD.ELF"
            target.write_bytes(b"\x7fELF" + b"\x00" * 128)
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            report.add_framework("PlayStation 2 ELF")
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                probable_binary=True,
                elf_metadata={"machine": "MIPS", "type": "executable", "bits": 32, "endianness": "little"},
                run_external_tools=True,
                run_ghidra=False,
            )

            def resolve_command_side_effect(candidates):
                executable = candidates[0][0]
                if executable in {"analyzeHeadless", "analyzeHeadless.bat"}:
                    return [str(root / "ghidra" / "support" / "analyzeHeadless.bat")]
                return None

            with (
                patch("re_pro.analyzers.external_tools.resolve_command", side_effect=resolve_command_side_effect),
                patch.object(ExternalToolAnalyzer, "_run_ghidra", return_value=True) as run_ghidra,
            ):
                ExternalToolAnalyzer().analyze(context, report)

            self.assertTrue(run_ghidra.called)
            self.assertTrue(any("automatically enabled the Ghidra headless pass" in note for note in report.notes))

    def test_choose_ghidra_profile_prefers_ps2_language(self) -> None:
        report = AnalysisReport(target="sample", output_dir="out")
        report.add_framework("PlayStation 2 ELF")
        context = AnalysisContext(
            target=Path("sample.elf"),
            output_dir=Path("out"),
            elf_metadata={"machine": "MIPS", "bits": 32, "endianness": "little"},
        )
        languages = [
            {
                "id": "EmotionEngine:LE:32:default",
                "description": "PS2 Emotion Engine",
                "variant": "EE",
                "endian": "little",
                "compiler_ids": ["default"],
                "external_names": [{"tool": "IDA-PRO", "name": "r5900l"}],
            },
            {
                "id": "MIPS:LE:64:64-32addr",
                "description": "Generic MIPS64 with 32-bit addresses",
                "variant": "64-32addr",
                "endian": "little",
                "compiler_ids": ["o32", "default"],
                "external_names": [],
            },
        ]

        with patch("re_pro.analyzers.external_tools.list_ghidra_languages", return_value=languages):
            profile = ExternalToolAnalyzer._choose_ghidra_profile(context, report)

        self.assertEqual(profile["language_id"], "EmotionEngine:LE:32:default")
        self.assertEqual(profile["compiler_id"], "default")

    def test_collect_ghidra_exports_adds_artifacts_and_note(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            export_dir = Path(temp_dir)
            (export_dir / "program_info.json").write_text(
                '{"language_id": "MIPS:LE:64:64-32addr", "function_count": 12}',
                encoding="utf-8",
            )
            (export_dir / "functions.json").write_text("[]", encoding="utf-8")
            (export_dir / "strings.json").write_text("[]", encoding="utf-8")
            report = AnalysisReport(target="sample", output_dir="out")

            ExternalToolAnalyzer._collect_ghidra_exports(export_dir, report)

            descriptions = [artifact.description for artifact in report.artifacts]
            self.assertIn("Ghidra function export", descriptions)
            self.assertIn("Ghidra strings export", descriptions)
            self.assertTrue(any("Ghidra imported the program as MIPS:LE:64:64-32addr" in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
