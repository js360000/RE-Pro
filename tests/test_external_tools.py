from __future__ import annotations

import json
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
            (export_dir / "targeted_decompilation.json").write_text("[]", encoding="utf-8")
            (export_dir / "enriched_class_manifest.json").write_text("{}", encoding="utf-8")
            (export_dir / "pseudo_code").mkdir()
            (export_dir / "class_pseudo_cpp").mkdir()
            report = AnalysisReport(target="sample", output_dir="out")

            ExternalToolAnalyzer._collect_ghidra_exports(export_dir, report)

            descriptions = [artifact.description for artifact in report.artifacts]
            self.assertIn("Ghidra function export", descriptions)
            self.assertIn("Ghidra strings export", descriptions)
            self.assertIn("Ghidra targeted pseudo-code export", descriptions)
            self.assertIn("Ghidra enriched class manifest", descriptions)
            self.assertIn("Ghidra targeted pseudo-code directory", descriptions)
            self.assertIn("Ghidra class-scoped pseudo-C++ directory", descriptions)
            self.assertTrue(any("Ghidra imported the program as MIPS:LE:64:64-32addr" in note for note in report.notes))

    def test_run_ghidra_queues_background_job_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "OpenCode.exe"
            target.write_bytes(b"MZ" + b"\x00" * 256)
            output_dir = root / "analysis_output"
            report = AnalysisReport(target=str(target), output_dir=str(output_dir))
            context = AnalysisContext(
                target=target,
                output_dir=output_dir,
                probable_binary=True,
                run_external_tools=True,
                run_ghidra=True,
            )
            native_dir = output_dir / "native"
            native_dir.mkdir(parents=True)
            manifest_path = native_dir / "msvc_rtti_classes.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "classes": [
                            {
                                "name": "Foo",
                                "methods": [
                                    {"address": "0x140001000"},
                                    {"address": "0x140001020"},
                                ],
                            }
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            with (
                patch("re_pro.analyzers.external_tools.resolve_command", return_value=[str(root / "ghidra" / "support" / "analyzeHeadless.bat")]),
                patch.object(ExternalToolAnalyzer, "_stage_ghidra_script", return_value=root / "ghidra_scripts"),
                patch.object(
                    ExternalToolAnalyzer,
                    "_choose_ghidra_profile",
                    return_value={"language_id": "x86:LE:64:default:windows", "compiler_id": "windows", "note": "profile note"},
                ),
                patch.object(ExternalToolAnalyzer, "_spawn_background_job") as spawn_background_job,
            ):
                queued = ExternalToolAnalyzer()._run_ghidra(context, report)

            self.assertTrue(queued)
            spawn_background_job.assert_called_once()

            request_path = output_dir / "ghidra" / "request.json"
            status_path = output_dir / "ghidra" / "status.json"
            self.assertTrue(request_path.exists())
            self.assertTrue(status_path.exists())

            request_payload = json.loads(request_path.read_text(encoding="utf-8"))
            status_payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(request_payload["job_type"], "ghidra")
            self.assertEqual(
                request_payload["analysis_timeout_seconds"],
                ExternalToolAnalyzer.GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
            )
            self.assertEqual(request_payload["language_id"], "x86:LE:64:default:windows")
            self.assertEqual(request_payload["rtti_manifest_path"], str(manifest_path))
            self.assertEqual(
                request_payload["targeted_decompilation_path"],
                str(output_dir / "ghidra" / "exports" / "targeted_decompilation.json"),
            )
            self.assertEqual(
                request_payload["native_class_pseudocode_dir"],
                str(output_dir / "native" / "pseudo_cpp"),
            )
            self.assertEqual(request_payload["targeted_method_count"], 2)
            self.assertEqual(status_payload["state"], "queued")

            artifact_descriptions = [artifact.description for artifact in report.artifacts]
            self.assertIn("Ghidra headless log", artifact_descriptions)
            self.assertIn("Ghidra headless status", artifact_descriptions)
            self.assertIn("Ghidra targeted pseudo-code export", artifact_descriptions)
            self.assertIn("Ghidra enriched class manifest", artifact_descriptions)
            self.assertIn("Ghidra targeted pseudo-code directory", artifact_descriptions)
            self.assertIn("Ghidra class-scoped pseudo-C++ directory", artifact_descriptions)
            self.assertTrue(any("background" in note.lower() for note in report.notes))
            self.assertTrue(any("profile note" in note for note in report.notes))
            self.assertTrue(any("targeted decompilation" in note.lower() for note in report.notes))

    def test_pe_tools_job_skips_redundant_deep_exports_after_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "OpenCode.exe"
            target.write_bytes(b"MZ" + b"\x00" * 256)
            payload = {
                "output_root": str(root / "pe_tools"),
                "rizin_dir": str(root / "rizin"),
                "radare2_dir": str(root / "radare2"),
                "log_path": str(root / "pe_tools" / "pe_tools.log"),
                "status_path": str(root / "pe_tools" / "status.json"),
                "target": str(target),
            }
            calls: list[tuple[str, int]] = []

            def resolve_command_side_effect(candidates):
                tool = candidates[0][0]
                if tool in {"rz-bin", "rizin", "rabin2", "r2"}:
                    return [str(root / f"{tool}.exe")]
                return None

            def capture_side_effect(command, destination, cwd, logger, outputs, errors, description, *, timeout=300):
                calls.append((description, timeout))
                if description == "rizin function list":
                    errors.append(f"{description}: Timed out after {timeout} seconds.")
                    return False
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("ok", encoding="utf-8")
                outputs.append({"path": str(destination), "description": description})
                return True

            with (
                patch("re_pro.analyzers.external_tools.resolve_command", side_effect=resolve_command_side_effect),
                patch.object(ExternalToolAnalyzer, "_capture_to_file_logged", side_effect=capture_side_effect),
            ):
                exit_code = ExternalToolAnalyzer._run_pe_tools_job(payload)

            self.assertEqual(exit_code, 0)
            descriptions = [description for description, _ in calls]
            self.assertIn("rizin function list", descriptions)
            self.assertIn("radare2 binary metadata", descriptions)
            self.assertNotIn("rizin strings export", descriptions)
            self.assertNotIn("radare2 function list", descriptions)

            status_payload = json.loads((root / "pe_tools" / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status_payload["state"], "completed")
            self.assertTrue(any("radare2 deep exports skipped" in error for error in status_payload["errors"]))


if __name__ == "__main__":
    unittest.main()
