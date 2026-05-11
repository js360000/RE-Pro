from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.analyzers.console import ConsoleFormatAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport
from re_pro.sce_decrypt import attempt_sce_unpack
from tests import _path_setup  # noqa: F401


class SceDecryptTests(unittest.TestCase):
    def test_self_debug_payload_is_carved_without_external_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "EBOOT.BIN"
            target.write_bytes(b"SCE\x00" + b"\x00" * 0x80 + b"\x7fELF" + b"payload")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                binary_head=target.read_bytes(),
                probable_binary=True,
            )

            ConsoleFormatAnalyzer().analyze(context, report)

            manifest_path = root / "out" / "console" / "sce_unpack" / "sce_unpack_manifest.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["ok"])
            self.assertEqual(manifest["results"][0]["method"], "embedded_elf_carve")
            output_path = Path(manifest["results"][0]["output_path"])
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), b"\x7fELFpayload")
            self.assertTrue(any(artifact.description == "SCE decrypted SELF ELF payload" for artifact in report.artifacts))

    def test_self_external_decryptor_uses_env_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "module.self"
            target.write_bytes(b"SCE\x00" + b"\x00" * 0x100)
            detections = [{"format_id": "sony-sce-self"}]

            def fake_run(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                output_path = Path(command[-1])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(b"\x7fELFdecrypted")
                if logger:
                    logger("fake self decrypt")
                return 0, "ok", ""

            with (
                patch.dict("os.environ", {"RE_PRO_SELF_DECRYPT_CMD": "fake-self-tool {input} {output}"}),
                patch("re_pro.sce_decrypt.run_command_logged", side_effect=fake_run),
            ):
                result = attempt_sce_unpack(target, root / "out", detections, run_external_tools=True)

            self.assertTrue(result["ok"])
            self.assertEqual(result["results"][0]["method"], "external_tool")
            self.assertTrue(Path(result["results"][0]["output_path"]).exists())

    def test_pkg_external_extractor_uses_pkg2zip_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.pkg"
            target.write_bytes(b"\x7fPKG" + b"\x00" * 0x100)
            detections = [{"format_id": "sony-pkg"}]

            def fake_run(command, *, cwd=None, timeout=300, logger=None, label=None, heartbeat_seconds=15):
                assert cwd is not None
                extracted = Path(cwd) / "USRDIR" / "EBOOT.BIN"
                extracted.parent.mkdir(parents=True, exist_ok=True)
                extracted.write_bytes(b"SCE\x00")
                if logger:
                    logger("fake pkg extract")
                return 0, "ok", ""

            with (
                patch("re_pro.sce_decrypt.resolve_command", return_value=["pkg2zip"]),
                patch("re_pro.sce_decrypt.run_command_logged", side_effect=fake_run),
            ):
                result = attempt_sce_unpack(target, root / "out", detections, run_external_tools=True)

            self.assertTrue(result["ok"])
            self.assertEqual(result["results"][0]["kind"], "pkg")
            self.assertEqual(result["results"][0]["extracted_file_count"], 2)
            self.assertTrue((root / "out" / "pkg" / "USRDIR" / "EBOOT.BIN").exists())

    def test_pkg_skips_with_clear_guidance_when_external_tools_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "game.pkg"
            target.write_bytes(b"\x7fPKG" + b"\x00" * 0x100)

            result = attempt_sce_unpack(target, root / "out", [{"format_id": "sony-pkg"}], run_external_tools=False)

            self.assertFalse(result["ok"])
            self.assertIn("--external-tools", result["results"][0]["message"])


if __name__ == "__main__":
    unittest.main()
