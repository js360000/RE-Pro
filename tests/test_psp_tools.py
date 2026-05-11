from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.psp_tools import encrypt_data_psp, pack_data_psar, psp_tool_status
from tests import _path_setup  # noqa: F401


class PspToolAdapterTests(unittest.TestCase):
    def test_tool_status_finds_bundled_psp_tools(self) -> None:
        status = psp_tool_status()

        self.assertTrue(status["pspdecrypt"]["available"])
        self.assertTrue(status["psp_packer"]["available"])

    def test_data_psp_encrypt_uses_configured_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            script = root / "copy_tool.py"
            script.write_text(
                "from pathlib import Path\n"
                "import shutil, sys\n"
                "Path(sys.argv[2]).parent.mkdir(parents=True, exist_ok=True)\n"
                "shutil.copyfile(sys.argv[1], sys.argv[2])\n",
                encoding="utf-8",
            )
            source = root / "payload.bin"
            source.write_bytes(b"edited payload")
            output = root / "DATA.PSP"
            env = {
                "RE_PRO_PSP_ENCRYPT_CMD": f'"{sys.executable}" "{script}" "{{input}}" "{{output}}"',
            }
            with patch.dict(os.environ, env, clear=False):
                result = encrypt_data_psp(source, output, work_dir=root / "work")

            self.assertTrue(result["ok"])
            self.assertEqual(output.read_bytes(), b"edited payload")

    def test_data_psar_pack_uses_configured_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            script = root / "pack_tool.py"
            script.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "Path(sys.argv[2]).parent.mkdir(parents=True, exist_ok=True)\n"
                "Path(sys.argv[2]).write_bytes(b'PSAR' + Path(sys.argv[1], 'file.bin').read_bytes())\n",
                encoding="utf-8",
            )
            source_dir = root / "psar"
            source_dir.mkdir()
            (source_dir / "file.bin").write_bytes(b"edited")
            output = root / "DATA.PSAR"
            env = {
                "RE_PRO_PSP_PSAR_PACK_CMD": f'"{sys.executable}" "{script}" "{{input}}" "{{output}}"',
            }
            with patch.dict(os.environ, env, clear=False):
                result = pack_data_psar(source_dir, output, work_dir=root / "work")

            self.assertTrue(result["ok"])
            self.assertEqual(output.read_bytes(), b"PSARedited")


if __name__ == "__main__":
    unittest.main()
