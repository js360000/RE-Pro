from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.cli import main
from re_pro.models import AnalysisReport


class CliArchitecturePortTests(unittest.TestCase):
    def test_architecture_port_command_generates_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            recovered = run_dir / "recovered_sources" / "native" / "main.cpp"
            recovered.parent.mkdir(parents=True, exist_ok=True)
            recovered.write_text("uintptr_t state = 0;\n", encoding="utf-8")
            report = AnalysisReport(target=str(root / "sample.exe"), output_dir=str(run_dir))
            report.target_type = "portable-executable"
            report.add_framework("Native C/C++")
            report.add_recovered_source("native/main.cpp", str(recovered), "")
            (run_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

            stdout = io.StringIO()
            with patch(
                "sys.argv",
                [
                    "re-pro",
                    "architecture-port",
                    str(run_dir),
                    "--source-arch",
                    "x86_64",
                    "--target-arch",
                    "arm64",
                    "--json",
                ],
            ):
                with patch("sys.stdout", stdout):
                    exit_code = main()

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertTrue(payload["ok"])
            self.assertTrue(Path(payload["architecture_ports"][0]["workspace_root"]).exists())


if __name__ == "__main__":
    unittest.main()
