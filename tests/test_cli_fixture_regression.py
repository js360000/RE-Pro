from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.cli import main
from tests import _path_setup  # noqa: F401


class CliFixtureRegressionTests(unittest.TestCase):
    def test_fixture_regression_command_dispatches_runner(self) -> None:
        payload = {
            "ok": True,
            "analysis_output_dir": str(Path("analysis_output") / "fixture"),
            "validation": {"ok": True, "checks": ["native_rtti_classes"], "errors": []},
        }
        stdout = io.StringIO()
        with patch("re_pro.cli.run_msvc_fixture_regression", return_value=payload) as runner:
            with patch("sys.argv", ["re-pro", "fixture-regression", "--no-ghidra", "--timeout", "120"]):
                with patch("sys.stdout", stdout):
                    exit_code = main()

        self.assertEqual(exit_code, 0)
        runner.assert_called_once()
        self.assertEqual(json.loads(stdout.getvalue()), payload)


if __name__ == "__main__":
    unittest.main()
