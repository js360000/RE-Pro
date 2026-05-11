from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_pro.cli import main
from tests import _path_setup  # noqa: F401


class CliExternalToolJobTests(unittest.TestCase):
    def test_external_tool_job_dispatches_request_to_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            request_path = Path(temp_dir) / "request.json"
            request_path.write_text('{"job_type":"ghidra"}', encoding="utf-8")

            with patch("re_pro.cli.ExternalToolAnalyzer.run_background_job", return_value=0) as run_background_job:
                with patch("sys.argv", ["re-pro", "external-tool-job", "--request", str(request_path)]):
                    exit_code = main()

            self.assertEqual(exit_code, 0)
            run_background_job.assert_called_once_with(request_path)


if __name__ == "__main__":
    unittest.main()
