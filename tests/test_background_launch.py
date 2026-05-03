from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from re_pro.background_launch import build_re_pro_background_command
from re_pro.mcp_launch import build_mcp_launch_details
from re_pro.models import LlmAssistSettings


class BackgroundLaunchTests(unittest.TestCase):
    def test_source_checkout_uses_module_launcher(self) -> None:
        with patch.object(sys, "executable", "python.exe"):
            command = build_re_pro_background_command("llm-job", "--request", "request.json")

        self.assertEqual(command, ["python.exe", "-m", "re_pro.cli", "llm-job", "--request", "request.json"])

    def test_frozen_build_uses_packaged_executable_directly(self) -> None:
        with patch.object(sys, "executable", "re-pro.exe"):
            with patch.object(sys, "frozen", True, create=True):
                command = build_re_pro_background_command("llm-job", "--request", "request.json")

        self.assertEqual(command, ["re-pro.exe", "llm-job", "--request", "request.json"])

    def test_llm_default_max_output_is_128k(self) -> None:
        self.assertEqual(LlmAssistSettings().max_output_tokens, 128000)
        self.assertEqual(LlmAssistSettings.from_dict({}).max_output_tokens, 128000)

    def test_frozen_mcp_details_use_packaged_executable(self) -> None:
        with patch.object(sys, "executable", "re-pro.exe"):
            with patch.object(sys, "frozen", True, create=True):
                details = build_mcp_launch_details(
                    workspace_root=".",
                    output_root="analysis_output",
                    tools_root="tools",
                    transport="stdio",
                )

        server_config = details["client_config"]["mcpServers"]["re-pro"]
        self.assertEqual(server_config["command"], "re-pro.exe")
        self.assertEqual(server_config["args"][0], "mcp-server")
        self.assertNotIn("env", server_config)


if __name__ == "__main__":
    unittest.main()
