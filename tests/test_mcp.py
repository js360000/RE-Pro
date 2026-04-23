from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from tests import _path_setup  # noqa: F401

from re_pro.mcp_server import build_mcp_server


class McpServerTests(unittest.TestCase):
    def test_mcp_server_exposes_tools_resources_and_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            server = build_mcp_server(workspace_root=root, output_root=root / "out", tools_root=root / "tools")

            async def _inspect() -> tuple[list[str], list[str], list[str]]:
                tools = await server.list_tools()
                resources = await server.list_resources()
                prompts = await server.list_prompts()
                return (
                    [tool.name for tool in tools],
                    [str(resource.uri) for resource in resources],
                    [prompt.name for prompt in prompts],
                )

            tool_names, resource_uris, prompt_names = asyncio.run(_inspect())

            self.assertIn("analyze_target", tool_names)
            self.assertIn("approximate_source_with_sampling", tool_names)
            self.assertIn("compare_analysis_runs", tool_names)
            self.assertIn("create_patch_bundle_from_runs", tool_names)
            self.assertIn("run_packaging_action", tool_names)
            self.assertIn("repro://capabilities", resource_uris)
            self.assertIn("repro://roadmap", resource_uris)
            self.assertIn("grounded_reconstruction", prompt_names)

    def test_mcp_analysis_and_reconstruction_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "notes.txt"
            target.write_text("plain text target", encoding="utf-8")
            roadmap = root / "VERSATILITY_ROADMAP.md"
            roadmap.write_text("# Roadmap\n\n- Example item\n", encoding="utf-8")
            server = build_mcp_server(workspace_root=root, output_root=root / "out", tools_root=root / "tools")

            async def _run() -> tuple[dict, dict, dict, dict, dict, str, str]:
                _, analyzed = await server.call_tool("analyze_target", {"target": str(target)})
                _, runs = await server.call_tool("list_analysis_runs", {})
                _, report = await server.call_tool("read_report", {"run_output_dir": analyzed["output_dir"]})
                _, workspace = await server.call_tool("prepare_recompile_workspace", {"run_output_dir": analyzed["output_dir"]})
                _, written = await server.call_tool(
                    "write_reconstruction_file",
                    {
                        "run_output_dir": analyzed["output_dir"],
                        "relative_path": "src/app.py",
                        "content": "print('hello from mcp')\n",
                        "confidence": 0.84,
                        "evidence_refs": ["manual:mcp"],
                        "rationale": "Smoke test reconstruction",
                    },
                )
                _, validated = await server.call_tool(
                    "validate_reconstruction_file",
                    {
                        "run_output_dir": analyzed["output_dir"],
                        "relative_path": "src/app.py",
                    },
                )
                resource_contents = await server.read_resource("repro://roadmap")
                prompt = await server.get_prompt(
                    "grounded_reconstruction",
                    {"run_output_dir": analyzed["output_dir"], "task": "Focus on the main app shell"},
                )
                resource_text = "\n".join(getattr(item, "content", "") for item in resource_contents)
                prompt_text = "\n".join(
                    getattr(getattr(message, "content", None), "text", "")
                    for message in getattr(prompt, "messages", [])
                )
                return analyzed, runs, report, workspace, validated, resource_text, prompt_text

            analyzed, runs, report, workspace, validated, resource_text, prompt_text = asyncio.run(_run())

            self.assertEqual(report["target"], str(target.resolve()))
            self.assertEqual(runs["runs"][0]["output_dir"], analyzed["output_dir"])
            self.assertTrue(Path(workspace["workspace_root"]).exists())
            self.assertTrue(validated["ok"])
            self.assertIn("Example item", resource_text)
            self.assertIn("Focus on the main app shell", prompt_text)


if __name__ == "__main__":
    unittest.main()
