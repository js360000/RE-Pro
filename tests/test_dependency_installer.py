from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.dependency_installer import DependencyInstaller


class DependencyInstallerTests(unittest.TestCase):
    def test_probe_existing_python_package_returns_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            installer = DependencyInstaller(tools_root=Path(temp_dir))
            spec = {
                "name": "Frida",
                "kind": "python-package",
                "module_name": "frida",
            }
            with patch.object(DependencyInstaller, "_resolve_python_package_version", return_value="17.9.1"):
                result = installer._probe_existing(spec)
            self.assertEqual(result["name"], "Frida")
            self.assertEqual(result["status"], "present")
            self.assertEqual(result["version"], "17.9.1")

    def test_probe_existing_python_package_returns_none_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            installer = DependencyInstaller(tools_root=Path(temp_dir))
            spec = {
                "name": "Frida",
                "kind": "python-package",
                "module_name": "frida",
            }
            with patch.object(DependencyInstaller, "_resolve_python_package_version", return_value=None):
                self.assertIsNone(installer._probe_existing(spec))

    def test_build_specs_adds_embedded_python_on_arm64_host_with_amd64_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            installer = DependencyInstaller(tools_root=Path(temp_dir))
            fake_release = {
                "assets": [
                    {"name": "ghidra_12.zip", "browser_download_url": "https://example/ghidra.zip"},
                    {"name": "rizin-windows-shared64-1.zip", "browser_download_url": "https://example/rizin.zip"},
                    {"name": "radare2-1-w64.zip", "browser_download_url": "https://example/radare2.zip"},
                    {"name": "jadx-1.zip", "browser_download_url": "https://example/jadx.zip"},
                    {"name": "apktool_1.jar", "browser_download_url": "https://example/apktool.jar"},
                ]
            }
            with (
                patch("re_pro.dependency_installer.platform.machine", return_value="ARM64"),
                patch("re_pro.dependency_installer.sysconfig.get_platform", return_value="win-amd64"),
                patch.object(DependencyInstaller, "_latest_github_release", return_value=fake_release),
                patch.object(DependencyInstaller, "_latest_temurin_21", return_value={"name": "jdk.zip", "url": "https://example/jdk.zip"}),
            ):
                specs = installer._build_specs()
            self.assertEqual(specs[0]["name"], "Python ARM64 (embedded)")


if __name__ == "__main__":
    unittest.main()
