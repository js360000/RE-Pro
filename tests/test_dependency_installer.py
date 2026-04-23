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


if __name__ == "__main__":
    unittest.main()
