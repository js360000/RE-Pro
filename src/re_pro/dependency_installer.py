from __future__ import annotations

import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path
from typing import Callable
from urllib.request import Request, urlopen

from .tooling import REPO_ROOT
from .utils import ensure_dir


class DependencyInstaller:
    def __init__(self, tools_root: str | Path | None = None, logger: Callable[[str], None] | None = None) -> None:
        self.tools_root = Path(tools_root).resolve() if tools_root else (REPO_ROOT / "tools").resolve()
        self.logger = logger

    def install_all(self) -> dict[str, object]:
        ensure_dir(self.tools_root)
        downloads_dir = ensure_dir(self.tools_root / "downloads")
        installed: list[dict[str, str]] = []
        for spec in self._build_specs():
            existing = self._probe_existing(spec)
            if existing is not None:
                self._log(f"{spec['name']} already present at {existing['path']}")
                installed.append(existing)
                continue
            archive_path = downloads_dir / spec["archive_name"] if spec.get("archive_name") else None
            if archive_path is not None and spec.get("url"):
                self._download(spec["url"], archive_path)
            self._install_artifact(archive_path, spec)
            installed_record = self._probe_existing(spec, installed=True)
            if installed_record is None:
                expected = spec.get("expected_leaf") or spec.get("module_name") or spec["name"]
                raise RuntimeError(f"{spec['name']} install completed but {expected} was not found under {self.tools_root}.")
            installed.append(installed_record)
            self._log(f"Installed {spec['name']} into {installed_record['path']}")
        manifest_path = self.tools_root / "installed_tools.json"
        manifest_path.write_text(json.dumps(installed, indent=2), encoding="utf-8")
        return {"tools_root": str(self.tools_root), "manifest_path": str(manifest_path), "installed": installed}

    def _build_specs(self) -> list[dict[str, str]]:
        ghidra = self._latest_github_release("NationalSecurityAgency/ghidra")
        ghidra_asset = self._select_asset(ghidra, lambda name: name.startswith("ghidra_") and name.endswith(".zip"))
        rizin = self._latest_github_release("rizinorg/rizin")
        rizin_asset = self._select_asset(rizin, lambda name: name.startswith("rizin-windows-shared64-") and name.endswith(".zip"))
        radare2 = self._latest_github_release("radareorg/radare2")
        radare2_asset = self._select_asset(radare2, lambda name: name.endswith("-w64.zip") and name.startswith("radare2-"))
        jadx = self._latest_github_release("skylot/jadx")
        jadx_asset = self._select_asset(jadx, lambda name: name.startswith("jadx-") and name.endswith(".zip") and "gui" not in name.lower())
        apktool = self._latest_github_release("iBotPeaches/Apktool")
        apktool_asset = self._select_asset(apktool, lambda name: name.startswith("apktool_") and name.endswith(".jar"))
        pspdecrypt = self._latest_github_release("John-K/pspdecrypt")
        pspdecrypt_asset = self._select_asset_or_none(pspdecrypt, lambda name: name.endswith("-windows.zip"))
        jdk = self._latest_temurin_21()
        specs = [
            {
                "name": ".NET SDK (LTS)",
                "url": "https://dot.net/v1/dotnet-install.ps1",
                "archive_name": "dotnet-install.ps1",
                "expected_leaf": "dotnet/dotnet.exe",
                "kind": "dotnet-sdk",
                "channel": "LTS",
            },
            {
                "name": "Temurin JDK 21",
                "url": jdk["url"],
                "archive_name": jdk["name"],
                "expected_leaf": "bin/java.exe",
            },
            {
                "name": "Ghidra",
                "url": ghidra_asset["url"],
                "archive_name": ghidra_asset["name"],
                "expected_leaf": "support/analyzeHeadless.bat",
            },
            {
                "name": "Rizin",
                "url": rizin_asset["url"],
                "archive_name": rizin_asset["name"],
                "expected_leaf": "bin/rizin.exe",
            },
            {
                "name": "radare2",
                "url": radare2_asset["url"],
                "archive_name": radare2_asset["name"],
                "expected_leaf": "radare2.exe",
            },
            {
                "name": "JADX",
                "url": jadx_asset["url"],
                "archive_name": jadx_asset["name"],
                "expected_leaf": "bin/jadx.bat",
            },
            {
                "name": "Apktool",
                "url": apktool_asset["url"],
                "archive_name": apktool_asset["name"],
                "expected_leaf": "apktool/apktool.bat",
                "install_subdir": "apktool",
                "payload_name": apktool_asset["name"],
                "kind": "file",
            },
            {
                "name": "ILSpyCmd",
                "archive_name": "ilspycmd.tool",
                "expected_leaf": "ilspycmd/ilspycmd.exe",
                "kind": "dotnet-tool",
                "package_id": "ilspycmd",
                "tool_path": "ilspycmd",
            },
            {
                "name": "dotnet-symbol",
                "archive_name": "dotnet-symbol.tool",
                "expected_leaf": "dotnet-symbol/dotnet-symbol.exe",
                "kind": "dotnet-tool",
                "package_id": "dotnet-symbol",
                "tool_path": "dotnet-symbol",
            },
            {
                "name": "Frida",
                "archive_name": "",
                "kind": "python-package",
                "module_name": "frida",
                "packages": ["frida", "frida-tools"],
            },
            {
                "name": "Electron ASAR",
                "archive_name": "electron-asar.npm",
                "expected_leaf": "asar/node_modules/.bin/asar.cmd",
                "kind": "npm-install",
                "package_id": "@electron/asar",
                "tool_path": "asar",
            },
            {
                "name": "psp-packer",
                "archive_name": "psp-packer.cargo",
                "expected_leaf": "psp-packer/bin/psp-packer.exe",
                "kind": "cargo-install",
                "package_id": "psp-packer",
                "tool_path": "psp-packer",
            },
        ]
        if pspdecrypt_asset is not None:
            specs.append(
                {
                    "name": "pspdecrypt",
                    "url": pspdecrypt_asset["url"],
                    "archive_name": pspdecrypt_asset["name"],
                    "expected_leaf": "pspdecrypt.exe",
                }
            )
        if platform.machine().upper() == "ARM64" and sysconfig.get_platform().lower() != "win-arm64":
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            specs.insert(
                0,
                {
                    "name": "Python ARM64 (embedded)",
                    "url": f"https://www.python.org/ftp/python/{python_version}/python-{python_version}-embed-arm64.zip",
                    "archive_name": f"python-{python_version}-embed-arm64.zip",
                    "expected_leaf": "python-arm64/python.exe",
                    "kind": "embedded-python",
                    "install_subdir": "python-arm64",
                },
            )
        return specs

    def _latest_temurin_21(self) -> dict[str, str]:
        url = (
            "https://api.adoptium.net/v3/assets/latest/21/hotspot"
            "?architecture=x64&heap_size=normal&image_type=jdk&jvm_impl=hotspot&os=windows&vendor=eclipse"
        )
        payload = self._read_json(url)
        package = payload[0]["binary"]["package"]
        name = package["name"]
        return {
            "name": name,
            "url": package["link"],
            "root": name.removesuffix(".zip"),
        }

    def _latest_github_release(self, repo: str) -> dict[str, object]:
        return self._read_json(f"https://api.github.com/repos/{repo}/releases/latest")

    @staticmethod
    def _select_asset(release: dict[str, object], predicate: Callable[[str], bool]) -> dict[str, str]:
        asset = DependencyInstaller._select_asset_or_none(release, predicate)
        if asset is not None:
            return asset
        raise RuntimeError(f"No matching asset found in release {release.get('tag_name')}")

    @staticmethod
    def _select_asset_or_none(release: dict[str, object], predicate: Callable[[str], bool]) -> dict[str, str] | None:
        for asset in release.get("assets") or []:
            name = asset["name"]
            if predicate(name):
                return {
                    "name": name,
                    "url": asset["browser_download_url"],
                    "root": name.removesuffix(".zip"),
                }
        return None

    @staticmethod
    def _read_json(url: str) -> dict | list:
        request = Request(url, headers={"User-Agent": "RE-Pro"})
        with urlopen(request) as response:
            return json.load(response)

    def _download(self, url: str, destination: Path) -> None:
        if destination.exists():
            self._log(f"Using cached archive {destination.name}")
            return
        self._log(f"Downloading {url}")
        request = Request(url, headers={"User-Agent": "RE-Pro"})
        with urlopen(request) as response, destination.open("wb") as handle:
            shutil.copyfileobj(response, handle)

    def _extract_zip(self, archive_path: Path, destination: Path) -> None:
        self._log(f"Extracting {archive_path.name}")
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(destination)

    def _install_artifact(self, archive_path: Path | None, spec: dict[str, str]) -> None:
        kind = spec.get("kind", "zip")
        if kind == "zip":
            if archive_path is None:
                raise RuntimeError(f"Missing archive for {spec['name']}")
            self._extract_zip(archive_path, self.tools_root)
            return
        if kind == "file":
            if archive_path is None:
                raise RuntimeError(f"Missing archive for {spec['name']}")
            install_dir = ensure_dir(self.tools_root / spec.get("install_subdir", ""))
            destination = install_dir / spec.get("payload_name", archive_path.name)
            shutil.copy2(archive_path, destination)
            wrapper_path = install_dir / "apktool.bat"
            wrapper_path.write_text(
                "@echo off\r\n"
                "setlocal\r\n"
                "set SCRIPT_DIR=%~dp0\r\n"
                f"java -jar \"%SCRIPT_DIR%{destination.name}\" %*\r\n",
                encoding="utf-8",
            )
            return
        if kind == "dotnet-sdk":
            if archive_path is None:
                raise RuntimeError(f"Missing archive for {spec['name']}")
            install_dir = ensure_dir(self.tools_root / "dotnet")
            command = [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(archive_path),
                "-InstallDir",
                str(install_dir),
                "-Channel",
                spec.get("channel", "LTS"),
            ]
            self._log(f"Installing .NET SDK into {install_dir}")
            subprocess.run(command, check=True)
            return
        if kind == "dotnet-tool":
            dotnet = self._resolve_existing_executable("dotnet/dotnet.exe")
            if not dotnet.exists():
                raise RuntimeError("Cannot install ILSpyCmd because the local .NET SDK is not installed yet.")
            tool_dir = ensure_dir(self.tools_root / spec.get("tool_path", spec["package_id"]))
            command = [
                str(dotnet),
                "tool",
                "install",
                spec["package_id"],
                "--tool-path",
                str(tool_dir),
            ]
            self._log(f"Installing {spec['package_id']} into {tool_dir}")
            process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                if "is already installed" in process.stderr.lower() or "is already installed" in process.stdout.lower():
                    update = [
                        str(dotnet),
                        "tool",
                        "update",
                        spec["package_id"],
                        "--tool-path",
                        str(tool_dir),
                    ]
                    process = subprocess.run(update, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                raise RuntimeError(process.stderr.strip() or process.stdout.strip() or f"Failed to install {spec['package_id']}")
            return
        if kind == "python-package":
            packages = spec.get("packages", "").split(";") if isinstance(spec.get("packages"), str) else spec.get("packages", [])
            if not packages:
                packages = [spec["module_name"]]
            python_runtime = self._resolve_python_runtime(spec)
            command = [python_runtime, "-m", "pip", "install", *packages]
            self._log(f"Installing Python packages: {', '.join(packages)}")
            process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                raise RuntimeError(process.stderr.strip() or process.stdout.strip() or f"Failed to install {' '.join(packages)}")
            return
        if kind == "npm-install":
            npm = shutil.which("npm")
            if not npm:
                raise RuntimeError(f"Cannot install {spec['name']} because npm is not on PATH.")
            tool_dir = ensure_dir(self.tools_root / spec.get("tool_path", spec["package_id"]))
            command = [npm, "install", "--prefix", str(tool_dir), spec["package_id"]]
            self._log(f"Installing {spec['package_id']} into {tool_dir}")
            process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                raise RuntimeError(process.stderr.strip() or process.stdout.strip() or f"Failed to install {spec['package_id']}")
            return
        if kind == "cargo-install":
            cargo = shutil.which("cargo")
            if not cargo:
                raise RuntimeError(f"Cannot install {spec['name']} because cargo is not on PATH.")
            tool_dir = ensure_dir(self.tools_root / spec.get("tool_path", spec["package_id"]))
            command = [cargo, "install", spec["package_id"], "--root", str(tool_dir), "--locked", "--force"]
            self._log(f"Installing {spec['package_id']} into {tool_dir}")
            process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                raise RuntimeError(process.stderr.strip() or process.stdout.strip() or f"Failed to install {spec['package_id']}")
            return
        if kind == "embedded-python":
            if archive_path is None:
                raise RuntimeError(f"Missing archive for {spec['name']}")
            install_dir = ensure_dir(self.tools_root / spec.get("install_subdir", "python-arm64"))
            self._extract_zip(archive_path, install_dir)
            pth_files = sorted(install_dir.glob("python*._pth"))
            for pth_path in pth_files:
                content = pth_path.read_text(encoding="utf-8", errors="ignore")
                if "#import site" in content:
                    content = content.replace("#import site", "import site")
                    pth_path.write_text(content, encoding="ascii", errors="ignore")
            bootstrap_path = install_dir / "get-pip.py"
            self._download("https://bootstrap.pypa.io/get-pip.py", bootstrap_path)
            command = [str(install_dir / "python.exe"), str(bootstrap_path)]
            self._log(f"Bootstrapping pip in {install_dir}")
            process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
            if process.returncode != 0:
                raise RuntimeError(process.stderr.strip() or process.stdout.strip() or f"Failed to bootstrap pip in {install_dir}")
            return
        raise RuntimeError(f"Unsupported artifact kind: {kind}")

    def _probe_existing(self, spec: dict[str, str], *, installed: bool = False) -> dict[str, str] | None:
        kind = spec.get("kind", "zip")
        status = "installed" if installed else "present"
        if kind == "python-package":
            version = self._resolve_python_package_version(spec.get("module_name", ""), python_runtime=self._resolve_python_runtime(spec))
            if version is None:
                return None
            return {
                "name": spec["name"],
                "path": self._resolve_python_runtime(spec),
                "status": status,
                "version": version,
            }
        executable = self._resolve_existing_executable(spec["expected_leaf"])
        if not executable.exists():
            return None
        return {"name": spec["name"], "path": str(executable), "status": status}

    def _resolve_existing_executable(self, expected_leaf: str) -> Path:
        direct = self.tools_root / expected_leaf
        if direct.exists():
            return direct
        matches = sorted(
            path
            for path in self.tools_root.glob(f"**/{expected_leaf}")
            if "downloads" not in {part.lower() for part in path.parts}
        )
        if matches:
            return matches[0]
        return direct

    @staticmethod
    def _resolve_python_package_version(module_name: str, *, python_runtime: str | None = None) -> str | None:
        if not module_name:
            return None
        runtime = python_runtime or sys.executable
        if runtime == sys.executable:
            try:
                return importlib.metadata.version(module_name)
            except importlib.metadata.PackageNotFoundError:
                return None
        command = [
            runtime,
            "-c",
            (
                "import importlib.metadata, sys; "
                f"print(importlib.metadata.version({module_name!r}))"
            ),
        ]
        process = subprocess.run(command, capture_output=True, text=True, errors="ignore", check=False)
        if process.returncode != 0:
            return None
        return process.stdout.strip() or None

    def _resolve_python_runtime(self, spec: dict[str, str]) -> str:
        explicit = spec.get("python_runtime", "").strip()
        if explicit:
            return explicit
        python_leaf = spec.get("python_leaf", "").strip()
        if python_leaf:
            candidate = self._resolve_existing_executable(python_leaf)
            if candidate.exists():
                return str(candidate)
        if platform.machine().upper() == "ARM64" and sysconfig.get_platform().lower() != "win-arm64":
            candidate = self._resolve_existing_executable("python-arm64/python.exe")
            if candidate.exists():
                return str(candidate)
        return sys.executable

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)
