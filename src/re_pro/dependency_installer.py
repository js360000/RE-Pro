from __future__ import annotations

import json
import shutil
import subprocess
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
            executable = self._resolve_existing_executable(spec["expected_leaf"])
            if executable.exists():
                self._log(f"{spec['name']} already present at {executable}")
                installed.append({"name": spec["name"], "path": str(executable), "status": "present"})
                continue
            archive_path = downloads_dir / spec["archive_name"]
            self._download(spec["url"], archive_path)
            self._install_artifact(archive_path, spec)
            executable = self._resolve_existing_executable(spec["expected_leaf"])
            if not executable.exists():
                raise RuntimeError(f"{spec['name']} install completed but {spec['expected_leaf']} was not found under {self.tools_root}.")
            installed.append({"name": spec["name"], "path": str(executable), "status": "installed"})
            self._log(f"Installed {spec['name']} into {executable}")
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
        jdk = self._latest_temurin_21()
        return [
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
        ]

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
        for asset in release.get("assets") or []:
            name = asset["name"]
            if predicate(name):
                return {
                    "name": name,
                    "url": asset["browser_download_url"],
                    "root": name.removesuffix(".zip"),
                }
        raise RuntimeError(f"No matching asset found in release {release.get('tag_name')}")

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

    def _install_artifact(self, archive_path: Path, spec: dict[str, str]) -> None:
        kind = spec.get("kind", "zip")
        if kind == "zip":
            self._extract_zip(archive_path, self.tools_root)
            return
        if kind == "file":
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
        raise RuntimeError(f"Unsupported artifact kind: {kind}")

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

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)
