param(
    [string]$Version = "",
    [string]$Python = "py",
    [string]$OutputRoot = "dist\release",
    [switch]$SkipPythonArtifacts
)

$ErrorActionPreference = "Stop"

function Get-ProjectVersion {
    $pyproject = Get-Content "pyproject.toml"
    foreach ($line in $pyproject) {
        if ($line -match '^\s*version\s*=\s*"([^"]+)"') {
            return $Matches[1]
        }
    }
    throw "Could not read project version from pyproject.toml"
}

if (-not $Version) {
    $Version = Get-ProjectVersion
}

$repoRoot = (Resolve-Path ".").Path
$outputRootPath = Join-Path $repoRoot $OutputRoot
$releaseName = "RE-Pro-$Version-windows-x64"
$releaseRoot = Join-Path $outputRootPath $releaseName
$stagingRoot = Join-Path $outputRootPath "staging"
$entryRoot = Join-Path $outputRootPath "entrypoints"
$pyInstallerWork = Join-Path $repoRoot "build\pyinstaller"
$pyInstallerDist = Join-Path $outputRootPath "pyinstaller"

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $releaseRoot, $stagingRoot, $entryRoot, $pyInstallerWork, $pyInstallerDist
New-Item -ItemType Directory -Force -Path $releaseRoot, $stagingRoot, $entryRoot, $pyInstallerWork, $pyInstallerDist | Out-Null

if (-not $SkipPythonArtifacts) {
    & $Python -m build --sdist --wheel
    if ($LASTEXITCODE -ne 0) {
        throw "Python package build failed"
    }
}

$entryName = "re-pro"
$entryModule = "re_pro.cli"

$commonArgs = @(
    "--noconfirm",
    "--clean",
    "--onefile",
    "--paths", "src",
    "--specpath", $pyInstallerWork,
    "--workpath", $pyInstallerWork,
    "--distpath", $pyInstallerDist,
    "--collect-data", "re_pro",
    "--hidden-import", "re_pro.gui",
    "--hidden-import", "re_pro.mcp_server",
    "--hidden-import", "PyQt5.QtCore",
    "--hidden-import", "PyQt5.QtGui",
    "--hidden-import", "PyQt5.QtWidgets",
    "--add-data", ((Join-Path $repoRoot "src\re_pro\ghidra_scripts") + ";re_pro\ghidra_scripts")
)

if (Test-Path "tools\frontend-ast\repro_frontend_ast.mjs") {
    $commonArgs += @("--add-data", ((Join-Path $repoRoot "tools\frontend-ast\repro_frontend_ast.mjs") + ";tools\frontend-ast"))
}
if (Test-Path "tools\frontend-ast\package.json") {
    $commonArgs += @("--add-data", ((Join-Path $repoRoot "tools\frontend-ast\package.json") + ";tools\frontend-ast"))
}

$entryPath = Join-Path $entryRoot "$entryName.py"
$entryArg = Join-Path $OutputRoot "entrypoints\$entryName.py"
@"
from $entryModule import main

if __name__ == "__main__":
    raise SystemExit(main())
"@ | Set-Content -Encoding UTF8 $entryPath

$pyInstallerArgs = @("-m", "PyInstaller") + $commonArgs + @("--console", "--name", $entryName, $entryArg)
& $Python @pyInstallerArgs
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed for $entryName"
}

Copy-Item (Join-Path $pyInstallerDist "re-pro.exe") $releaseRoot
Copy-Item "README.md" $releaseRoot
Copy-Item "CONTRIBUTING.md" $releaseRoot
Copy-Item "SECURITY.md" $releaseRoot

@"
@echo off
"%~dp0re-pro.exe" gui %*
"@ | Set-Content -Encoding ASCII (Join-Path $releaseRoot "re-pro-gui.cmd")

@"
@echo off
"%~dp0re-pro.exe" mcp-server %*
"@ | Set-Content -Encoding ASCII (Join-Path $releaseRoot "re-pro-mcp.cmd")

$releaseNotesPath = Join-Path $releaseRoot "RELEASE_NOTES.txt"
@"
RE-Pro $Version Windows x64

Included entry points:
- re-pro.exe: compiled CLI, analysis, package actions, MCP server, and GUI launcher
- re-pro-gui.cmd: launches re-pro.exe gui
- re-pro-mcp.cmd: launches re-pro.exe mcp-server

Optional reverse-engineering tools are not bundled. Run:
  re-pro.exe install-tools

LLM assistance can use OPENAI_API_KEY or Codex OAuth via .codex/auth.json.
"@ | Set-Content -Encoding UTF8 $releaseNotesPath

$archivePath = Join-Path $outputRootPath "$releaseName.zip"
Remove-Item -Force -ErrorAction SilentlyContinue $archivePath
Compress-Archive -Path (Join-Path $releaseRoot "*") -DestinationPath $archivePath -Force

$checksumsPath = Join-Path $outputRootPath "SHA256SUMS.txt"
Get-FileHash -Algorithm SHA256 $archivePath, (Join-Path $repoRoot "dist\re_pro-$Version-py3-none-any.whl"), (Join-Path $repoRoot "dist\re_pro-$Version.tar.gz") |
    ForEach-Object { "$($_.Hash.ToLower())  $([System.IO.Path]::GetFileName($_.Path))" } |
    Set-Content -Encoding ASCII $checksumsPath

Write-Host "Windows release archive: $archivePath"
Write-Host "Checksums: $checksumsPath"
