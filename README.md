# RE-Pro

RE-Pro is a Python reverse-engineering workbench aimed at packaged applications across Windows, Android, and macOS. It focuses on:

- Detecting what kind of program an `.exe` likely contains.
- Recovering high-value artifacts from packaged apps, especially Electron/web bundles.
- Restoring original source trees from shipped source maps when available.
- Preparing recovered code and manifests for platform-porting work.
- Optionally using GPT-5.4 to reconstruct plausible source files and string-to-function mappings when binaries ship little original metadata.
- Orchestrating external decompilers and disassemblers where full source recovery requires specialist tooling.
- Providing both a CLI and a full PyQt5 desktop GUI.

## Current MVP scope

The current build supports:

- Android package extraction for `.apk`, `.apks`, and `.xapk` archives.
- Android web-asset/source-map recovery from embedded `assets/` bundles when source maps ship `sourcesContent`.
- Optional Android manifest/resource decoding through `apktool` when installed.
- Optional Android DEX decompilation through `jadx` when installed.
- Apple app bundle (`.app`) inspection with `Info.plist` parsing and Mach-O header detection.
- Apple archive extraction for `.dmg` and `.pkg` through 7-Zip when available.
- Optional Mach-O header, symbol, and function exports through `llvm-objdump`, `llvm-nm`, `rizin`, and `radare2` when installed.
- PE metadata inspection.
- PE debug-directory / CodeView parsing for embedded PDB paths, GUIDs, and ages.
- PE CLR-header parsing for managed metadata version, runtime version, stream layout, assembly flags, and ManagedNativeHeader data.
- Installer-family detection for NSIS, Inno Setup, and Squirrel wrappers.
- Windows Installer (`.msi`) detection and extraction through 7-Zip when available.
- Installer extraction through 7-Zip when available.
- Framework heuristics for Electron, .NET, PyInstaller/Nuitka, Rust, Go, and native C/C++.
- Native game/UI heuristics for Dear ImGui, Direct3D 9/11/12, Vulkan, OpenGL, SDL2/SDL3, GLFW, DirectStorage, Steamworks, FMOD, and Bink.
- Tauri detection via PE section names and runtime strings.
- Tauri embedded asset manifest recovery, section dumping, and Brotli-backed frontend asset extraction.
- PE resource extraction for manifests, version blobs, icons, HTML, and raw resource payloads.
- ELF parsing for headers, program headers, sections, dynamic dependencies, interpreters, and symbol tables.
- MIPS-aware ELF analysis, including little/big-endian tagging, MIPS flag decoding, and PS2-style sectionless ELF heuristics.
- Fast Capstone-backed ELF instruction previews from executable sections or load segments when the Python `capstone` package is installed.
- PS2-oriented Ghidra routing for probable Emotion Engine ELFs, with automatic `MIPS:LE/BE:64:64-32addr` imports plus headless program/function exports when Ghidra is installed.
- Electron resource discovery in sibling `resources/` folders.
- `app.asar` extraction via external `asar` or `npx @electron/asar` when available.
- JavaScript source map restoration using `sourcesContent`.
- Porting-preparation output that copies recovered sources/manifests into a dedicated `porting/` workspace with platform recommendations.
- Recompile workspaces with detected toolchains and prepared source/manifests for iterative rebuild attempts.
- Optional GPT-5.4-assisted reconstruction through the OpenAI Responses API, with configurable reasoning effort, verbosity, background execution, operator steering, grounded evidence references, immediate validation hooks, and local tool-driven context inspection.
- .NET framework heuristics for WinForms, WPF, Avalonia, MAUI, Unity managed, ASP.NET Core, and Blazor.
- .NET ReadyToRun detection from the managed native header, including header version and section counts.
- .NET apphost and single-file bundle probing, including 7-Zip-based bundle inspection for modern self-contained desktop apps.
- .NET managed manifest-resource extraction, including nested `.resources` decoding, WPF `.baml` recovery, and readable `.xaml` reconstruction.
- Optional .NET decompilation through `ilspycmd` when installed.
- Optional native symbol export through `llvm-nm`, `nm`, or `objdump` when installed.
- Optional PDB summary and symbol export through `llvm-pdbutil` when installed.
- Optional PDB opening through the Microsoft DIA SDK when the `Microsoft.DiaSource` COM class is registered.
- Optional native disassembly through `llvm-objdump` or `objdump` when installed.
- Optional UPX unpacking through `upx -d` when installed.
- Optional NVIDIA nvCOMP-backed GDeflate asset recovery for game data files when `nvidia-nvcomp-cu12` is installed on a CUDA-capable system.
- Optional Ghidra headless project generation when `analyzeHeadless` is installed.
- Optional rizin exports when `rizin` or `rz-bin` is installed.
- Optional radare2 exports when `r2`, `radare2`, or `rabin2` is installed.
- A PyQt5 desktop application for running analyses and browsing results.

## Important limits

There is no universal, lossless decompiler for arbitrary native binaries. For C, C++, Rust, and Go binaries, RE-Pro can classify, extract symbols, recover adjacent artifacts, and drive external tooling, but it cannot guarantee restoration of original source names or project structure unless the binary or package actually ships that information.

Electron/web-style apps remain the highest-yield target for file-name and source restoration because they often ship:

- `app.asar` or unpacked JS bundles.
- `package.json`.
- Source maps with `sources` and `sourcesContent`.
- Original relative file paths embedded in build metadata.

Installer-wrapped apps should usually be unpacked first. RE-Pro now detects common Windows and Apple packaging wrappers and can use 7-Zip to extract payloads like nested `.exe`, `.dll`, `.app`, `app.asar`, and source maps before deeper analysis.

## Install

```bash
python -m pip install -e .
```

## CLI

```bash
re-pro analyze path\to\target.exe -o analysis_output
```

For deeper Android or native exports:

```bash
re-pro install-tools
re-pro analyze path\to\app.apk -o analysis_output --external-tools
re-pro analyze path\to\Sample.app -o analysis_output --external-tools
```

To install the local managed toolchain used for .NET decompilation:

```bash
re-pro install-tools
```

That local toolchain is also used to build the small managed-resource helper that extracts nested `.resources`, recovers WPF `.baml` payloads, and decompiles them back into readable `.xaml`.

For optional NVIDIA GDeflate recovery in game pipelines:

```bash
python -m pip install nvidia-nvcomp-cu12
```

For GPT-assisted reconstruction:

```bash
set OPENAI_API_KEY=...
re-pro analyze path\to\target.exe -o analysis_output --llm --llm-background --llm-task "Focus on mapping updater and IPC logic"
```

To auto-trigger GPT only when source recovery is weak:

```bash
re-pro analyze path\to\target.exe -o analysis_output --llm-auto --llm-background
```

To keep GPT reconstruction grounded while still allowing it to acquire and use missing libraries:

```bash
re-pro analyze path\to\target.exe -o analysis_output --llm --llm-background
```

To disable autonomous dependency installation or build checks:

```bash
re-pro analyze path\to\target.exe -o analysis_output --llm --llm-no-install --llm-no-build-checks
```

## GUI

```bash
re-pro-gui
```

## Output

Each analysis run writes a timestamped folder containing:

- `report.json`
- `report.md`
- Recovered sources
- Porting preparation notes and prepared source bundles
- Recompile workspaces and toolchain manifests
- Optional GPT reconstruction status, logs, summaries, reconstructed source files, validation results, and autonomous dependency/build activity
- Extracted application assets
- External-tool output when available
