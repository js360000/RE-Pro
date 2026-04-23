# RE-Pro

RE-Pro is a Python reverse-engineering workbench aimed at packaged applications across Windows, Android, and macOS. It focuses on:

- Detecting what kind of program an `.exe` likely contains.
- Recovering high-value artifacts from packaged apps, especially Electron/web bundles.
- Restoring original source trees from shipped source maps when available.
- Preparing recovered code and manifests for platform-porting work.
- Optionally using GPT-5.4 to reconstruct plausible source files and string-to-function mappings when binaries ship little original metadata.
- Exposing RE-Pro over MCP so external LLM clients can drive analysis, inspect evidence, reconstruct files, and run rebuild checks without using the direct OpenAI integration path.
- Orchestrating external decompilers and disassemblers where full source recovery requires specialist tooling.
- Writing a unified per-run analysis index so frameworks, findings, artifacts, resources, and tool outputs can be correlated in one machine-readable graph.
- Providing both a CLI and a full PyQt5 desktop GUI.

## Current MVP scope

The current build supports:

- Android package extraction for `.apk`, `.apks`, and `.xapk` archives.
- Standalone Android DEX bytecode parsing for raw `.dex` files, including strings, class descriptors, package hints, and optional JADX decompilation.
- Android web-asset/source-map recovery from embedded `assets/` bundles when source maps ship `sourcesContent`.
- Optional Android manifest/resource decoding through `apktool` when installed.
- Optional Android DEX decompilation through `jadx` when installed.
- Java archive extraction for `.jar`, `.war`, `.ear`, and `.aar` packages, including manifest parsing, framework hints, and web source-map recovery from embedded static assets.
- Linux package extraction for `.AppImage`, raw SquashFS images, and embedded AppImage root filesystems, including SquashFS carving and web source-map recovery from unpacked assets.
- Apple app bundle (`.app`) inspection with `Info.plist` parsing and Mach-O header detection.
- iOS `.ipa` extraction with `Payload/*.app` recovery, iOS `Info.plist` parsing, primary Mach-O discovery, and packaged web/source-map restoration from app resources.
- Apple archive extraction for `.dmg` and `.pkg` through 7-Zip when available.
- Optional Mach-O header, symbol, and function exports through `llvm-objdump`, `llvm-nm`, `rizin`, and `radare2` when installed.
- PE metadata inspection.
- PE debug-directory / CodeView parsing for embedded PDB paths, GUIDs, and ages.
- Remote PDB acquisition from configured symbol servers using PE CodeView GUID/age records, with Microsoft’s public symbol server as the default source.
- PE CLR-header parsing for managed metadata version, runtime version, stream layout, assembly flags, and ManagedNativeHeader data.
- Installer-family detection for NSIS, Inno Setup, and Squirrel wrappers.
- CAB archive detection and extraction through `expand.exe` or 7-Zip when available.
- Windows Installer (`.msi`) detection and extraction through 7-Zip when available.
- Installer extraction through 7-Zip when available.
- Framework heuristics for Electron, .NET, PyInstaller/Nuitka, Rust, Go, and native C/C++.
- Native game/UI heuristics for Dear ImGui, Direct3D 9/11/12, Vulkan, OpenGL, SDL2/SDL3, GLFW, DirectStorage, Steamworks, FMOD, and Bink.
- Tauri detection via PE section names and runtime strings.
- Tauri embedded asset manifest recovery, section dumping, and Brotli-backed frontend asset extraction.
- PE resource extraction for manifests, version blobs, icons, HTML, and raw resource payloads.
- ELF parsing for headers, program headers, sections, dynamic dependencies, interpreters, and symbol tables.
- WebAssembly (`.wasm`) parsing for headers, sections, imports, exports, producers metadata, sourceMappingURL recovery, and adjacent source-map restoration.
- MIPS-aware ELF analysis, including little/big-endian tagging, MIPS flag decoding, and PS2-style sectionless ELF heuristics.
- Fast Capstone-backed ELF instruction previews from executable sections or load segments when the Python `capstone` package is installed.
- PS2-oriented Ghidra routing for probable Emotion Engine ELFs, with automatic `MIPS:LE/BE:64:64-32addr` imports plus headless program/function exports when Ghidra is installed.
- Electron resource discovery in sibling `resources/` folders.
- `app.asar` extraction via external `asar` or `npx @electron/asar` when available.
- JavaScript source map restoration using `sourcesContent`.
- Porting-preparation output that copies recovered sources/manifests into a dedicated `porting/` workspace with platform recommendations.
- Recompile workspaces with detected toolchains and prepared source/manifests for iterative rebuild attempts.
- Optional GPT-5.4-assisted reconstruction through the OpenAI Responses API, with configurable reasoning effort, verbosity, background execution, operator steering, grounded evidence references, immediate validation hooks, and local tool-driven context inspection.
- MCP server support over `stdio`, `sse`, and `streamable-http`, exposing RE-Pro analysis, analysis-index search, artifact/source reading, rebuild tooling, and client-sampling-backed approximation workflows to external LLM clients.
- .NET framework heuristics for WinForms, WPF, Avalonia, MAUI, Unity managed, ASP.NET Core, and Blazor.
- .NET ReadyToRun detection from the managed native header, including header version and section counts.
- .NET apphost and single-file bundle probing, including 7-Zip-based bundle inspection for modern self-contained desktop apps.
- .NET managed manifest-resource extraction, including nested `.resources` decoding, WPF `.baml` recovery, and readable `.xaml` reconstruction.
- Local analyzer plugin discovery from the repo `plugins/` directory and Python entry points under `re_pro.analyzers`.
- Unified `analysis_index.json` output with normalized entities and relations for targets, frameworks, findings, artifacts, resources, imports, debug references, and tool runs.
- Structured ingestion of Ghidra/rizin/radare2 function and string exports into the unified analysis index, including cross-tool address correlation.
- Graph-driven workflow pivots from normalized functions, strings, frameworks, artifacts, and recovered sources back into export artifacts, porting guidance, and recompile workspaces.
- Optional .NET decompilation through `ilspycmd` when installed.
- Optional native symbol export through `llvm-nm`, `nm`, or `objdump` when installed.
- Optional PDB summary and symbol export through `llvm-pdbutil` when installed.
- Optional PDB opening through the Microsoft DIA SDK when the `Microsoft.DiaSource` COM class is registered.
- Optional `dotnet-symbol` support for managed/runtime-linked symbol acquisition workflows.
- Optional native disassembly through `llvm-objdump` or `objdump` when installed.
- Optional UPX unpacking through `upx -d` when installed.
- Optional NVIDIA nvCOMP-backed GDeflate asset recovery for game data files when `nvidia-nvcomp-cu12` is installed on a CUDA-capable system.
- Optional bounded runtime tracing for launchable Windows targets, including process observation, child-process discovery, module snapshots, stdout/stderr capture, and connection snapshots.
- Optional Frida-backed runtime API hooks for file, registry, network, library-load, and child-process activity when the Python `frida` and `frida-tools` packages are installed, with phase-aware helper status output for faster failure diagnosis.
- Automatic ARM64 Frida sidecar routing on Windows ARM64 hosts running an AMD64 main Python runtime.
- Optional Ghidra headless project generation when `analyzeHeadless` is installed.
- Optional rizin exports when `rizin` or `rz-bin` is installed.
- Optional radare2 exports when `r2`, `radare2`, or `rabin2` is installed.
- A PyQt5 desktop application for running analyses and browsing results.
- A PyQt5 analysis-index browser with filtering, relation inspection, and direct pivots into artifacts, recovered sources, porting guidance, and recompile workspaces.

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

To load extra local analyzer plugins from another directory:

```bash
re-pro analyze path\to\target.exe -o analysis_output --plugin-dir path\to\plugins
```

For deeper Android or native exports:

```bash
re-pro install-tools
re-pro analyze path\to\app.apk -o analysis_output --external-tools
re-pro analyze path\to\Sample.app -o analysis_output --external-tools
re-pro analyze C:\Windows\System32\whoami.exe -o analysis_output --runtime-trace --trace-seconds 2
```

For remote symbol acquisition, RE-Pro uses Microsoft’s public symbol server by default. To override or extend the server list, set:

```bash
set RE_PRO_SYMBOL_SERVERS=https://msdl.microsoft.com/download/symbols/;https://your-symbol-server.example/symbols/
```

To install the local managed toolchain used for .NET decompilation:

```bash
re-pro install-tools
```

That local toolchain is also used to build the small managed-resource helper that extracts nested `.resources`, recovers WPF `.baml` payloads, decompiles them back into readable `.xaml`, and supports optional `dotnet-symbol` installation for external symbol acquisition.

For optional NVIDIA GDeflate recovery in game pipelines:

```bash
python -m pip install nvidia-nvcomp-cu12
```

For richer runtime instrumentation hooks:

```bash
python -m pip install frida frida-tools
re-pro analyze path\to\target.exe -o analysis_output --runtime-trace
```

`re-pro install-tools` now also installs the Python Frida bindings/tooling into the active interpreter, so the GUI `Install Tooling` action and MCP `install_tooling` endpoint cover runtime instrumentation as well as archive/decompiler dependencies.
On Windows ARM64 systems where the main RE-Pro interpreter is AMD64, `install-tools` also provisions an embedded `tools/python-arm64` runtime and uses that sidecar automatically for Frida-based tracing.

For GPT-assisted reconstruction:

```bash
set OPENAI_API_KEY=...
re-pro analyze path\to\target.exe -o analysis_output --llm --llm-background --llm-task "Focus on mapping updater and IPC logic"
```

The GPT workflow now receives a graph-aware `analysis_index.json` snapshot and can query normalized entities and cross-tool correlations directly instead of relying only on raw artifact files.

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

## MCP

Run RE-Pro as an MCP server over standard I/O:

```bash
re-pro mcp-server --transport stdio
```

Or via the dedicated entry point:

```bash
re-pro-mcp --transport stdio
```

For HTTP-capable MCP clients:

```bash
re-pro mcp-server --transport streamable-http --host 127.0.0.1 --port 8000
```

The MCP surface exposes:

- Analysis execution through `analyze_target`.
- Run discovery and inspection through `list_analysis_runs`, `read_report`, `read_analysis_index`, `search_analysis_index`, and `get_index_entity`.
- Artifact and recovered-source browsing through `list_artifacts`, `list_recovered_sources`, and `read_output_file`.
- Rebuild workspace preparation and validation through `prepare_recompile_workspace`, `inspect_toolchains`, `install_project_dependency`, `run_project_command`, `write_reconstruction_file`, and `validate_reconstruction_file`.
- A client-side sampling workflow through `approximate_source_with_sampling`, which uses MCP `sampling/createMessage` when the connected client advertises sampling support.

The server also exposes MCP resources and prompts:

- `repro://roadmap`
- `repro://capabilities`
- `repro://latest-runs`
- `grounded_reconstruction`

This MCP path is intended to be a full alternative to the built-in OpenAI API integration. A connected LLM client can inspect the unified analysis graph, browse artifacts, write grounded approximation files, validate them locally, and iterate inside RE-Pro's recompile workspace without calling the direct GPT integration.

## GUI

```bash
re-pro-gui
```

## Plugins

RE-Pro auto-loads local analyzer plugins from [plugins/README.md](plugins/README.md) when the `plugins/` directory exists. Additional plugin directories can be passed with `--plugin-dir`, and packaged plugins can register entry points under `re_pro.analyzers`.

## Output

Each analysis run writes a timestamped folder containing:

- `report.json`
- `report.md`
- `analysis_index.json`
- `analysis_pipeline.json`
- Recovered sources
- Porting preparation notes and prepared source bundles
- Recompile workspaces and toolchain manifests
- Optional GPT reconstruction status, logs, summaries, reconstructed source files, validation results, and autonomous dependency/build activity
- Extracted application assets
- External-tool output when available
