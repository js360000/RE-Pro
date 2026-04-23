# RE-Pro

![RE-Pro hero](docs/assets/hero.png)

RE-Pro is a cross-platform reverse-engineering workbench built to turn opaque binaries and packaged apps into readable evidence, recovered source, and actionable rebuild workflows.

It combines format-aware extraction, source restoration, external tool orchestration, graph-based correlation, GPT-assisted approximation, rebuild planning, and patch/signing workflows in one system with a CLI, a PyQt5 desktop GUI, and an MCP server.

## Why RE-Pro

- Recover real source when it ships: source maps, managed resources, BAML/XAML, Tauri assets, manifests, symbols, package metadata, and bundled web payloads.
- Correlate everything: functions, strings, frameworks, artifacts, resources, findings, and external tool exports land in a unified analysis graph.
- Move beyond reporting: RE-Pro generates project templates, rebuild plans, signing plans, patch bundles, and bounded package actions instead of stopping at static dumps.
- Work from any interface: GUI for browsing, CLI for repeatable automation, and MCP for LLM-driven evidence, reconstruction, and rebuild workflows.

## Highlights

### Platform and Package Coverage

- Windows: PE, MSI, NSIS, Inno, CAB, .NET apphosts and bundles, PDB workflows, PE resources, native/game/UI heuristics.
- Android: APK, APKS, AAB, DEX, AAR, `resources.arsc`, JADX/apktool workflows, source-map recovery, signing and repack support.
- Apple: `.app`, `.ipa`, `.dmg`, `.pkg`, Mach-O inspection, entitlements, provisioning profiles, app extensions, framework heuristics.
- Linux and native ecosystems: ELF, AppImage, SquashFS, WASM, MIPS/PS2-style ELFs, Capstone previews, Ghidra/rizin/radare2 exports.
- Java and managed ecosystems: JAR, WAR, EAR, AAR, ILSpy, WPF/BAML/XAML recovery, ReadyToRun detection, managed resource extraction.

### Recovery and Analysis

- JavaScript and web source-map restoration with shipped `sourcesContent`.
- Electron `app.asar` and unpacked resource recovery.
- Tauri embedded asset extraction and frontend restoration.
- Remote PDB acquisition from symbol servers.
- Unified `analysis_index.json` with normalized entities and relations.
- Structured ingestion and cross-correlation of Ghidra, rizin, radare2, JADX, and ILSpy-oriented exports.

### Reconstruction and Rebuild

- Porting workspaces with prepared source trees and target-platform guidance.
- Recompile workspaces with Android Studio, Xcode, Node, Tauri/Electron, and CMake-oriented templates.
- Rebuild plans, signing plans, patch plans, run-to-run diffs, and diff-driven patch bundles.
- Bounded package actions for APK signing, Electron repack, Tauri packaging, and patch application.
- Optional GPT-5.4-assisted approximation when direct source recovery is weak.

### Interfaces

- PyQt5 desktop GUI for reports, artifacts, recovered sources, and graph-driven pivots.
- CLI for analysis, comparison, patch-bundle creation, packaging actions, and tooling install.
- MCP server exposing analysis, graph search, reconstruction, validation, diff, rebuild, and packaging workflows to external LLM clients.

## Fast Start

```bash
python -m pip install -e .
re-pro analyze path\to\target.exe -o analysis_output
```

For a fuller local setup:

```bash
re-pro install-tools
re-pro analyze path\to\target.exe -o analysis_output --external-tools
```

## CLI

Analyze a target:

```bash
re-pro analyze path\to\target.exe -o analysis_output
```

Compare two existing runs:

```bash
re-pro compare-runs path\to\base_run path\to\head_run -o diff_output
```

Create and apply a patch bundle from two runs:

```bash
re-pro create-patch-bundle path\to\base_run path\to\head_run -o patch_bundle
re-pro package-action --workspace-root path\to\run\porting\recompile --ecosystem patch --action apply-bundle --patch-bundle-path patch_bundle --target-root path\to\target_root
```

Run package rebuild or signing actions:

```bash
re-pro package-action --workspace-root path\to\run\porting\recompile --ecosystem electron --action repack
re-pro package-action --workspace-root path\to\run\porting\recompile --ecosystem tauri --action repack
re-pro package-action --workspace-root path\to\run\porting\recompile --ecosystem android-gradle --action sign-apk --artifact-path app.apk --keystore-path debug.keystore --key-alias androiddebugkey
```

Load additional local analyzer plugins:

```bash
re-pro analyze path\to\target.exe -o analysis_output --plugin-dir path\to\plugins
```

## Tooling

Install local reverse-engineering dependencies:

```bash
re-pro install-tools
```

That tooling surface includes support for Ghidra, rizin, radare2, JADX, apktool, ILSpy, .NET workflows, Frida-oriented runtime tracing, and helper runtimes used by RE-Pro’s analysis and rebuild paths.

For richer runtime instrumentation:

```bash
python -m pip install frida frida-tools
re-pro analyze path\to\target.exe -o analysis_output --runtime-trace
```

For optional NVIDIA GDeflate recovery in game pipelines:

```bash
python -m pip install nvidia-nvcomp-cu12
```

For remote symbol acquisition, RE-Pro uses Microsoft’s public symbol server by default. To override or extend the server list:

```bash
set RE_PRO_SYMBOL_SERVERS=https://msdl.microsoft.com/download/symbols/;https://your-symbol-server.example/symbols/
```

## GPT Reconstruction

Run GPT-assisted reconstruction:

```bash
set OPENAI_API_KEY=...
re-pro analyze path\to\target.exe -o analysis_output --llm --llm-background --llm-task "Focus on updater and IPC logic"
```

Auto-trigger GPT only when recovery is weak:

```bash
re-pro analyze path\to\target.exe -o analysis_output --llm-auto --llm-background
```

Disable autonomous dependency installation or build checks:

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
- Run-to-run comparison through `compare_analysis_runs`.
- Patch-bundle creation through `create_patch_bundle_from_runs`.
- Package rebuild, signing, and patch execution through `run_packaging_action`.
- Client-side sampling workflows through `approximate_source_with_sampling`.

This makes MCP a genuine alternative to direct API integration: an external LLM can inspect the graph, browse evidence, write grounded approximations, validate them locally, and drive rebuild steps through RE-Pro’s own execution surface.

## GUI

Launch the desktop GUI with:

```bash
re-pro-gui
```

Or on this repo’s Windows setup:

```bash
launch_gui.bat
```

## Output

Each analysis run writes a timestamped folder containing:

- `report.json`
- `report.md`
- `analysis_index.json`
- `analysis_pipeline.json`
- recovered sources and extracted artifacts
- porting guidance and prepared source bundles
- recompile templates and manifests
- optional diff, patch, and packaging outputs

## GitHub Pages

The repo includes a GitHub Pages-ready public landing page under [docs/index.html](docs/index.html). If Pages is configured to publish from `docs/`, that page can act as the project’s public product site.

## Plugins

RE-Pro auto-loads local analyzer plugins from [plugins/README.md](plugins/README.md) when the `plugins/` directory exists. Additional plugin directories can be passed with `--plugin-dir`, and packaged plugins can register entry points under `re_pro.analyzers`.

## Important Limits

There is no universal, lossless decompiler for arbitrary native binaries.

For C, C++, Rust, Go, and other stripped native targets, RE-Pro can classify, extract symbols, recover adjacent artifacts, drive specialist tooling, and help reconstruct plausible project structure, but it cannot guarantee restoration of the original source tree unless the binary or package actually ships that information.

Electron and web-style apps remain some of the highest-yield targets for file-name and source restoration because they often ship:

- `app.asar` or unpacked JS bundles
- `package.json`
- source maps with `sources` and `sourcesContent`
- original relative file paths embedded in build metadata

Installer-wrapped apps should usually be unpacked first. RE-Pro detects common Windows and Apple packaging wrappers and can extract nested payloads like `.exe`, `.dll`, `.app`, `app.asar`, and source maps before deeper analysis.
