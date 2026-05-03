# Supported Formats

RE-Pro is intentionally evidence-first: each target is classified, unpacked where possible, correlated into `analysis_index.json`, and then promoted to recovered source only when the available evidence supports it.

## Native And Desktop

| Area | Current support |
| --- | --- |
| Windows PE | PE metadata, imports/exports, resources, manifests, overlays, Authenticode hints, PDB discovery, MSVC RTTI/vftable/class recovery, Ghidra/rizin/radare2 orchestration |
| .NET | apphost/bundle detection, managed resource extraction, ILSpy-oriented workflows, WPF/BAML/XAML recovery, ReadyToRun detection |
| Linux ELF | ELF metadata, sections, symbols, strings, Capstone preview, external-tool exports, AppImage/SquashFS extraction paths |
| Apple Mach-O | Mach-O metadata, `.app`, `.ipa`, `.dmg`, `.pkg`, entitlements, provisioning profiles, embedded frameworks and extensions |
| WASM | Module detection, section metadata, strings, and source-map/resource correlation when shipped |

## Application Packages

| Area | Current support |
| --- | --- |
| Electron | `app.asar` extraction, package metadata, native ASAR fallback, source-map restoration, bundle beautification, rebuild/repack actions |
| Tauri | Embedded asset extraction, frontend source restoration, source-map and hash-stripped asset naming, repack-oriented workspace generation |
| Android | APK/APKS/AAB/AAR, DEX, `resources.arsc`, JADX/apktool workflows, signing and patch/repack support |
| Java | JAR/WAR/EAR metadata, class/resource extraction, manifest analysis, decompiler handoff |
| Installers | MSI, NSIS, Inno, CAB, Apple package wrappers, nested payload extraction |

## Console And Game-Oriented Formats

| Area | Current support |
| --- | --- |
| Sony | PSARC parse/create/rebuild, zlib/LZMA/no-compression preservation, PSP PBP, DATA.PSP, DATA.PSAR, PARAM.SFO editing, PS3 PKG metadata |
| Nintendo-era archives | RARC, U8, NARC, AFS-style archive markers, GameCube/Wii-oriented extraction hooks |
| Game payload hints | CRI/CPK, HOG, WAD-family markers, GDeflate and DDL-oriented detection, runtime-carved payload workflows |
| Runtime-assisted recovery | Live Windows process capture, mapped-image options, readable memory dumps, carved runtime payloads, Frida-oriented traces |

## Source Recovery

| Evidence | Output quality target |
| --- | --- |
| Source maps with `sourcesContent` | Original source tree and original file contents |
| Symbols/PDB/managed metadata | Near-source naming, typed entities, method/class structure, and stronger decompiler mapping |
| RTTI/vtables/classes | Class headers, vtable maps, method ownership, member-access recovery, pseudo-C++ files named from recovered classes |
| Bundled JS/CSS without maps | Beautified shipped bundle, hash-stripped names, import/name propagation, JSX recovery, optional LLM source-grade rewrite |
| Stripped native binaries | Evidence-grounded pseudo-source, decompiler output, graph pivots, and rebuild/porting guidance rather than claimed lossless recovery |

## Rebuild And Editing

| Workflow | Current support |
| --- | --- |
| Source-first browser | View/edit recovered files, manifests, archives, executables, JSON resources, PARAM.SFO, and hex/base64 nodes |
| Package actions | APK signing, Electron/Tauri repack, PSARC create/rebuild, patch bundle apply |
| Architecture porting | x86/x64-to-arm64 style guidance, heuristic/LLM/hybrid modes, source-tree preparation |
| MCP-driven rebuild | External LLMs can inspect evidence, write files, validate reconstruction, and run bounded rebuild/package commands |

## Limits

RE-Pro does not claim universal lossless decompilation. It prioritizes original source when artifacts actually ship it, then progressively falls back to symbol-informed source, decompiler-informed pseudo-source, and finally readable evidence bundles.
