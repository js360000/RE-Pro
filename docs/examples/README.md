# Example Outputs

This directory documents what good public demo outputs should look like without committing proprietary binaries, commercial app extracts, or large generated artifacts.

## Recommended Demo Set

Use small, redistributable fixtures for public examples:

- A tiny MSVC C++ fixture with classes, inheritance, virtual methods, RTTI, and optional PDBs.
- A tiny Electron or Vite fixture with one build containing source maps and one build without maps.
- A small Android fixture with a manifest, resources, and one simple activity.
- A minimal archive fixture for PSARC create/rebuild behavior using synthetic text assets.

## Suggested Commands

```bash
python -m pip install -e .
re-pro analyze path\to\fixture.exe -o analysis_output\fixture_native --external-tools --ghidra
re-pro analyze path\to\fixture_electron -o analysis_output\fixture_electron --beautify-frontend
re-pro compare-runs analysis_output\fixture_native\run_a analysis_output\fixture_native\run_b -o analysis_output\fixture_diff
```

## What To Publish

Publish small excerpts rather than full generated trees:

- `report.md`
- selected recovered source files
- `analysis_index.json` excerpts
- screenshots of the GUI source browser and graph pivots
- rebuild or package-action logs with target names redacted when needed

## What Not To Commit

Do not commit proprietary apps, game archives, decrypted console payloads, symbol files from private servers, or large generated output directories. Keep those in local `analysis_output*` folders or attach sanitized excerpts to issues.
