# Contributing

RE-Pro is a reverse-engineering workbench, so useful contributions should improve evidence quality, recovery accuracy, reproducibility, or safe rebuild workflows.

## Local Setup

```bash
python -m pip install -e .
python -m pytest -q
```

On Windows, use `py -m ...` if `python` is not on PATH.

Optional external tools can be installed through:

```bash
re-pro install-tools
```

Ghidra, rizin, radare2, JADX, apktool, ILSpy, Frida, Node, and archive-specific helpers are optional for many tests. Code should degrade cleanly when a tool is absent.

## Development Rules

- Prefer deterministic fixtures and focused tests over large real-world binaries.
- Keep generated analysis outputs out of git unless they are tiny, synthetic, and intentionally documented.
- Do not commit proprietary applications, decrypted console payloads, private symbols, secrets, or commercial game data.
- When adding a format, include classification, extraction, index entities, user-facing report output, and at least one regression test where practical.
- When adding LLM behavior, keep a non-LLM fallback and store enough evidence for reproducibility.
- When adding rebuild/edit behavior, document whether the workflow is lossless, best-effort, or patch-based.

## Useful Test Targets

```bash
python -m pytest -q
python -m pytest tests/test_msvc_* -q
python -m pytest tests/test_frontend_* -q
python -m pytest tests/test_package_* -q
```

Run only the relevant subset while iterating, then run the full suite before committing broad changes.

## Pull Requests

Include:

- What changed and why.
- The target formats or workflows affected.
- Commands/tests run.
- Any optional tools required to reproduce deeper behavior.
- Screenshots or sanitized report excerpts for GUI/output changes.

If a change depends on a third-party binary format document or tool, link the source and describe any licensing constraints.
