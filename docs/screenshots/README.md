# Screenshot Checklist

The README already uses [docs/assets/hero.png](../assets/hero.png). Future screenshots should be small, current, and generated from synthetic or redistributable fixtures.

## Useful Screens

- `gui-run-summary.png`: completed analysis run with report and artifact counts.
- `gui-source-browser.png`: recovered source tree with source-first view and hex fallback.
- `gui-mcp-config.png`: MCP server panel showing exact client JSON.
- `native-class-recovery.png`: MSVC RTTI/vtable/class recovery output.
- `frontend-source-lift.png`: source-map or beautified frontend recovery.
- `package-action.png`: rebuild/repack/signing action result.

## Capture Rules

- Avoid paths containing private usernames when possible.
- Do not show proprietary source, keys, decrypted payloads, or private symbol-server URLs.
- Prefer fixtures under `tests/fixtures` or temporary local analysis runs.
- Keep images compressed enough for GitHub browsing.
