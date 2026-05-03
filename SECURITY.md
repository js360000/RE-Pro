# Security Policy

RE-Pro analyzes untrusted binaries and archives. Treat every target as hostile.

## Reporting Vulnerabilities

Open a private report if GitHub private vulnerability reporting is enabled for the repository. If it is not enabled, open a minimal public issue that says a security report is available, without exploit details or sensitive samples.

Please include:

- A concise description of the issue.
- Affected command, GUI workflow, or MCP tool.
- Safe reproduction steps.
- Whether the issue requires a malicious target file.
- Sanitized logs or stack traces.

## Scope

In scope:

- Unsafe extraction paths, path traversal, overwrite, or symlink issues.
- Unsafe archive/package rebuild behavior.
- Command injection through tool orchestration, package actions, or MCP workflows.
- Secret exposure through reports, logs, source recovery, or LLM prompts.
- Crashes caused by malformed binaries when they indicate a security boundary issue.

Out of scope:

- General decompiler inaccuracy without a security impact.
- Third-party tool vulnerabilities unless RE-Pro invokes them unsafely.
- Reports requiring proprietary samples that cannot be shared or minimized.

## Handling Samples

- Do not upload malware, proprietary binaries, decrypted console payloads, private symbols, or secrets to public issues.
- Prefer tiny synthetic reproducers.
- If a real binary is required, provide hashes, metadata, and a private transfer path only after maintainers agree.

## Operator Guidance

Run analysis in a disposable workspace when processing unknown binaries. Runtime tracing and live-process capture can execute or attach to software; only do this for targets you are authorized to inspect.
