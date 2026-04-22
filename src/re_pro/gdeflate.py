from __future__ import annotations

from pathlib import Path

NVCOMP_PYTHON_PACKAGE = "nvidia-nvcomp-cu12"


def nvcomp_available() -> tuple[bool, str]:
    try:
        from nvidia import nvcomp  # type: ignore
    except Exception as exc:  # pragma: no cover - environment specific
        return False, str(exc)
    version = getattr(nvcomp, "__version__", "unknown")
    return True, str(version)


def try_decompress_file(source: Path, destination: Path) -> tuple[bool, str]:
    try:
        from nvidia import nvcomp  # type: ignore
    except Exception as exc:  # pragma: no cover - environment specific
        return False, f"nvidia.nvcomp unavailable: {exc}"

    try:
        compressed = source.read_bytes()
    except OSError as exc:
        return False, f"failed to read input: {exc}"

    errors: list[str] = []
    decode_attempts = [
        lambda: nvcomp.Codec().decode(compressed),
        lambda: nvcomp.Codec(algorithm="GDeflate").decode(compressed),
    ]
    for decode in decode_attempts:
        try:
            decoded = decode()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_coerce_bytes(decoded))
            return True, "decoded with nvidia.nvcomp"
        except Exception as exc:  # pragma: no cover - environment specific
            errors.append(str(exc))
    return False, "; ".join(errors) if errors else "unknown decode failure"


def _coerce_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if hasattr(value, "cpu"):
        return _coerce_bytes(value.cpu())
    if hasattr(value, "tobytes"):
        return bytes(value.tobytes())
    return bytes(value)
