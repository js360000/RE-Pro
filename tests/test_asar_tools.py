from __future__ import annotations

import tempfile
import unittest
import json
import struct
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.asar_tools import extract_asar_archive


def _write_minimal_asar(path: Path, files: dict[str, bytes]) -> None:
    header_files = {}
    offset = 0
    payload = bytearray()
    for name, data in files.items():
        header_files[name] = {"offset": str(offset), "size": len(data)}
        payload.extend(data)
        offset += len(data)
    header = {"files": header_files}
    header_pickle = _pickle_string(json.dumps(header, separators=(",", ":")))
    size_pickle = _pickle_uint32(len(header_pickle))
    path.write_bytes(size_pickle + header_pickle + bytes(payload))


def _pickle_uint32(value: int) -> bytes:
    return struct.pack("<II", 4, value)


def _pickle_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    payload = struct.pack("<i", len(encoded)) + encoded
    padding = (4 - (len(payload) % 4)) % 4
    payload += b"\x00" * padding
    return struct.pack("<I", len(payload)) + payload


class AsarToolsTests(unittest.TestCase):
    def test_extract_asar_retries_access_denied_into_fresh_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "app.asar"
            archive.write_bytes(b"asar")
            destination_base = root / "extracted_asar"
            calls: list[list[str]] = []

            def resolve_command_side_effect(candidates):
                executable = candidates[0][0]
                if executable == "asar":
                    return [str(root / "asar.cmd")]
                if executable == "npx":
                    return [str(root / "npx.cmd")]
                return None

            def run_command_side_effect(command, *, cwd=None, timeout=300):
                calls.append(command)
                destination = Path(command[-1])
                destination.mkdir(parents=True, exist_ok=True)
                if Path(command[0]).name == "asar.cmd":
                    (destination / "partial.tmp").write_text("partial", encoding="utf-8")
                    return 1, "", "Access is denied."
                (destination / "package.json").write_text('{"name":"ok"}', encoding="utf-8")
                return 0, "", ""

            with (
                patch("re_pro.asar_tools.resolve_command", side_effect=resolve_command_side_effect),
                patch("re_pro.asar_tools.run_command", side_effect=run_command_side_effect),
            ):
                extracted, error = extract_asar_archive(archive, destination_base, cwd=root)

            self.assertEqual(error, "")
            self.assertEqual(extracted, root / "extracted_asar_1")
            self.assertTrue((root / "extracted_asar" / "partial.tmp").exists())
            self.assertTrue((root / "extracted_asar_1" / "package.json").exists())
            self.assertEqual(Path(calls[0][0]).name, "asar.cmd")
            self.assertEqual(Path(calls[1][0]).name, "npx.cmd")

    def test_extract_asar_falls_back_to_native_python_when_commands_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "app.asar"
            _write_minimal_asar(archive, {"package.json": b'{"name":"native"}', "main.js": b"console.log(1);"})

            def resolve_command_side_effect(candidates):
                executable = candidates[0][0]
                if executable == "asar":
                    return [str(root / "asar.cmd")]
                if executable == "npx":
                    return [str(root / "npx.cmd")]
                if executable == "node":
                    return None
                return None

            def run_command_side_effect(command, *, cwd=None, timeout=300):
                destination = Path(command[-1])
                destination.mkdir(parents=True, exist_ok=True)
                (destination / "partial.tmp").write_text("partial", encoding="utf-8")
                return 1, "", "Access is denied."

            with (
                patch("re_pro.asar_tools.resolve_command", side_effect=resolve_command_side_effect),
                patch("re_pro.asar_tools.run_command", side_effect=run_command_side_effect),
            ):
                extracted, error = extract_asar_archive(archive, root / "extracted_asar", cwd=root)

            self.assertEqual(error, "")
            self.assertEqual(extracted, root / "extracted_asar_2")
            self.assertEqual((extracted / "package.json").read_text(encoding="utf-8"), '{"name":"native"}')
            self.assertEqual((extracted / "main.js").read_text(encoding="utf-8"), "console.log(1);")


if __name__ == "__main__":
    unittest.main()
