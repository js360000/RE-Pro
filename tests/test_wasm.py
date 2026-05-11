from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.engine import ReverseEngineeringEngine
from re_pro.wasm import parse_wasm_module
from tests import _path_setup  # noqa: F401


class WasmAnalyzerTests(unittest.TestCase):
    def test_wasm_analysis_parses_module_and_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wasm_path = root / "module.wasm"
            wasm_path.write_bytes(_build_test_wasm_module())
            (root / "module.wasm.map").write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "module.wasm",
                        "sources": ["src/lib.rs"],
                        "sourcesContent": ["pub fn run() {}\n"],
                    }
                ),
                encoding="utf-8",
            )

            engine = ReverseEngineeringEngine(output_root=root / "out")
            report = engine.analyze(wasm_path)

            self.assertEqual(report.target_type, "wasm-module")
            self.assertIn("WebAssembly (WASM)", report.frameworks)
            self.assertIn("WebAssembly toolchain: wasm-bindgen", report.frameworks)
            self.assertIn("WebAssembly language: Rust", report.frameworks)
            self.assertGreaterEqual(len(report.recovered_sources), 1)
            self.assertTrue(any("WASM sourceMappingURL: module.wasm.map" in note for note in report.notes))

            index_artifact = next(artifact for artifact in report.artifacts if artifact.description == "Unified analysis index")
            payload = json.loads(Path(index_artifact.path).read_text(encoding="utf-8"))
            entity_ids = {f"{entity['kind']}:{entity['key']}" for entity in payload["entities"]}
            self.assertIn("format:wasm:module.wasm", entity_ids)
            self.assertIn("import:env::__wbindgen_malloc", entity_ids)
            self.assertIn("export:__wbindgen_start", entity_ids)

    def test_parse_wasm_module_reads_imports_exports_and_custom_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            wasm_path = Path(temp_dir) / "probe.wasm"
            wasm_path.write_bytes(_build_test_wasm_module())
            payload = parse_wasm_module(wasm_path)
            self.assertIsNotNone(payload)
            assert payload is not None
            self.assertEqual(payload["version"], 1)
            self.assertEqual(payload["imports"][0]["module"], "env")
            self.assertEqual(payload["exports"][0]["name"], "__wbindgen_start")
            self.assertEqual(payload["source_mapping_url"], "module.wasm.map")


def _build_test_wasm_module() -> bytes:
    def section(section_id: int, payload: bytes) -> bytes:
        return bytes([section_id]) + _uleb(len(payload)) + payload

    def name(value: str) -> bytes:
        encoded = value.encode("utf-8")
        return _uleb(len(encoded)) + encoded

    magic = b"\x00asm" + (1).to_bytes(4, "little")
    type_section = section(1, _uleb(1) + b"\x60\x00\x00")
    import_section = section(2, _uleb(1) + name("env") + name("__wbindgen_malloc") + b"\x00" + _uleb(0))
    export_section = section(7, _uleb(1) + name("__wbindgen_start") + b"\x00" + _uleb(0))
    producers_body = (
        _uleb(2)
        + name("language")
        + _uleb(1)
        + name("Rust")
        + name("1.78.0")
        + name("processed-by")
        + _uleb(1)
        + name("wasm-bindgen")
        + name("0.2.92")
    )
    producers_section = section(0, name("producers") + producers_body)
    source_map_section = section(0, name("sourceMappingURL") + name("module.wasm.map"))
    return magic + type_section + import_section + export_section + producers_section + source_map_section


def _uleb(value: int) -> bytes:
    parts = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            parts.append(byte | 0x80)
        else:
            parts.append(byte)
            return bytes(parts)


if __name__ == "__main__":
    unittest.main()
