from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import brotli

from re_pro.frontend_reconstruct import reconstruct_bundled_frontend_assets
from re_pro.models import LlmAssistSettings
from re_pro.tauri_extract import extract_tauri_assets, scan_tauri_asset_entries
from tests import _path_setup  # noqa: F401


class TauriExtractTests(unittest.TestCase):
    def test_scan_and_extract_tauri_asset_entries(self) -> None:
        image_base = 0x140000000
        rdata = bytearray(0x800)
        key = b"/assets/index-test.js"
        raw = b"console.log('hello');"
        compressed = brotli.compress(raw)

        key_offset = 0x220
        data_offset = key_offset + len(key)
        table_offset = 0x120

        rdata[key_offset : key_offset + len(key)] = key
        rdata[data_offset : data_offset + len(compressed)] = compressed
        key_va = image_base + 0x1000 + key_offset
        data_va = image_base + 0x1000 + data_offset
        struct.pack_into("<QQQQ", rdata, table_offset, key_va, len(key), data_va, len(compressed))

        sections = [
            {
                "name": ".rdata",
                "virtual_address": 0x1000,
                "raw_offset": 0,
                "raw_size": 0x400,
            }
        ]
        entries = scan_tauri_asset_entries(bytes(rdata), image_base, sections)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].key, "/assets/index-test.js")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(_make_fake_pe(bytes(rdata), image_base))
            result = extract_tauri_assets(target, root / "tauri", root / "sources")
            extracted_file = root / "tauri" / "assets" / "assets" / "index-test.js"
            self.assertEqual(result["extracted_count"], 1)
            self.assertTrue(extracted_file.exists())
            self.assertEqual(extracted_file.read_bytes(), raw)

    def test_scan_and_extract_nextjs_source_map_entries(self) -> None:
        image_base = 0x140000000
        rdata = bytearray(0x4000)
        key = b"/_next/static/chunks/app-test.js.map"
        raw = (
            b'{'
            b'"version":3,'
            b'"file":"app-test.js",'
            b'"sources":["webpack://_N_E/src/app/page.tsx"],'
            b'"sourcesContent":["export default function Page() { return null; }"]'
            b"}"
        )
        compressed = brotli.compress(raw)

        key_offset = 0x600
        data_offset = 0x900
        table_offset = 0x200

        rdata[key_offset : key_offset + len(key)] = key
        rdata[data_offset : data_offset + len(compressed)] = compressed
        key_va = image_base + 0x1000 + key_offset
        data_va = image_base + 0x1000 + data_offset
        struct.pack_into("<QQQQ", rdata, table_offset, key_va, len(key), data_va, len(compressed))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(_make_fake_pe(bytes(rdata), image_base))
            result = extract_tauri_assets(target, root / "tauri", root / "sources")
            extracted_map = root / "tauri" / "assets" / "_next" / "static" / "chunks" / "app-test.js.map"
            restored_source = root / "sources" / "app-test.js" / "_N_E" / "src" / "app" / "page.tsx"
            self.assertEqual(result["extracted_count"], 1)
            self.assertTrue(extracted_map.exists())
            self.assertTrue(restored_source.exists())

    def test_reconstruct_bundled_frontend_assets_without_source_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            assets_dir = root / "tauri" / "assets"
            js_path = assets_dir / "assets" / "index-test.js"
            css_path = assets_dir / "assets" / "index-test.css"
            json_path = assets_dir / "manifest.json"
            png_path = assets_dir / "assets" / "logo.png"
            js_path.parent.mkdir(parents=True)
            js_path.write_text("function main(){const value=1;console.log(value)}main();", encoding="utf-8")
            css_path.write_text("body{margin:0;color:red}.app{display:flex}", encoding="utf-8")
            json_path.write_text('{"name":"demo","start_url":"/"}', encoding="utf-8")
            png_path.write_bytes(b"\x89PNG")
            manifest_path = root / "tauri" / "extracted_assets_manifest.json"
            manifest_path.write_text(
                json.dumps(
                    [
                        {"key": "/assets/index-test.js", "path": str(js_path), "raw_size": js_path.stat().st_size},
                        {"key": "/assets/index-test.css", "path": str(css_path), "raw_size": css_path.stat().st_size},
                        {"key": "/manifest.json", "path": str(json_path), "raw_size": json_path.stat().st_size},
                        {"key": "/assets/logo.png", "path": str(png_path), "raw_size": png_path.stat().st_size},
                    ]
                ),
                encoding="utf-8",
            )

            result = reconstruct_bundled_frontend_assets(assets_dir, manifest_path, root / "recovered_sources")

            self.assertEqual(result["recovered_count"], 3)
            restored_js = root / "recovered_sources" / "tauri_bundle" / "assets" / "index-test.js"
            restored_css = root / "recovered_sources" / "tauri_bundle" / "assets" / "index-test.css"
            restored_json = root / "recovered_sources" / "tauri_bundle" / "manifest.json"
            self.assertTrue(restored_js.exists())
            self.assertTrue(restored_css.exists())
            self.assertTrue(restored_json.exists())
            self.assertIn("bundled asset reconstruction", restored_js.read_text(encoding="utf-8"))
            self.assertIn("\n", restored_js.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(restored_json.read_text(encoding="utf-8"))["name"], "demo")
            self.assertTrue((root / "recovered_sources" / "tauri_bundle" / "BUNDLE_RECONSTRUCTION_MANIFEST.json").exists())

    def test_reconstruct_bundled_frontend_assets_lifts_jsx_and_rewrites_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            assets_dir = root / "assets"
            assets_dir.mkdir()
            banner = assets_dir / "banner-B9VgUWZ2.js"
            runtime = assets_dir / "jsx-runtime-ebkFq_df.js"
            logger = assets_dir / "logger-VlXfBBlQ.js"
            chevron = assets_dir / "chevron-D6MfOAjU.js"
            banner.write_text(
                "import{t}from'./jsx-runtime-ebkFq_df.js';"
                "import{o as e}from'./logger-VlXfBBlQ.js';"
                "import{n}from'./chevron-D6MfOAjU.js';"
                "var a=t();"
                "function o(e){let t=(0,i.c)(4),s=Symbol.for(`react.early_return_sentinel`),{title:r}=e;return(0,a.jsxs)(`div`,{children:[(0,a.jsx)(n,{}),(0,a.jsx)(`h3`,{children:r})]})}"
                "export{o as t};"
                "//# sourceMappingURL=banner-B9VgUWZ2.js.map",
                encoding="utf-8",
            )
            runtime.write_text("export const t=()=>({jsx(){}});", encoding="utf-8")
            logger.write_text("export function o(){}", encoding="utf-8")
            chevron.write_text("export function n(){return null}", encoding="utf-8")

            result = reconstruct_bundled_frontend_assets(assets_dir, root / "missing_manifest.json", root / "sources")

            self.assertEqual(result["recovered_count"], 4)
            restored = root / "sources" / "tauri_bundle" / "banner.js"
            text = restored.read_text(encoding="utf-8")
            self.assertIn("from './jsx-runtime.js'", text)
            self.assertIn("from './logger.js'", text)
            self.assertIn("from './chevron.js'", text)
            self.assertIn("t as createJsxRuntime", text)
            self.assertIn("o as createLogger", text)
            self.assertIn("n as Chevron", text)
            self.assertLess(text.index("from './chevron.js'"), text.index("const REACT_EARLY_RETURN_SENTINEL"))
            self.assertIn("const jsxRuntime =", text)
            self.assertIn("function Banner(", text)
            self.assertIn("export { Banner as t }", text)
            self.assertIn("function Banner(props)", text)
            self.assertIn("<Chevron />", text)
            self.assertIn("<h3>{title}</h3>", text)
            self.assertIn("Source-lift features:", text)
            manifest = json.loads((root / "sources" / "tauri_bundle" / "BUNDLE_RECONSTRUCTION_MANIFEST.json").read_text(encoding="utf-8"))
            banner_entry = next(item for item in manifest["files"] if item["cleaned_path"] == "banner.js")
            self.assertTrue(banner_entry["source_lift"]["ast"]["ok"])
            self.assertEqual(banner_entry["source_lift"]["equivalence"]["missing_relative_imports"], [])
            self.assertIn("module_graph", manifest)
            self.assertIn("llm_source_grade", manifest)

    def test_reconstruct_bundled_frontend_assets_optionally_runs_llm_source_grade(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            assets_dir = root / "assets"
            assets_dir.mkdir()
            (assets_dir / "panel-A1b2C3d4.js").write_text(
                "import{t}from'./jsx-runtime-ebkFq_df.js';var a=t();function o(e){let{title:n}=e;return(0,a.jsx)(`h3`,{children:n})}export{o as t};",
                encoding="utf-8",
            )
            (assets_dir / "jsx-runtime-ebkFq_df.js").write_text("export const t=()=>({jsx(){}});", encoding="utf-8")

            result = reconstruct_bundled_frontend_assets(
                assets_dir,
                root / "missing_manifest.json",
                root / "sources",
                llm_settings=LlmAssistSettings(enabled=True, background=False),
                llm_client_factory=_FakeFrontendLlmClient,
            )

            manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["llm_source_grade"]["status"], "completed")
            self.assertGreaterEqual(manifest["llm_source_grade"]["rewritten_count"], 1)
            llm_outputs = list((root / "sources" / "tauri_bundle" / "SOURCE_GRADE_LLM").glob("*.source-grade.tsx"))
            self.assertTrue(llm_outputs)
            self.assertIn("SourceGradePanel", llm_outputs[0].read_text(encoding="utf-8"))


def _make_fake_pe(rdata_bytes: bytes, image_base: int) -> bytes:
    data = bytearray(max(0x1200, 0x200 + len(rdata_bytes)))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x80 + 24 + 24, image_base)
    section_offset = 0x80 + 24 + 0xF0
    data[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", data, section_offset + 8, len(rdata_bytes), 0x1000, len(rdata_bytes), 0x200)
    data[0x200 : 0x200 + len(rdata_bytes)] = rdata_bytes
    return bytes(data)


class _FakeFrontendLlmClient:
    class responses:
        @staticmethod
        def create(**kwargs):
            del kwargs
            return type("Response", (), {"output_text": "export function SourceGradePanel() { return <h3 />; }\n"})()


if __name__ == "__main__":
    unittest.main()
