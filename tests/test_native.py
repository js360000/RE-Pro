from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import struct

from tests import _path_setup  # noqa: F401

from re_pro.elf import parse_elf_metadata, parse_elf_needed_libraries, parse_elf_program_headers, parse_elf_sections, parse_elf_symbols
from re_pro.analyzers.native import NativeLanguageAnalyzer
from re_pro.engine import AnalysisContext
from re_pro.models import AnalysisReport


class NativeAnalyzerTests(unittest.TestCase):
    def test_parse_elf_metadata_and_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.elf"
            target.write_bytes(self._build_minimal_elf64())

            metadata = parse_elf_metadata(target)
            sections = parse_elf_sections(target)
            symbols = parse_elf_symbols(target)
            needed = parse_elf_needed_libraries(target)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["machine"], "x86_64")
            self.assertEqual(metadata["type"], "executable")
            self.assertIn(".text", metadata["sections"])
            self.assertTrue(any(section.get("name") == ".dynamic" for section in sections))
            self.assertTrue(any(symbol.get("name") == "main" for symbol in symbols))
            self.assertEqual(needed, ["libstdc++.so.6"])

    def test_parse_sectionless_mips_elf_program_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "OPNPS2LD.ELF"
            target.write_bytes(self._build_minimal_mips_elf32_sectionless())

            metadata = parse_elf_metadata(target)
            program_headers = parse_elf_program_headers(target)

            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertEqual(metadata["machine"], "MIPS")
            self.assertEqual(metadata["endianness"], "little")
            self.assertEqual(metadata["section_header_count"], 0)
            self.assertEqual(metadata["mips_flags"]["machine_variant"], "R5900")
            self.assertEqual(program_headers[0]["type_name"], "LOAD")
            self.assertIn("EXECUTE", program_headers[0]["flag_names"])

    def test_dos_stub_string_alone_does_not_mark_cpp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["This program cannot be run in DOS mode"],
                probable_binary=True,
            )

            NativeLanguageAnalyzer().analyze(context, report)

            self.assertNotIn("Native C/C++ binary", report.frameworks)

    def test_cpp_markers_and_symbol_dump_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample.exe"
            target.write_bytes(b"MZ")
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["__CxxFrameHandler4", "std::bad_alloc"],
                probable_binary=True,
                pe_metadata={"machine": "x64"},
                pe_imports=["user32.dll"],
            )

            def resolve_command_side_effect(candidates):
                executable = candidates[0][0]
                if executable == "llvm-nm":
                    return ["llvm-nm"]
                return None

            with (
                patch("re_pro.analyzers.native.resolve_command", side_effect=resolve_command_side_effect),
                patch("re_pro.analyzers.native.run_command", return_value=(0, "00000000 T main\n", "")),
            ):
                NativeLanguageAnalyzer().analyze(context, report)

            self.assertIn("Native C/C++ application", report.frameworks)
            self.assertTrue(
                any(artifact.description.startswith("Native symbol listing produced by llvm-nm") for artifact in report.artifacts)
            )

    def test_elf_markers_and_capstone_preview_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "sample"
            target.write_bytes(b"\x90" * 512)
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=["std::bad_alloc", "__gxx_personality_v0"],
                probable_binary=True,
                elf_metadata={"machine": "x86_64", "type": "executable", "bits": 64, "endianness": "little"},
                elf_sections=[
                    {
                        "name": ".text",
                        "offset": 0,
                        "size": 64,
                        "address": 0x401000,
                        "flag_names": ["ALLOC", "EXECINSTR"],
                    }
                ],
                elf_symbols=[
                    {
                        "name": "main",
                        "value": 0x401000,
                        "binding": "GLOBAL",
                        "type": "FUNC",
                        "section_name": ".text",
                    }
                ],
                elf_needed_libraries=["libstdc++.so.6", "libc.so.6"],
                elf_interpreter="/lib64/ld-linux-x86-64.so.2",
            )

            class FakeInstruction:
                def __init__(self, address, mnemonic, op_str):
                    self.address = address
                    self.mnemonic = mnemonic
                    self.op_str = op_str

            class FakeCs:
                def __init__(self, arch, mode):
                    self.detail = False

                def disasm(self, payload, address):
                    return [
                        FakeInstruction(address, "push", "rbp"),
                        FakeInstruction(address + 1, "mov", "rbp, rsp"),
                    ]

            class FakeCapstone:
                CS_ARCH_X86 = 1
                CS_ARCH_ARM = 2
                CS_ARCH_ARM64 = 3
                CS_ARCH_MIPS = 4
                CS_MODE_32 = 1
                CS_MODE_64 = 2
                CS_MODE_ARM = 4
                CS_MODE_LITTLE_ENDIAN = 0
                CS_MODE_BIG_ENDIAN = 0x80000000
                Cs = FakeCs

            with patch.object(NativeLanguageAnalyzer, "_load_capstone", return_value=FakeCapstone):
                NativeLanguageAnalyzer().analyze(context, report)

            self.assertIn("ELF", report.frameworks)
            self.assertIn("Linux ELF executable", report.frameworks)
            self.assertIn("Native C/C++ application", report.frameworks)
            self.assertTrue(any(artifact.description == "Capstone ELF entry/text preview" for artifact in report.artifacts))
            self.assertTrue(any(artifact.description == "ELF symbol listing (parsed)" for artifact in report.artifacts))

    def test_sectionless_mips_ps2_markers_use_program_header_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "OPNPS2LD.ELF"
            target.write_bytes(b"\x00" * 512)
            report = AnalysisReport(target=str(target), output_dir=str(root / "out"))
            context = AnalysisContext(
                target=target,
                output_dir=root / "out",
                ascii_strings=[],
                probable_binary=True,
                elf_metadata={
                    "machine": "MIPS",
                    "type": "executable",
                    "bits": 32,
                    "endianness": "little",
                    "mips_flags": {"machine_variant": "R5900", "arch": "MIPS III", "abi": None, "flags": []},
                },
                elf_program_headers=[
                    {
                        "index": 0,
                        "type_name": "LOAD",
                        "offset": 0,
                        "file_size": 64,
                        "virtual_address": 0x100000,
                        "flag_names": ["READ", "EXECUTE"],
                    }
                ],
                elf_sections=[],
                elf_symbols=[],
                elf_needed_libraries=[],
                elf_interpreter=None,
            )

            class FakeInstruction:
                def __init__(self, address, mnemonic, op_str):
                    self.address = address
                    self.mnemonic = mnemonic
                    self.op_str = op_str

            class FakeCs:
                def __init__(self, arch, mode):
                    self.detail = False

                def disasm(self, payload, address):
                    return [
                        FakeInstruction(address, "lui", "$t0, 0x1234"),
                        FakeInstruction(address + 4, "jr", "$ra"),
                    ]

            class FakeCapstone:
                CS_ARCH_X86 = 1
                CS_ARCH_ARM = 2
                CS_ARCH_ARM64 = 3
                CS_ARCH_MIPS = 4
                CS_MODE_32 = 1
                CS_MODE_64 = 2
                CS_MODE_ARM = 4
                CS_MODE_LITTLE_ENDIAN = 0
                CS_MODE_BIG_ENDIAN = 0x80000000
                Cs = FakeCs

            with patch.object(NativeLanguageAnalyzer, "_load_capstone", return_value=FakeCapstone):
                NativeLanguageAnalyzer().analyze(context, report)

            self.assertIn("MIPS ELF", report.frameworks)
            self.assertIn("MIPS little-endian ELF", report.frameworks)
            self.assertIn("PlayStation 2 ELF", report.frameworks)
            self.assertIn("Sectionless ELF", report.frameworks)
            self.assertTrue(any(artifact.description == "Capstone ELF entry/text preview" for artifact in report.artifacts))

    @staticmethod
    def _build_minimal_elf64() -> bytes:
        data = bytearray(0x900)
        data[0:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        data[6] = 1
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0x401000, 0, 0x400, 0, 64, 0, 0, 64, 6, 5)

        shstrtab = b"\x00.text\x00.dynstr\x00.dynsym\x00.dynamic\x00.shstrtab\x00"
        dynstr = b"\x00libstdc++.so.6\x00main\x00"
        text = b"\x55\x48\x89\xe5\xc3"
        dynsym = bytearray(48)
        struct.pack_into("<IBBHQQ", dynsym, 24, 16, 0x12, 0, 1, 0x401000, 5)
        dynamic = bytearray(32)
        struct.pack_into("<QQ", dynamic, 0, 1, 1)
        struct.pack_into("<QQ", dynamic, 16, 0, 0)

        text_offset = 0x100
        dynstr_offset = 0x200
        dynsym_offset = 0x300
        dynamic_offset = 0x340
        shstr_offset = 0x380

        data[text_offset : text_offset + len(text)] = text
        data[dynstr_offset : dynstr_offset + len(dynstr)] = dynstr
        data[dynsym_offset : dynsym_offset + len(dynsym)] = dynsym
        data[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
        data[shstr_offset : shstr_offset + len(shstrtab)] = shstrtab

        section_offset = 0x400
        headers = [
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (1, 1, 0x6, 0x401000, text_offset, len(text), 0, 0, 16, 0),
            (7, 3, 0x2, 0, dynstr_offset, len(dynstr), 0, 0, 1, 0),
            (15, 0x0B, 0x2, 0x402000, dynsym_offset, len(dynsym), 2, 1, 8, 24),
            (23, 0x06, 0x2, 0x403000, dynamic_offset, len(dynamic), 2, 0, 8, 16),
            (32, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0),
        ]
        for index, header in enumerate(headers):
            struct.pack_into("<IIQQQQIIQQ", data, section_offset + (index * 64), *header)
        return bytes(data)

    @staticmethod
    def _build_minimal_mips_elf32_sectionless() -> bytes:
        data = bytearray(0x200)
        data[0:4] = b"\x7fELF"
        data[4] = 1
        data[5] = 1
        data[6] = 1
        # EF_MIPS_ARCH_3 | EF_MIPS_MACH_5900
        struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 0x08, 1, 0x00100000, 52, 0, 0x20920000, 52, 32, 1, 0, 0, 0)
        struct.pack_into("<IIIIIIII", data, 52, 1, 0x100, 0x00100000, 0x00100000, 0x40, 0x40, 0x5, 16)
        data[0x100 : 0x108] = b"\x3c\x08\x12\x34\x03\xe0\x00\x08"
        return bytes(data)


if __name__ == "__main__":
    unittest.main()
