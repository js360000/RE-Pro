from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from re_pro.msvc_pseudo_cpp import RECOVERY_CAPABILITIES, enrich_recovered_classes, write_pseudo_class_sources
from tests import _path_setup  # noqa: F401


class MsvcPseudoCppTests(unittest.TestCase):
    def test_write_pseudo_class_sources_merges_targeted_decompilation(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": ["Base"],
                    "methods": [
                        {
                            "name": "vf_140001000",
                            "slot": 0,
                            "address": "0x140001000",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001000",
                "name": "sub_140001000",
                "signature": "undefined8 sub_140001000(void)",
                "return_type": "undefined8",
                "parameters": [],
                "callers": [
                    {"caller_name": "main", "caller_entry_point": "0x140000100"},
                    {"caller_name": "dispatch", "caller_entry_point": "0x140000200"},
                ],
                "caller_count": 2,
                "decompile_success": True,
                "decompiled_c": "undefined8 sub_140001000(void)\n{\n  return 1;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            generated = write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            self.assertEqual(len(generated), 2)
            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Foo.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual undefined8 vf_140001000(void);", header_text)
            self.assertIn("undefined8 Foo::vf_140001000(void) {", source_text)
            self.assertIn("return 1;", source_text)
            self.assertIn("Observed direct callers: 2", source_text)
            self.assertIn("Caller examples: main, dispatch", source_text)
            self.assertIn("Decompiled from Ghidra function: sub_140001000", source_text)

    def test_write_pseudo_class_sources_infers_deleting_destructor_metadata(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {
                            "name": "vf_140001040",
                            "slot": 1,
                            "address": "0x140001040",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001040",
                "name": "scalar_deleting_destructor",
                "signature": "void __thiscall scalar_deleting_destructor(Foo *this, uint flags)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                    {"ordinal": 1, "name": "flags", "data_type": "uint", "storage": "RDX"},
                ],
                "decompile_success": True,
                "decompiled_c": "void __thiscall scalar_deleting_destructor(Foo *this, uint flags)\n{\n  operator_delete(this,flags);\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Foo.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual void __scalar_deleting_destructor(uint flags);", header_text)
            self.assertIn("void Foo::__scalar_deleting_destructor(uint flags) {", source_text)
            self.assertIn("Inferred method role: scalar_deleting_destructor", source_text)
            self.assertIn("Human-readable alias: ~Foo", source_text)

    def test_write_pseudo_class_sources_uses_callsite_hints_to_improve_param_names(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {
                            "name": "vf_140001080",
                            "slot": 2,
                            "address": "0x140001080",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001080",
                "name": "sub_140001080",
                "signature": "undefined8 sub_140001080(Foo *this, undefined8 param_1)",
                "return_type": "undefined8",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "undefined8", "storage": "RDX"},
                ],
                "callers": [
                    {
                        "caller_name": "main",
                        "argument_hints": [
                            {"position": 0, "storage": "RCX", "name_hint": "this", "type_hint": "Foo *"},
                            {"position": 1, "storage": "RDX", "name_hint": "path", "type_hint": "const char *", "source_repr": "\"config.json\""},
                        ],
                    }
                ],
                "caller_count": 1,
                "decompile_success": True,
                "decompiled_c": "undefined8 sub_140001080(Foo *this, undefined8 param_1)\n{\n  return 0;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual undefined8 vf_140001080(const char * path);", header_text)

    def test_write_pseudo_class_sources_uses_result_hints_to_improve_return_type(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {
                            "name": "vf_1400010c0",
                            "slot": 3,
                            "address": "0x1400010c0",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x1400010c0",
                "name": "sub_1400010c0",
                "signature": "undefined8 sub_1400010c0(Foo *this)",
                "return_type": "undefined8",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                ],
                "result_hints": [
                    {"type_hint": "bool", "reason": "result_tested_for_branch", "sample": "JZ LAB_1400100"}
                ],
                "callers": [
                    {
                        "caller_name": "main",
                        "result_hint": {"type_hint": "bool", "reason": "result_tested_for_branch", "sample": "JZ LAB_1400100"},
                    }
                ],
                "caller_count": 1,
                "decompile_success": True,
                "decompiled_c": "undefined8 sub_1400010c0(Foo *this)\n{\n  return 1;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Foo.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual bool vf_1400010c0(void);", header_text)
            self.assertIn("Return type inferred from callsite usage: result_tested_for_branch", source_text)

    def test_write_pseudo_class_sources_uses_body_hints_to_improve_param_names(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {
                            "name": "vf_140001140",
                            "slot": 4,
                            "address": "0x140001140",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001140",
                "name": "sub_140001140",
                "signature": "void sub_140001140(Foo *this, undefined8 param_1, undefined8 param_2)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "undefined8", "storage": "RDX"},
                    {"ordinal": 2, "name": "param_2", "data_type": "undefined8", "storage": "R8"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "void sub_140001140(Foo *this, undefined8 param_1, undefined8 param_2)\n"
                    "{\n"
                    "  MessageBoxA((HWND)0x0,param_2,param_1,0);\n"
                    "}"
                ),
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual void ShowAlert(const char * title, const char * message);", header_text)

    def test_write_pseudo_class_sources_infers_semantic_names_for_generic_vtable_methods(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001500", "slot": 0, "address": "0x140001500", "vtable_rva": "0x2128"},
                        {"name": "vf_140001520", "slot": 1, "address": "0x140001520", "vtable_rva": "0x2128"},
                        {"name": "vf_140001540", "slot": 2, "address": "0x140001540", "vtable_rva": "0x2128"},
                    ],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001560", "slot": 0, "address": "0x140001560", "vtable_rva": "0x2228"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001500",
                "name": "sub_140001500",
                "signature": "char * sub_140001500(Fixture::AppController *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * sub_140001500(Fixture::AppController *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&this->display_name_);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001520",
                "name": "sub_140001520",
                "signature": "void sub_140001520(Fixture::AppController *this, wchar_t * param_1)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "wchar_t *", "storage": "RDX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "void sub_140001520(Fixture::AppController *this, wchar_t * param_1)\n"
                    "{\n"
                    "  std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::operator=(&this->config_path_w_,param_1);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001540",
                "name": "sub_140001540",
                "signature": "Fixture::ILogger * sub_140001540(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "Fixture::ILogger * sub_140001540(Fixture::AppController *this)\n"
                    "{\n"
                    "  return (Fixture::ILogger *)&this->logger_;\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001560",
                "name": "sub_140001560",
                "signature": "void sub_140001560(Fixture::ConsoleLogger *this, char * param_1)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::ConsoleLogger *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "char *", "storage": "RDX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "void sub_140001560(Fixture::ConsoleLogger *this, char * param_1)\n"
                    "{\n"
                    "  OutputDebugStringA(param_1);\n"
                    "}"
                ),
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            app_header = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")
            app_source = (Path(temp_dir) / "Fixture__AppController.cpp").read_text(encoding="utf-8")
            logger_header = (Path(temp_dir) / "Fixture__ConsoleLogger.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual const char * GetDisplayName(void);", app_header)
            self.assertIn("virtual void SetConfigPathW(const wchar_t * path);", app_header)
            self.assertIn("virtual Fixture::ILogger * GetLogger(void);", app_header)
            self.assertIn("virtual void Log(const char * message);", logger_header)
            self.assertIn("Method name inferred from string_member_c_str: c_str(&this->display_name_)", app_source)
            self.assertIn("Original recovered vtable name: vf_140001500", app_source)

    def test_write_pseudo_class_sources_promotes_c_str_returns_to_const(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {
                            "name": "vf_140001180",
                            "slot": 5,
                            "address": "0x140001180",
                            "vtable_rva": "0x2128",
                        }
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001180",
                "name": "CurrentName",
                "signature": "char * CurrentName(Foo *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * CurrentName(Foo *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&this->name_);\n"
                    "}"
                ),
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Foo.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual const char * CurrentName(void);", header_text)
            self.assertIn("Return type inferred from callsite usage: string_c_str_return", source_text)

    def test_write_pseudo_class_sources_assigns_unique_pure_virtual_slot_names(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "IFoo",
                    "kind": "class",
                    "mangled_name": ".?AVIFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_1400011c0", "slot": 0, "address": "0x1400011c0", "vtable_rva": "0x2128"},
                        {"name": "vf_1400011d0", "slot": 1, "address": "0x1400011d0", "vtable_rva": "0x2128"},
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x1400011c0",
                "name": "_purecall",
                "signature": "undefined8 _purecall(void)",
                "return_type": "undefined8",
                "parameters": [],
                "decompile_success": True,
                "decompiled_c": "undefined8 _purecall(void)\n{\n  return 0;\n}",
            },
            {
                "entry_point": "0x1400011d0",
                "name": "_purecall",
                "signature": "undefined8 _purecall(void)",
                "return_type": "undefined8",
                "parameters": [],
                "decompile_success": True,
                "decompiled_c": "undefined8 _purecall(void)\n{\n  return 0;\n}",
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "IFoo.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual undefined8 __pure_virtual_slot_0(void) = 0;", header_text)
            self.assertIn("virtual undefined8 __pure_virtual_slot_1(void) = 0;", header_text)

    def test_write_pseudo_class_sources_infers_repeated_unresolved_vtable_targets_as_pure_virtual(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "IFoo",
                    "kind": "class",
                    "mangled_name": ".?AVIFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_1400011f0", "slot": 0, "address": "0x1400011f0", "vtable_rva": "0x2128"},
                        {"name": "vf_1400011f0", "slot": 1, "address": "0x1400011f0", "vtable_rva": "0x2128"},
                        {"name": "vf_1400011f0", "slot": 2, "address": "0x1400011f0", "vtable_rva": "0x2128"},
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered)

            header_text = (Path(temp_dir) / "IFoo.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "IFoo.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual void __pure_virtual_slot_0(void) = 0;", header_text)
            self.assertIn("virtual void __pure_virtual_slot_1(void) = 0;", header_text)
            self.assertIn("virtual void __pure_virtual_slot_2(void) = 0;", header_text)
            self.assertNotIn("TODO: map this stub", source_text)
            self.assertIn("declared pure virtual in the header", source_text)

    def test_write_pseudo_class_sources_emits_evidence_fallback_for_unresolved_methods(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Widget",
                    "kind": "class",
                    "mangled_name": ".?AVWidget@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001300", "slot": 4, "address": "0x140001300", "vtable_rva": "0x2128"},
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered)

            source_text = (Path(temp_dir) / "Widget.cpp").read_text(encoding="utf-8")

            self.assertNotIn("TODO", source_text)
            self.assertIn("Body unresolved in available decompiler exports", source_text)
            self.assertIn("return;", source_text)

    def test_write_pseudo_class_sources_uses_method_name_semantics_for_setters(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Foo",
                    "kind": "class",
                    "mangled_name": ".?AVFoo@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001200", "slot": 6, "address": "0x140001200", "vtable_rva": "0x2128"},
                        {"name": "vf_140001220", "slot": 7, "address": "0x140001220", "vtable_rva": "0x2128"},
                    ],
                }
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001200",
                "name": "SetConfigPathW",
                "signature": "void SetConfigPathW(Foo *this, wchar_t * param_1)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "wchar_t *", "storage": "RDX"},
                ],
                "decompile_success": True,
                "decompiled_c": "void SetConfigPathW(Foo *this, wchar_t * param_1)\n{\n  OutputDebugStringW(param_1);\n}",
            },
            {
                "entry_point": "0x140001220",
                "name": "ShowAlert",
                "signature": "void ShowAlert(Foo *this, char * param_1, char * param_2)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Foo *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "char *", "storage": "RDX"},
                    {"ordinal": 2, "name": "param_2", "data_type": "char *", "storage": "R8"},
                ],
                "decompile_success": True,
                "decompiled_c": "void ShowAlert(Foo *this, char * param_1, char * param_2)\n{\n  MessageBoxA((HWND)0x0,param_2,param_1,0);\n}",
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Foo.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual void SetConfigPathW(const wchar_t * path);", header_text)
            self.assertIn("virtual void ShowAlert(const char * title, const char * message);", header_text)

    def test_write_pseudo_class_sources_promotes_base_pointer_return_to_concrete_class(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Fixture::ILogger",
                    "kind": "class",
                    "mangled_name": ".?AVILogger@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": ["Fixture::ILogger"],
                    "methods": [
                        {"name": "vf_1400012e0", "slot": 0, "address": "0x1400012e0", "vtable_rva": "0x2028"},
                    ],
                },
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001260", "slot": 8, "address": "0x140001260", "vtable_rva": "0x2128"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001260",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "Fixture::ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "callers": [
                    {
                        "caller_name": "main",
                        "result_hint": {
                            "type_hint": "Fixture::ConsoleLogger *",
                            "reason": "result_forwarded_to_typed_parameter",
                            "callee": "Fixture::ConsoleLogger::SetName",
                            "argument_position": 0,
                        },
                    }
                ],
                "result_hints": [
                    {
                        "type_hint": "Fixture::ConsoleLogger *",
                        "reason": "result_forwarded_to_typed_parameter",
                        "callee": "Fixture::ConsoleLogger::SetName",
                        "argument_position": 0,
                    }
                ],
                "decompile_success": True,
                "decompiled_c": "Fixture::ILogger * GetLogger(Fixture::AppController *this)\n{\n  return &this->logger_;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual Fixture::ConsoleLogger * GetLogger(void);", header_text)

    def test_write_pseudo_class_sources_promotes_base_pointer_return_from_member_body(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Fixture::ILogger",
                    "kind": "class",
                    "mangled_name": ".?AVILogger@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": ["Fixture::ILogger"],
                    "methods": [
                        {"name": "vf_1400012e0", "slot": 0, "address": "0x1400012e0", "vtable_rva": "0x2028"},
                    ],
                },
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001280", "slot": 9, "address": "0x140001280", "vtable_rva": "0x2128"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001280",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "Fixture::ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "callers": [],
                "result_hints": [],
                "decompile_success": True,
                "decompiled_c": "Fixture::ILogger * GetLogger(Fixture::AppController *this)\n{\n  return (Fixture::ILogger *)&this->logger_;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Fixture__AppController.cpp").read_text(encoding="utf-8")

            self.assertIn("virtual Fixture::ConsoleLogger * GetLogger(void);", header_text)
            self.assertIn("Return type inferred from callsite usage: returned_member_matches_concrete_class", source_text)

    def test_write_pseudo_class_sources_promotes_unqualified_base_pointer_return_from_member_body(self) -> None:
        recovered = {
            "classes": [
                {
                    "name": "Fixture::ILogger",
                    "kind": "class",
                    "mangled_name": ".?AVILogger@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": ["Fixture::ILogger"],
                    "methods": [],
                },
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_1400012a0", "slot": 10, "address": "0x1400012a0", "vtable_rva": "0x2128"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x1400012a0",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "callers": [],
                "result_hints": [],
                "decompile_success": True,
                "decompiled_c": "ILogger * GetLogger(Fixture::AppController *this)\n{\n  return (ILogger *)&this->logger_;\n}",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")

            self.assertIn("virtual Fixture::ConsoleLogger * GetLogger(void);", header_text)

    def test_write_pseudo_class_sources_infers_member_layouts_from_method_bodies(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Fixture::ILogger",
                    "kind": "class",
                    "mangled_name": ".?AVILogger@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": ["Fixture::ILogger"],
                    "methods": [
                        {"name": "vf_1400012e0", "slot": 0, "address": "0x1400012e0", "vtable_rva": "0x2028"},
                    ],
                },
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001300", "slot": 0, "address": "0x140001300", "vtable_rva": "0x2128"},
                        {"name": "vf_140001320", "slot": 1, "address": "0x140001320", "vtable_rva": "0x2128"},
                        {"name": "vf_140001340", "slot": 2, "address": "0x140001340", "vtable_rva": "0x2128"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x1400012e0",
                "name": "CurrentName",
                "namespace": "Fixture::ConsoleLogger",
                "signature": "char * CurrentName(Fixture::ConsoleLogger *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::ConsoleLogger *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * CurrentName(Fixture::ConsoleLogger *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::c_str"
                    "(&this->name_);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001300",
                "name": "GetDisplayName",
                "namespace": "Fixture::AppController",
                "signature": "char * GetDisplayName(Fixture::AppController *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * GetDisplayName(Fixture::AppController *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::c_str"
                    "(&this->display_name_);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001320",
                "name": "SetConfigPathW",
                "namespace": "Fixture::AppController",
                "signature": "void SetConfigPathW(Fixture::AppController *this, wchar_t * param_1)",
                "return_type": "void",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                    {"ordinal": 1, "name": "param_1", "data_type": "wchar_t *", "storage": "RDX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "void SetConfigPathW(Fixture::AppController *this, wchar_t * param_1)\n"
                    "{\n"
                    "  std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>_>::operator="
                    "(&this->config_path_w_,param_1);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001340",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "Fixture::ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "result_hints": [
                    {
                        "type_hint": "Fixture::ConsoleLogger *",
                        "reason": "result_forwarded_to_typed_parameter",
                    }
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "Fixture::ILogger * GetLogger(Fixture::AppController *this)\n"
                    "{\n"
                    "  return (Fixture::ILogger *)&this->logger_;\n"
                    "}"
                ),
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")

            self.assertIn("// Estimated object size: 0x70", header_text)
            self.assertIn("private:", header_text)
            self.assertIn(
                "std::wstring config_path_w_; // inferred from std_wstring_member_usage, via virtual_method SetConfigPathW, approx +0x8, size 0x20, layout high",
                header_text,
            )
            self.assertIn(
                "std::string display_name_; // inferred from std_string_member_usage, via virtual_method GetDisplayName, approx +0x28, size 0x20, layout high",
                header_text,
            )
            self.assertIn(
                "Fixture::ConsoleLogger logger_; // inferred from returned_member_matches_concrete_class, via virtual_method GetLogger, approx +0x48, size 0x28, layout medium",
                header_text,
            )

    def test_write_pseudo_class_sources_prefers_constructor_member_order(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Fixture::ILogger",
                    "kind": "class",
                    "mangled_name": ".?AVILogger@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [],
                },
                {
                    "name": "Fixture::ConsoleLogger",
                    "kind": "class",
                    "mangled_name": ".?AVConsoleLogger@Fixture@@",
                    "type_descriptor_rva": "0x2100",
                    "base_classes": ["Fixture::ILogger"],
                    "methods": [
                        {"name": "vf_1400012e0", "slot": 0, "address": "0x1400012e0", "vtable_rva": "0x2028"},
                        {"name": "vf_1400012f0", "slot": 1, "address": "0x1400012f0", "vtable_rva": "0x2028"},
                    ],
                },
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001300", "slot": 0, "address": "0x140001300", "vtable_rva": "0x2128"},
                    ],
                },
            ]
        }
        decompiled_entries = [
            {
                "entry_point": "0x1400012e0",
                "name": "CurrentName",
                "namespace": "Fixture::ConsoleLogger",
                "signature": "char * CurrentName(Fixture::ConsoleLogger *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::ConsoleLogger *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * CurrentName(Fixture::ConsoleLogger *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::c_str"
                    "(&this->name_);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x1400012f0",
                "name": "ConsoleLogger",
                "namespace": "Fixture::ConsoleLogger",
                "signature": "ConsoleLogger * __thiscall ConsoleLogger(Fixture::ConsoleLogger *this)",
                "return_type": "ConsoleLogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::ConsoleLogger *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "ConsoleLogger * __thiscall ConsoleLogger(Fixture::ConsoleLogger *this)\n"
                    "{\n"
                    "  std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::basic_string(&this->name_);\n"
                    "  return this;\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001300",
                "name": "GetDisplayName",
                "namespace": "Fixture::AppController",
                "signature": "char * GetDisplayName(Fixture::AppController *this)",
                "return_type": "char *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "char * GetDisplayName(Fixture::AppController *this)\n"
                    "{\n"
                    "  return std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::c_str"
                    "(&this->display_name_);\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001320",
                "name": "AppController",
                "namespace": "Fixture::AppController",
                "signature": "AppController * __thiscall AppController(Fixture::AppController *this)",
                "return_type": "AppController *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "AppController * __thiscall AppController(Fixture::AppController *this)\n"
                    "{\n"
                    "  std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::basic_string(&this->display_name_);\n"
                    "  std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::basic_string(&this->config_path_a_);\n"
                    "  std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>_>::basic_string(&this->config_path_w_);\n"
                    "  ConsoleLogger(&this->logger_);\n"
                    "  return this;\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001340",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "Fixture::ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "result_hints": [
                    {"type_hint": "Fixture::ConsoleLogger *", "reason": "result_forwarded_to_typed_parameter"}
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "Fixture::ILogger * GetLogger(Fixture::AppController *this)\n"
                    "{\n"
                    "  return (Fixture::ILogger *)&this->logger_;\n"
                    "}"
                ),
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__AppController.hpp").read_text(encoding="utf-8")

            display_index = header_text.index("std::string display_name_;")
            path_a_index = header_text.index("std::string config_path_a_;")
            path_w_index = header_text.index("std::wstring config_path_w_;")
            logger_index = header_text.index("Fixture::ConsoleLogger logger_;")

            self.assertLess(display_index, path_a_index)
            self.assertLess(path_a_index, path_w_index)
            self.assertLess(path_w_index, logger_index)
            self.assertIn(
                "std::string display_name_; // inferred from std_string_member_usage, via constructor AppController, approx +0x8, size 0x20, layout high",
                header_text,
            )
            self.assertIn(
                "std::string config_path_a_; // inferred from std_string_member_usage, via constructor AppController, approx +0x28, size 0x20, layout high",
                header_text,
            )
            self.assertIn(
                "std::wstring config_path_w_; // inferred from std_wstring_member_usage, via constructor AppController, approx +0x48, size 0x20, layout high",
                header_text,
            )
            self.assertIn(
                "Fixture::ConsoleLogger logger_; // inferred from returned_member_matches_concrete_class, via virtual_method GetLogger, approx +0x68, size 0x28, layout medium",
                header_text,
            )

    def test_enrich_recovered_classes_emits_layout_provenance(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Fixture::AppController",
                    "kind": "class",
                    "mangled_name": ".?AVAppController@Fixture@@",
                    "type_descriptor_rva": "0x2200",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140001320", "slot": 0, "address": "0x140001320", "vtable_rva": "0x2128"},
                        {"name": "vf_140001340", "slot": 1, "address": "0x140001340", "vtable_rva": "0x2128"},
                    ],
                },
            ],
        }
        decompiled_entries = [
            {
                "entry_point": "0x140001320",
                "name": "AppController",
                "namespace": "Fixture::AppController",
                "signature": "AppController * __thiscall AppController(Fixture::AppController *this)",
                "return_type": "AppController *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "AppController * __thiscall AppController(Fixture::AppController *this)\n"
                    "{\n"
                    "  std::basic_string<char,std::char_traits<char>,std::allocator<char>_>::basic_string(&this->display_name_);\n"
                    "  return this;\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140001340",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "signature": "Fixture::ILogger * GetLogger(Fixture::AppController *this)",
                "return_type": "Fixture::ILogger *",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *", "storage": "RCX"},
                ],
                "result_hints": [
                    {"type_hint": "Fixture::ConsoleLogger *", "reason": "result_forwarded_to_typed_parameter"}
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "Fixture::ILogger * GetLogger(Fixture::AppController *this)\n"
                    "{\n"
                    "  return (Fixture::ILogger *)&this->logger_;\n"
                    "}"
                ),
            },
        ]

        enriched = enrich_recovered_classes(recovered, decompiled_entries=decompiled_entries)
        app_controller = next(entry for entry in enriched["classes"] if entry["name"] == "Fixture::AppController")
        members = {member["name"]: member for member in app_controller["members"]}

        self.assertEqual(app_controller["layout_strategy"], "constructor_first_evidence_order")
        self.assertIn("constructor", app_controller["layout_sources"])
        self.assertEqual(members["display_name_"]["primary_provenance"]["source_kind"], "constructor")
        self.assertEqual(members["display_name_"]["primary_provenance"]["source_function"], "AppController")
        self.assertIn("display_name_", members["display_name_"]["primary_provenance"]["statement"])
        self.assertEqual(members["logger_"]["primary_provenance"]["source_function"], "GetLogger")
        self.assertTrue(any(item["reason"] == "returned_member_matches_concrete_class" for item in members["logger_"]["layout_provenance"]))

    def test_enrich_recovered_classes_emits_full_recovery_feature_model(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {"name": "Fixture::IBase", "kind": "class", "base_classes": [], "methods": []},
                {
                    "name": "Fixture::Worker",
                    "kind": "class",
                    "base_classes": ["Fixture::IBase"],
                    "methods": [
                        {"name": "vf_140002000", "slot": 0, "address": "0x140002000", "vtable_rva": "0x3000"},
                        {"name": "vf_140002040", "slot": 1, "address": "0x140002040", "vtable_rva": "0x3000"},
                        {"name": "thunk_140002080", "slot": 2, "address": "0x140002080", "vtable_rva": "0x3000"},
                    ],
                },
            ],
        }
        decompiled_entries = [
            {
                "entry_point": "0x140002000",
                "name": "Worker",
                "namespace": "Fixture::Worker",
                "signature": "Worker * __thiscall Worker(Fixture::Worker *this)",
                "return_type": "Worker *",
                "parameters": [{"name": "this", "data_type": "Fixture::Worker *"}],
                "decompile_success": True,
                "decompiled_c": (
                    "Worker * __thiscall Fixture::Worker::Worker(Fixture::Worker *this)\n"
                    "{\n"
                    "  IBase::IBase((IBase *)this);\n"
                    "  this->enabled_ = true;\n"
                    "  this->count_ = 7;\n"
                    "  this->_padding_ = (longlong)vftable;\n"
                    "  return this;\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140002040",
                "name": "Run",
                "namespace": "Fixture::Worker",
                "signature": "void __thiscall Run(Fixture::Worker *this, uint flags)",
                "return_type": "void",
                "parameters": [
                    {"name": "this", "data_type": "Fixture::Worker *"},
                    {"name": "flags", "data_type": "uint"},
                ],
                "decompile_success": True,
                "decompiled_c": (
                    "void __thiscall Fixture::Worker::Run(Fixture::Worker *this,uint flags)\n"
                    "{\n"
                    "  if ((flags & 1) != 0) { Fixture::IBase::Notify((IBase *)this); }\n"
                    "}"
                ),
            },
            {
                "entry_point": "0x140002080",
                "name": "thunk_140002080",
                "namespace": "Fixture::Worker",
                "signature": "void thunk_140002080(Fixture::Worker *this)",
                "return_type": "void",
                "parameters": [{"name": "this", "data_type": "Fixture::Worker *"}],
                "decompile_success": True,
                "decompiled_c": (
                    "void thunk_140002080(Fixture::Worker *this)\n"
                    "{\n"
                    "  Fixture::Worker::Run(this + 8,1);\n"
                    "}"
                ),
            },
        ]

        enriched = enrich_recovered_classes(recovered, decompiled_entries=decompiled_entries)
        worker = next(entry for entry in enriched["classes"] if entry["name"] == "Fixture::Worker")
        methods = {method["display_name"]: method for method in worker["methods"]}
        members = {member["name"]: member for member in worker["members"]}

        self.assertEqual(enriched["recovery_capabilities"], RECOVERY_CAPABILITIES)
        self.assertEqual(worker["recovery_capabilities"], RECOVERY_CAPABILITIES)
        self.assertTrue(any(item["kind"] == "base_class" and item["name"] == "Fixture::IBase" for item in worker["subobjects"]))
        self.assertEqual(members["enabled_"]["storage_shape"], "bool_scalar")
        self.assertEqual(members["count_"]["storage_shape"], "dword_scalar")
        self.assertTrue(methods["thunk_140002080"]["is_thunk"])
        self.assertEqual(methods["thunk_140002080"]["thunk_kind"], "adjustor_thunk")
        self.assertTrue(worker["constructor_phases"][0]["steps"])
        self.assertTrue(any(edge["target"] == "Fixture::IBase::Notify" for edge in worker["class_call_edges"]))
        self.assertEqual(methods["Run"]["flag_inferences"][0]["constants"], ["1"])
        self.assertIn(worker["symbol_recovery"]["quality"], {"medium", "high"})
        self.assertIn("fixture_benchmark_regression", worker["recovery_capabilities"])
        self.assertEqual(enriched["cross_tool_fusion"]["primary_decompiler"], "ghidra")

    def test_write_pseudo_class_sources_rewrites_pointer_offset_member_accesses(self) -> None:
        recovered = {
            "machine": "x64",
            "classes": [
                {
                    "name": "Fixture::Worker",
                    "kind": "class",
                    "mangled_name": ".?AVWorker@Fixture@@",
                    "type_descriptor_rva": "0x2000",
                    "base_classes": [],
                    "methods": [
                        {"name": "vf_140003000", "slot": 0, "address": "0x140003000", "vtable_rva": "0x2128"},
                    ],
                }
            ],
        }
        decompiled_entries = [
            {
                "entry_point": "0x140003000",
                "name": "sub_140003000",
                "namespace": "Fixture::Worker",
                "signature": "int sub_140003000(Fixture::Worker *this)",
                "return_type": "int",
                "parameters": [{"name": "this", "data_type": "Fixture::Worker *"}],
                "decompile_success": True,
                "decompiled_c": (
                    "int sub_140003000(Fixture::Worker *this)\n"
                    "{\n"
                    "  *(undefined4 *)(this + 0x10) = *(undefined4 *)(this + 0x10) + 1;\n"
                    "  return *(undefined4 *)(this + 0x10);\n"
                    "}"
                ),
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            write_pseudo_class_sources(Path(temp_dir), recovered, decompiled_entries=decompiled_entries)

            header_text = (Path(temp_dir) / "Fixture__Worker.hpp").read_text(encoding="utf-8")
            source_text = (Path(temp_dir) / "Fixture__Worker.cpp").read_text(encoding="utf-8")

            self.assertIn("undefined4 field_10; // inferred from this_pointer_offset_access", header_text)
            self.assertIn("approx +0x10", header_text)
            self.assertIn("this->field_10 = this->field_10 + 1;", source_text)
            self.assertIn("return this->field_10;", source_text)
            self.assertNotIn("*(undefined4 *)(this + 0x10)", source_text)


if __name__ == "__main__":
    unittest.main()
