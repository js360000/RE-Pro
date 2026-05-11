from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.fixture_regression import EXPECTED_RECOVERY_CAPABILITIES, validate_msvc_fixture_run
from tests import _path_setup  # noqa: F401


class FixtureRegressionTests(unittest.TestCase):
    def test_validate_msvc_fixture_run_accepts_expected_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "native").mkdir(parents=True)
            (run_dir / "ghidra" / "exports").mkdir(parents=True)

            (run_dir / "report.json").write_text(
                json.dumps(
                    {
                        "findings": [{"title": "PDB file recovered"}],
                        "recovered_sources": [
                            {"original_path": "msvc_rtti::Fixture::AppController.hpp"},
                            {"original_path": "msvc_rtti::Fixture::ConsoleLogger.hpp"},
                            {"original_path": "msvc_rtti::Fixture::IConfigProvider.hpp"},
                            {"original_path": "msvc_rtti::Fixture::ILogger.hpp"},
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (run_dir / "native" / "msvc_rtti_classes.json").write_text(
                json.dumps(
                    {
                        "classes": [
                            {"name": "Fixture::AppController"},
                            {"name": "Fixture::ConsoleLogger"},
                            {"name": "Fixture::IConfigProvider"},
                            {"name": "Fixture::ILogger"},
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (run_dir / "ghidra" / "status.json").write_text(json.dumps({"state": "completed"}, indent=2), encoding="utf-8")
            (run_dir / "ghidra" / "exports" / "targeted_decompilation.json").write_text(
                json.dumps([{"entry_point": hex(0x140001000 + index)} for index in range(16)], indent=2),
                encoding="utf-8",
            )
            (run_dir / "ghidra" / "exports" / "enriched_class_manifest.json").write_text(
                json.dumps(
                    {
                        "recovery_capabilities": sorted(EXPECTED_RECOVERY_CAPABILITIES),
                        "classes": [
                            {
                                "name": "Fixture::AppController",
                                "estimated_object_size": 0x90,
                                "layout_strategy": "constructor_first_evidence_order",
                                "layout_sources": ["constructor", "method"],
                                "recovery_capabilities": sorted(EXPECTED_RECOVERY_CAPABILITIES),
                                "subobjects": [{"kind": "primary_vptr", "name": "vftable", "estimated_offset": 0}],
                                "constructor_phases": [{"function": "AppController", "steps": [{"kind": "member_constructor_call"}]}],
                                "symbol_recovery": {"quality": "high", "named_method_ratio": 1.0},
                                "members": [
                                    {
                                        "name": "display_name_",
                                        "type": "std::string",
                                        "estimated_offset": 0x8,
                                        "estimated_size": 0x20,
                                        "storage_shape": "std_string_object",
                                        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
                                        "layout_provenance": [
                                            {
                                                "source_kind": "constructor",
                                                "source_function": "AppController",
                                                "reason": "std_string_member_usage",
                                                "statement": "std::basic_string<char>::basic_string(&this->display_name_);",
                                            }
                                        ],
                                    },
                                    {
                                        "name": "config_path_a_",
                                        "type": "std::string",
                                        "estimated_offset": 0x28,
                                        "estimated_size": 0x20,
                                        "storage_shape": "std_string_object",
                                        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
                                        "layout_provenance": [
                                            {
                                                "source_kind": "constructor",
                                                "source_function": "AppController",
                                                "reason": "std_string_member_usage",
                                                "statement": "std::basic_string<char>::basic_string(&this->config_path_a_);",
                                            }
                                        ],
                                    },
                                    {
                                        "name": "config_path_w_",
                                        "type": "std::wstring",
                                        "estimated_offset": 0x48,
                                        "estimated_size": 0x20,
                                        "storage_shape": "std_wstring_object",
                                        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
                                        "layout_provenance": [
                                            {
                                                "source_kind": "constructor",
                                                "source_function": "AppController",
                                                "reason": "std_wstring_member_usage",
                                                "statement": "std::basic_string<wchar_t>::basic_string(&this->config_path_w_);",
                                            }
                                        ],
                                    },
                                    {
                                        "name": "logger_",
                                        "type": "Fixture::ConsoleLogger",
                                        "estimated_offset": 0x68,
                                        "estimated_size": 0x28,
                                        "storage_shape": "class_object",
                                        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
                                        "layout_provenance": [
                                            {
                                                "source_kind": "constructor",
                                                "source_function": "AppController",
                                                "reason": "constructed_member_matches_recovered_class",
                                                "statement": "ConsoleLogger::ConsoleLogger(&this->logger_,pbVar1);",
                                            },
                                            {
                                                "source_kind": "method",
                                                "source_function": "GetLogger",
                                                "reason": "returned_member_matches_concrete_class",
                                                "statement": "return (ILogger *)&this->logger_;",
                                            }
                                        ],
                                    },
                                ],
                                "methods": [
                                    {"display_name": "GetConfigPathW", "return_type": "const wchar_t *", "params": []},
                                    {"display_name": "GetConfigPathA", "return_type": "const char *", "params": []},
                                    {"display_name": "GetDisplayName", "return_type": "const char *", "params": []},
                                    {"display_name": "ShouldShowUi", "return_type": "bool", "params": []},
                                    {"display_name": "GetLogger", "return_type": "Fixture::ConsoleLogger *", "params": []},
                                    {
                                        "display_name": "SetDisplayName",
                                        "return_type": "void",
                                        "params": [{"type": "const char *", "name": "name"}],
                                    },
                                    {
                                        "display_name": "SetConfigPathW",
                                        "return_type": "void",
                                        "params": [{"type": "const wchar_t *", "name": "path"}],
                                    },
                                    {
                                        "display_name": "SetConfigPathA",
                                        "return_type": "void",
                                        "params": [{"type": "const char *", "name": "path"}],
                                    },
                                    {
                                        "display_name": "ShowDisplayMessage",
                                        "return_type": "void",
                                        "params": [
                                            {"type": "const char *", "name": "title"},
                                            {"type": "const char *", "name": "message"},
                                        ],
                                    },
                                    {
                                        "display_name": "__scalar_deleting_destructor",
                                        "return_type": "void",
                                        "method_kind": "scalar_deleting_destructor",
                                        "params": [{"type": "uint", "name": "flags"}],
                                    },
                                ],
                            },
                            {
                                "name": "Fixture::ConsoleLogger",
                                "estimated_object_size": 0x28,
                                "layout_strategy": "constructor_first_evidence_order",
                                "layout_sources": ["constructor"],
                                "recovery_capabilities": sorted(EXPECTED_RECOVERY_CAPABILITIES),
                                "subobjects": [{"kind": "primary_vptr", "name": "vftable", "estimated_offset": 0}],
                                "constructor_phases": [{"function": "ConsoleLogger", "steps": [{"kind": "member_constructor_call"}]}],
                                "symbol_recovery": {"quality": "high", "named_method_ratio": 1.0},
                                "members": [
                                    {
                                        "name": "name_",
                                        "type": "std::string",
                                        "estimated_offset": 0x8,
                                        "estimated_size": 0x20,
                                        "storage_shape": "std_string_object",
                                        "primary_provenance": {"source_kind": "constructor", "source_function": "ConsoleLogger"},
                                        "layout_provenance": [
                                            {
                                                "source_kind": "constructor",
                                                "source_function": "ConsoleLogger",
                                                "reason": "std_string_member_usage",
                                                "statement": "std::basic_string<char>::basic_string(&this->name_);",
                                            }
                                        ],
                                    },
                                ],
                                "methods": [
                                    {
                                        "display_name": "LogMessage",
                                        "return_type": "void",
                                        "params": [{"type": "const char *", "name": "message"}],
                                    },
                                    {"display_name": "CurrentName", "return_type": "const char *", "params": []},
                                    {
                                        "display_name": "SetName",
                                        "return_type": "void",
                                        "params": [{"type": "const char *", "name": "name"}],
                                    },
                                    {
                                        "display_name": "ShowAlert",
                                        "return_type": "void",
                                        "params": [
                                            {"type": "const char *", "name": "title"},
                                            {"type": "const char *", "name": "message"},
                                        ],
                                    },
                                    {
                                        "display_name": "__scalar_deleting_destructor",
                                        "return_type": "void",
                                        "method_kind": "scalar_deleting_destructor",
                                        "params": [{"type": "uint", "name": "flags"}],
                                    },
                                ],
                            },
                            {
                                "name": "Fixture::ILogger",
                                "estimated_object_size": 0x8,
                                "methods": [
                                    {"display_name": "__pure_virtual_slot_0", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_1", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_2", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_3", "method_kind": "pure_virtual"},
                                ],
                            },
                            {
                                "name": "Fixture::IConfigProvider",
                                "estimated_object_size": 0x8,
                                "methods": [
                                    {"display_name": "__pure_virtual_slot_0", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_1", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_2", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_3", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_4", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_5", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_6", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_7", "method_kind": "pure_virtual"},
                                    {"display_name": "__pure_virtual_slot_8", "method_kind": "pure_virtual"},
                                ],
                            },
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = validate_msvc_fixture_run(run_dir, require_ghidra=True)

            self.assertTrue(result["ok"])
            self.assertIn("native_rtti_classes", result["checks"])
            self.assertIn("Fixture::AppController_methods", result["checks"])
            self.assertIn("Fixture::AppController_members", result["checks"])
            self.assertIn("Fixture::ConsoleLogger_methods", result["checks"])
            self.assertIn("Fixture::ConsoleLogger_members", result["checks"])
            self.assertIn("Fixture::ILogger_pure_virtuals", result["checks"])
            self.assertIn("Fixture::IConfigProvider_pure_virtuals", result["checks"])

    def test_validate_msvc_fixture_run_reports_missing_method(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "native").mkdir(parents=True)
            (run_dir / "ghidra" / "exports").mkdir(parents=True)

            (run_dir / "report.json").write_text(
                json.dumps(
                    {
                        "findings": [{"title": "PDB file recovered"}],
                        "recovered_sources": [
                            {"original_path": "msvc_rtti::Fixture::AppController.hpp"},
                            {"original_path": "msvc_rtti::Fixture::ConsoleLogger.hpp"},
                            {"original_path": "msvc_rtti::Fixture::IConfigProvider.hpp"},
                            {"original_path": "msvc_rtti::Fixture::ILogger.hpp"},
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (run_dir / "native" / "msvc_rtti_classes.json").write_text(
                json.dumps(
                    {
                        "recovery_capabilities": sorted(EXPECTED_RECOVERY_CAPABILITIES),
                        "classes": [
                            {"name": "Fixture::AppController"},
                            {"name": "Fixture::ConsoleLogger"},
                            {"name": "Fixture::IConfigProvider"},
                            {"name": "Fixture::ILogger"},
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (run_dir / "ghidra" / "status.json").write_text(json.dumps({"state": "completed"}, indent=2), encoding="utf-8")
            (run_dir / "ghidra" / "exports" / "targeted_decompilation.json").write_text(
                json.dumps([{"entry_point": hex(0x140001000 + index)} for index in range(16)], indent=2),
                encoding="utf-8",
            )
            (run_dir / "ghidra" / "exports" / "enriched_class_manifest.json").write_text(
                json.dumps(
                    {
                        "classes": [
                            {
                                "name": "Fixture::AppController",
                                "estimated_object_size": 0x90,
                                "layout_strategy": "constructor_first_evidence_order",
                                "layout_sources": ["constructor"],
                                "members": [],
                                "methods": [
                                    {"display_name": "GetConfigPathW", "return_type": "const wchar_t *"},
                                ],
                            },
                            {
                                "name": "Fixture::ConsoleLogger",
                                "estimated_object_size": 0x28,
                                "layout_strategy": "constructor_first_evidence_order",
                                "layout_sources": ["constructor"],
                                "members": [],
                                "methods": [
                                    {"display_name": "LogMessage", "return_type": "void"},
                                    {"display_name": "CurrentName", "return_type": "const char *"},
                                ],
                            },
                            {"name": "Fixture::ILogger", "estimated_object_size": 0x8, "methods": []},
                            {"name": "Fixture::IConfigProvider", "estimated_object_size": 0x8, "methods": []},
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = validate_msvc_fixture_run(run_dir, require_ghidra=True)

            self.assertFalse(result["ok"])
            self.assertTrue(any("GetConfigPathA" in error for error in result["errors"]))
            self.assertTrue(any("display_name_" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
