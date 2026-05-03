from __future__ import annotations

import unittest

from tests import _path_setup  # noqa: F401

from re_pro.api_semantics import (
    infer_argument_hint_from_callee,
    infer_result_hint_from_callee,
    refine_targeted_decompilation,
)


class ApiSemanticsTests(unittest.TestCase):
    def test_infer_argument_hint_from_messagebox_positions(self) -> None:
        message_hint = infer_argument_hint_from_callee("MessageBoxA", 1)
        title_hint = infer_argument_hint_from_callee("MessageBoxA", 2)

        self.assertEqual(
            message_hint,
            {
                "name_hint": "message",
                "type_hint": "const char *",
                "reason": "messagebox_text_argument",
                "callee": "MessageBoxA",
            },
        )
        self.assertEqual(
            title_hint,
            {
                "name_hint": "title",
                "type_hint": "const char *",
                "reason": "messagebox_title_argument",
                "callee": "MessageBoxA",
            },
        )

    def test_infer_argument_hint_from_logger_method(self) -> None:
        hint = infer_argument_hint_from_callee("Fixture::ILogger::LogMessage", 0)

        self.assertEqual(
            hint,
            {
                "name_hint": "message",
                "type_hint": "const char *",
                "reason": "logger_message_argument",
                "callee": "Fixture::ILogger::LogMessage",
            },
        )

    def test_infer_result_hint_from_path_api(self) -> None:
        hint = infer_result_hint_from_callee("CreateFileW")

        self.assertEqual(hint, {"type_hint": "const wchar_t *", "reason": "result_used_as_path", "callee": "CreateFileW"})

    def test_infer_result_hint_from_string_api(self) -> None:
        hint = infer_result_hint_from_callee("__imp_MessageBoxA")

        self.assertEqual(
            hint,
            {"type_hint": "const char *", "reason": "result_passed_to_string_like_api", "callee": "MessageBoxA"},
        )

    def test_infer_result_hint_from_class_method(self) -> None:
        hint = infer_result_hint_from_callee("Fixture::ILogger::LogMessage")

        self.assertEqual(
            hint,
            {
                "type_hint": "Fixture::ILogger *",
                "reason": "result_passed_to_class_method",
                "callee": "Fixture::ILogger::LogMessage",
            },
        )

    def test_refine_targeted_decompilation_promotes_result_to_recovered_class_pointer(self) -> None:
        entries = [
            {
                "entry_point": "0x140001000",
                "name": "GetLogger",
                "namespace": "Fixture::AppController",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::AppController *"},
                ],
                "callers": [
                    {
                        "caller_name": "main",
                        "result_hint": {
                            "type_hint": "void *",
                            "reason": "result_passed_to_call",
                            "callee": "Fixture::ConsoleLogger::SetName",
                            "argument_position": 0,
                        },
                    }
                ],
                "result_hints": [],
            },
            {
                "entry_point": "0x140001100",
                "name": "SetName",
                "namespace": "Fixture::ConsoleLogger",
                "parameters": [
                    {"ordinal": 0, "name": "this", "data_type": "Fixture::ConsoleLogger *"},
                    {"ordinal": 1, "name": "name", "data_type": "const char *"},
                ],
            },
        ]

        refined = refine_targeted_decompilation(entries)

        caller_hint = refined[0]["callers"][0]["result_hint"]
        self.assertEqual(caller_hint["type_hint"], "Fixture::ConsoleLogger *")
        self.assertEqual(caller_hint["reason"], "result_forwarded_to_typed_parameter")

    def test_refine_targeted_decompilation_updates_generic_result_hints(self) -> None:
        entries = [
            {
                "entry_point": "0x140001000",
                "name": "MessageBoxA",
                "callsite_argument_hints": [
                    {"position": 1, "name_hint": "value", "type_hint": "void *"},
                    {"position": 2, "name_hint": "value", "type_hint": "undefined8"},
                ],
                "callers": [
                    {
                        "caller_name": "main",
                        "argument_hints": [
                            {"position": 1, "name_hint": "text", "type_hint": "void *"},
                            {"position": 2, "name_hint": "value", "type_hint": "undefined8"},
                        ],
                        "result_hint": {
                            "type_hint": "void *",
                            "reason": "result_passed_to_call",
                            "callee": "CreateFileW",
                        },
                    }
                ],
                "result_hints": [
                    {
                        "type_hint": "void *",
                        "reason": "result_passed_to_call",
                        "callee": "CreateFileW",
                    }
                ],
            }
        ]

        refined = refine_targeted_decompilation(entries)

        caller_hint = refined[0]["callers"][0]["result_hint"]
        self.assertEqual(caller_hint["type_hint"], "const wchar_t *")
        self.assertEqual(caller_hint["reason"], "result_used_as_path")
        self.assertEqual(refined[0]["result_hints"][0]["type_hint"], "const wchar_t *")
        self.assertEqual(refined[0]["callsite_argument_hints"][0]["name_hint"], "message")
        self.assertEqual(refined[0]["callsite_argument_hints"][1]["name_hint"], "title")
        self.assertEqual(refined[0]["callers"][0]["argument_hints"][0]["type_hint"], "const char *")
        self.assertEqual(refined[0]["callers"][0]["argument_hints"][1]["name_hint"], "title")


if __name__ == "__main__":
    unittest.main()
