from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .engine import ReverseEngineeringEngine

MSVC_FIXTURE_RELATIVE_ROOT = Path("samples") / "fixtures" / "msvc_rtti_demo"
MSVC_FIXTURE_BUILD_SCRIPT = Path("samples") / "fixtures" / "build_msvc_fixture.ps1"
EXPECTED_MSVS_FIXTURE_CLASSES = {
    "Fixture::AppController",
    "Fixture::ConsoleLogger",
    "Fixture::IConfigProvider",
    "Fixture::ILogger",
}
EXPECTED_APP_CONTROLLER_METHODS = {
    "GetConfigPathW": {"return_type": "const wchar_t *"},
    "GetConfigPathA": {"return_type": "const char *"},
    "GetDisplayName": {"return_type": "const char *"},
    "ShouldShowUi": {"return_type": "bool"},
    "GetLogger": {"return_type": "Fixture::ConsoleLogger *"},
    "SetDisplayName": {"return_type": "void", "params": [("const char *", "name")]},
    "SetConfigPathW": {"return_type": "void", "params": [("const wchar_t *", "path")]},
    "SetConfigPathA": {"return_type": "void", "params": [("const char *", "path")]},
    "ShowDisplayMessage": {
        "return_type": "void",
        "params": [("const char *", "title"), ("const char *", "message")],
    },
    "__scalar_deleting_destructor": {"return_type": "void", "method_kind": "scalar_deleting_destructor"},
}
EXPECTED_CONSOLE_LOGGER_METHODS = {
    "LogMessage": {"return_type": "void", "params": [("const char *", "message")]},
    "CurrentName": {"return_type": "const char *"},
    "SetName": {"return_type": "void", "params": [("const char *", "name")]},
    "ShowAlert": {
        "return_type": "void",
        "params": [("const char *", "title"), ("const char *", "message")],
    },
    "__scalar_deleting_destructor": {"return_type": "void", "method_kind": "scalar_deleting_destructor"},
}
EXPECTED_APP_CONTROLLER_MEMBERS = {
    "display_name_": {
        "type": "std::string",
        "estimated_offset": 0x8,
        "estimated_size": 0x20,
        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
    },
    "config_path_a_": {
        "type": "std::string",
        "estimated_offset": 0x28,
        "estimated_size": 0x20,
        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
    },
    "config_path_w_": {
        "type": "std::wstring",
        "estimated_offset": 0x48,
        "estimated_size": 0x20,
        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
    },
    "logger_": {
        "type": "Fixture::ConsoleLogger",
        "estimated_offset": 0x68,
        "estimated_size": 0x28,
        "primary_provenance": {"source_kind": "constructor", "source_function": "AppController"},
        "layout_provenance_contains": {"source_function": "GetLogger"},
    },
}
EXPECTED_CONSOLE_LOGGER_MEMBERS = {
    "name_": {
        "type": "std::string",
        "estimated_offset": 0x8,
        "estimated_size": 0x20,
        "primary_provenance": {"source_kind": "constructor", "source_function": "ConsoleLogger"},
    },
}
EXPECTED_CLASS_SIZES = {
    "Fixture::AppController": 0x90,
    "Fixture::ConsoleLogger": 0x28,
    "Fixture::IConfigProvider": 0x8,
    "Fixture::ILogger": 0x8,
}
EXPECTED_RECOVERY_CAPABILITIES = {
    "subobject_layout_recovery",
    "field_storage_shape_inference",
    "thunk_folding",
    "constructor_destructor_phase_modeling",
    "class_aware_callgraph_propagation",
    "enum_flag_inference",
    "symbol_rich_source_recovery",
    "fixture_benchmark_regression",
    "cross_tool_decomp_fusion",
    "llm_evidence_guided_reconstruction",
}


def build_msvc_fixture(repo_root: Path, architecture: str = "x64") -> dict[str, object]:
    repo_root = repo_root.resolve()
    script_path = repo_root / MSVC_FIXTURE_BUILD_SCRIPT
    if not script_path.exists():
        raise FileNotFoundError(script_path)
    command = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-Architecture",
        architecture,
    ]
    completed = subprocess.run(command, cwd=repo_root, capture_output=True, text=True, check=False)
    output_dir = repo_root / MSVC_FIXTURE_RELATIVE_ROOT / "build" / architecture
    manifest_path = output_dir / "build_manifest.json"
    if completed.returncode != 0:
        raise RuntimeError((completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else ""))
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)
    return json.loads(manifest_path.read_text(encoding="utf-8-sig"))


def run_msvc_fixture_regression(
    repo_root: Path,
    *,
    output_root: Path,
    use_ghidra: bool = True,
    wait_timeout_seconds: int = 300,
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_root = output_root.resolve()
    build_manifest = build_msvc_fixture(repo_root)
    fixture_exe = Path(str(build_manifest["exe"]))
    if not fixture_exe.exists():
        raise FileNotFoundError(fixture_exe)

    engine = ReverseEngineeringEngine(
        output_root=output_root,
        logger=print,
        run_external_tools=True,
        run_ghidra=use_ghidra,
    )
    report = engine.analyze(fixture_exe)
    wait_results = wait_for_fixture_jobs(Path(report.output_dir), timeout_seconds=wait_timeout_seconds)
    validation = validate_msvc_fixture_run(Path(report.output_dir), require_ghidra=use_ghidra)
    return {
        "ok": bool(validation["ok"]),
        "build_manifest": build_manifest,
        "analysis_output_dir": report.output_dir,
        "wait_results": wait_results,
        "validation": validation,
    }


def wait_for_fixture_jobs(run_dir: Path, timeout_seconds: int = 300) -> dict[str, object]:
    run_dir = run_dir.resolve()
    statuses: dict[str, object] = {}
    ghidra_status_path = run_dir / "ghidra" / "status.json"
    pe_tools_status_path = run_dir / "pe_tools" / "status.json"
    if ghidra_status_path.exists():
        statuses["ghidra"] = wait_for_status_file(ghidra_status_path, timeout_seconds=timeout_seconds)
    if pe_tools_status_path.exists():
        statuses["pe_tools"] = wait_for_status_file(pe_tools_status_path, timeout_seconds=timeout_seconds)
    return statuses


def wait_for_status_file(status_path: Path, timeout_seconds: int = 300) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_payload: dict[str, object] = {}
    while time.monotonic() < deadline:
        if status_path.exists():
            last_payload = json.loads(status_path.read_text(encoding="utf-8"))
            if str(last_payload.get("state", "")).lower() in {"completed", "failed"}:
                return last_payload
        time.sleep(1.0)
    if last_payload:
        return last_payload
    raise TimeoutError(f"Timed out waiting for {status_path}")


def validate_msvc_fixture_run(run_dir: Path, *, require_ghidra: bool = True) -> dict[str, object]:
    run_dir = run_dir.resolve()
    checks: list[str] = []
    errors: list[str] = []

    report_payload = _read_json(run_dir / "report.json")
    native_manifest = _read_json(run_dir / "native" / "msvc_rtti_classes.json")
    native_classes = {str(entry.get("name")) for entry in native_manifest.get("classes") or [] if entry.get("name")}
    missing_native_classes = sorted(EXPECTED_MSVS_FIXTURE_CLASSES - native_classes)
    if missing_native_classes:
        errors.append(f"Native RTTI manifest missed expected classes: {', '.join(missing_native_classes)}")
    else:
        checks.append("native_rtti_classes")

    recovered_sources = {str(entry.get("original_path")) for entry in report_payload.get("recovered_sources") or []}
    for source_name in {
        "msvc_rtti::Fixture::AppController.hpp",
        "msvc_rtti::Fixture::ConsoleLogger.hpp",
        "msvc_rtti::Fixture::IConfigProvider.hpp",
        "msvc_rtti::Fixture::ILogger.hpp",
    }:
        if source_name not in recovered_sources:
            errors.append(f"Recovered source missing: {source_name}")
    if not any(error.startswith("Recovered source missing:") for error in errors):
        checks.append("native_pseudo_cpp_sources")

    findings = {str(entry.get("title")) for entry in report_payload.get("findings") or [] if entry.get("title")}
    if "PDB file recovered" not in findings:
        errors.append("Expected the fixture regression to recover the sibling PDB.")
    else:
        checks.append("pdb_recovered")

    if require_ghidra:
        ghidra_status = _read_json(run_dir / "ghidra" / "status.json")
        if str(ghidra_status.get("state", "")).lower() != "completed":
            errors.append(f"Ghidra status was not completed: {ghidra_status.get('state')}")
        else:
            checks.append("ghidra_completed")
        enriched_manifest = _read_json(run_dir / "ghidra" / "exports" / "enriched_class_manifest.json")
        _validate_recovery_capabilities(enriched_manifest, checks, errors)
        classes_by_name = {
            str(entry.get("name")): entry
            for entry in enriched_manifest.get("classes") or []
            if isinstance(entry, dict) and entry.get("name")
        }
        app_controller = classes_by_name.get("Fixture::AppController")
        console_logger = classes_by_name.get("Fixture::ConsoleLogger")
        if app_controller is None:
            errors.append("Ghidra enriched manifest missed Fixture::AppController.")
        else:
            _validate_class_size_expectation(app_controller, EXPECTED_CLASS_SIZES["Fixture::AppController"], "Fixture::AppController", errors)
            _validate_class_layout_metadata(app_controller, "Fixture::AppController", errors)
            _validate_class_recovery_features(app_controller, "Fixture::AppController", errors)
            _validate_method_expectations(app_controller, EXPECTED_APP_CONTROLLER_METHODS, "Fixture::AppController", checks, errors)
            _validate_member_expectations(
                app_controller,
                EXPECTED_APP_CONTROLLER_MEMBERS,
                "Fixture::AppController",
                checks,
                errors,
            )
        if console_logger is None:
            errors.append("Ghidra enriched manifest missed Fixture::ConsoleLogger.")
        else:
            _validate_class_size_expectation(console_logger, EXPECTED_CLASS_SIZES["Fixture::ConsoleLogger"], "Fixture::ConsoleLogger", errors)
            _validate_class_layout_metadata(console_logger, "Fixture::ConsoleLogger", errors)
            _validate_class_recovery_features(console_logger, "Fixture::ConsoleLogger", errors)
            _validate_method_expectations(console_logger, EXPECTED_CONSOLE_LOGGER_METHODS, "Fixture::ConsoleLogger", checks, errors)
            _validate_member_expectations(
                console_logger,
                EXPECTED_CONSOLE_LOGGER_MEMBERS,
                "Fixture::ConsoleLogger",
                checks,
                errors,
            )
        _validate_pure_virtual_expectations(classes_by_name, checks, errors)

        decompilation = _read_json(run_dir / "ghidra" / "exports" / "targeted_decompilation.json")
        if len(decompilation) < 12:
            errors.append(f"Expected targeted decompilation entries for the fixture, saw only {len(decompilation)}.")
        else:
            checks.append("ghidra_targeted_decompilation")

    return {"ok": not errors, "checks": checks, "errors": errors}


def _validate_method_expectations(
    class_entry: dict[str, object],
    expectations: dict[str, dict[str, object]],
    class_name: str,
    checks: list[str],
    errors: list[str],
) -> None:
    methods = {
        str(method.get("display_name") or method.get("name")): method
        for method in class_entry.get("methods") or []
        if isinstance(method, dict)
    }
    for method_name, expected in expectations.items():
        method = methods.get(method_name)
        if method is None:
            errors.append(f"{class_name} is missing expected method {method_name}.")
            continue
        expected_return = str(expected.get("return_type") or "").strip()
        observed_return = str(method.get("return_type") or "").strip()
        if expected_return and observed_return != expected_return:
            errors.append(
                f"{class_name}::{method_name} expected return {expected_return!r}, observed {observed_return!r}."
            )
        expected_kind = str(expected.get("method_kind") or "").strip()
        observed_kind = str(method.get("method_kind") or "").strip()
        if expected_kind and observed_kind != expected_kind:
            errors.append(
                f"{class_name}::{method_name} expected method kind {expected_kind!r}, observed {observed_kind!r}."
            )
        expected_params = list(expected.get("params") or [])
        if expected_params:
            observed_params = [
                (str(param.get("type") or "").strip(), str(param.get("name") or "").strip())
                for param in method.get("params") or []
                if isinstance(param, dict)
            ]
            if observed_params[: len(expected_params)] != expected_params:
                errors.append(
                    f"{class_name}::{method_name} expected params {expected_params!r}, observed {observed_params!r}."
                )
    if not any(error.startswith(f"{class_name} ") or error.startswith(f"{class_name}::") for error in errors):
        checks.append(f"{class_name}_methods")


def _validate_pure_virtual_expectations(
    classes_by_name: dict[str, dict[str, object]],
    checks: list[str],
    errors: list[str],
) -> None:
    for class_name, expected_count in {
        "Fixture::ILogger": 4,
        "Fixture::IConfigProvider": 9,
    }.items():
        class_entry = classes_by_name.get(class_name)
        if class_entry is None:
            errors.append(f"Ghidra enriched manifest missed {class_name}.")
            continue
        _validate_class_size_expectation(class_entry, EXPECTED_CLASS_SIZES[class_name], class_name, errors)
        pure_virtual_methods = [
            method
            for method in class_entry.get("methods") or []
            if isinstance(method, dict) and str(method.get("method_kind") or "").strip() == "pure_virtual"
        ]
        if len(pure_virtual_methods) < expected_count:
            errors.append(
                f"{class_name} expected at least {expected_count} pure virtual methods, observed {len(pure_virtual_methods)}."
            )
            continue
        display_names = [str(method.get("display_name") or "").strip() for method in pure_virtual_methods]
        if len(display_names) != len(set(display_names)):
            errors.append(f"{class_name} pure virtual slots were not assigned unique display names.")
            continue
        checks.append(f"{class_name}_pure_virtuals")


def _validate_member_expectations(
    class_entry: dict[str, object],
    expectations: dict[str, dict[str, object]],
    class_name: str,
    checks: list[str],
    errors: list[str],
) -> None:
    members = {
        str(member.get("name") or "").strip(): member
        for member in class_entry.get("members") or []
        if isinstance(member, dict) and member.get("name")
    }
    for member_name, expected in expectations.items():
        member = members.get(member_name)
        if member is None:
            errors.append(f"{class_name} is missing expected member {member_name}.")
            continue
        expected_type = str(expected.get("type") or "").strip()
        observed_type = str(member.get("type") or "").strip()
        if expected_type and observed_type != expected_type:
            errors.append(
                f"{class_name}::{member_name} expected member type {expected_type!r}, observed {observed_type!r}."
            )
        expected_offset = expected.get("estimated_offset")
        observed_offset = member.get("estimated_offset")
        if isinstance(expected_offset, int) and observed_offset != expected_offset:
            errors.append(
                f"{class_name}::{member_name} expected member offset 0x{expected_offset:x}, observed {observed_offset!r}."
            )
        expected_size = expected.get("estimated_size")
        observed_size = member.get("estimated_size")
        if isinstance(expected_size, int) and observed_size != expected_size:
            errors.append(
                f"{class_name}::{member_name} expected member size 0x{expected_size:x}, observed {observed_size!r}."
            )
        expected_primary = expected.get("primary_provenance")
        if isinstance(expected_primary, dict):
            observed_primary = member.get("primary_provenance")
            if not isinstance(observed_primary, dict):
                errors.append(f"{class_name}::{member_name} is missing primary provenance.")
            else:
                for key, expected_value in expected_primary.items():
                    observed_value = str(observed_primary.get(key) or "").strip()
                    if observed_value != str(expected_value):
                        errors.append(
                            f"{class_name}::{member_name} expected primary provenance {key}={expected_value!r}, observed {observed_value!r}."
                        )
        expected_provenance = expected.get("layout_provenance_contains")
        if isinstance(expected_provenance, dict):
            observed_provenance = [
                value for value in member.get("layout_provenance") or [] if isinstance(value, dict)
            ]
            if not any(
                all(str(item.get(key) or "").strip() == str(expected_value) for key, expected_value in expected_provenance.items())
                for item in observed_provenance
            ):
                errors.append(
                    f"{class_name}::{member_name} was missing expected layout provenance {expected_provenance!r}."
                )
    if not any(error.startswith(f"{class_name} is missing expected member") or error.startswith(f"{class_name}::") for error in errors):
        checks.append(f"{class_name}_members")


def _validate_class_size_expectation(
    class_entry: dict[str, object],
    expected_size: int,
    class_name: str,
    errors: list[str],
) -> None:
    observed_size = class_entry.get("estimated_object_size")
    if observed_size != expected_size:
        errors.append(
            f"{class_name} expected object size 0x{expected_size:x}, observed {observed_size!r}."
        )


def _validate_class_layout_metadata(
    class_entry: dict[str, object],
    class_name: str,
    errors: list[str],
) -> None:
    strategy = str(class_entry.get("layout_strategy") or "").strip()
    if strategy != "constructor_first_evidence_order":
        errors.append(f"{class_name} expected layout strategy 'constructor_first_evidence_order', observed {strategy!r}.")
    sources = {str(value).strip() for value in class_entry.get("layout_sources") or [] if str(value).strip()}
    if "constructor" not in sources:
        errors.append(f"{class_name} expected constructor layout evidence, observed {sorted(sources)!r}.")


def _validate_recovery_capabilities(
    enriched_manifest: dict[str, object] | list[dict[str, object]],
    checks: list[str],
    errors: list[str],
) -> None:
    if not isinstance(enriched_manifest, dict):
        errors.append("Ghidra enriched manifest was not a JSON object.")
        return
    observed = {str(value).strip() for value in enriched_manifest.get("recovery_capabilities") or [] if str(value).strip()}
    missing = sorted(EXPECTED_RECOVERY_CAPABILITIES - observed)
    if missing:
        errors.append(f"Ghidra enriched manifest missed recovery capabilities: {', '.join(missing)}")
        return
    checks.append("recovery_capabilities")


def _validate_class_recovery_features(
    class_entry: dict[str, object],
    class_name: str,
    errors: list[str],
) -> None:
    capabilities = {str(value).strip() for value in class_entry.get("recovery_capabilities") or [] if str(value).strip()}
    missing = sorted(EXPECTED_RECOVERY_CAPABILITIES - capabilities)
    if missing:
        errors.append(f"{class_name} missed recovery capabilities: {', '.join(missing)}")
    if not class_entry.get("subobjects"):
        errors.append(f"{class_name} expected recovered subobject metadata.")
    if not class_entry.get("constructor_phases"):
        errors.append(f"{class_name} expected constructor phase metadata.")
    symbol_quality = str((class_entry.get("symbol_recovery") or {}).get("quality") or "").strip()
    if symbol_quality not in {"medium", "high"}:
        errors.append(f"{class_name} expected medium/high symbol recovery quality, observed {symbol_quality!r}.")
    for member in class_entry.get("members") or []:
        if not isinstance(member, dict):
            continue
        if not member.get("storage_shape"):
            errors.append(f"{class_name}::{member.get('name')} expected a storage_shape inference.")


def _read_json(path: Path) -> dict[str, object] | list[dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8-sig"))
