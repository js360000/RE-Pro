# RE-Pro Ghidra headless export script.
# @category RE-Pro
# @runtime Jython

import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.symbol import RefType
from ghidra.program.model.data import StringDataInstance
from ghidra.program.util import DefinedStringIterator


MIN_STRING_LENGTH = 5
MAX_STRINGS = 1024
MAX_FUNCTION_EXPORTS = 20000
ASCII_FALLBACK_THRESHOLD = 256
MAX_TARGET_DECOMPILATIONS = 96
TARGET_DECOMPILE_TIMEOUT_SECONDS = 8
MAX_DECOMPILED_TEXT_CHARS = 24000
MAX_CALLSITE_REFS = 16
MAX_CALLSITE_SCAN_BACK = 12
MAX_RESULT_SCAN_FORWARD = 6


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def to_text(value):
    try:
        return unicode(value)
    except NameError:
        return str(value)
    except Exception:
        return str(value)


def write_json(path, payload):
    handle = open(path, "w")
    try:
        handle.write(json.dumps(payload, indent=2, sort_keys=True))
    finally:
        handle.close()


def write_json_compact(path, payload):
    handle = open(path, "w")
    try:
        handle.write(json.dumps(payload, separators=(",", ":")))
    finally:
        handle.close()


def read_json(path):
    handle = open(path, "r")
    try:
        return json.loads(handle.read())
    finally:
        handle.close()


def normalize_text(text):
    if text is None:
        return None
    value = to_text(text).replace("\r", "")
    value = value.rstrip("\x00")
    return value if len(value) >= MIN_STRING_LENGTH else None


def add_string(strings, seen, address, data_type, length, value, source):
    if address in seen:
        return
    text = normalize_text(value)
    if text is None:
        return
    strings.append(
        {
            "address": str(address),
            "data_type": data_type,
            "length": int(length),
            "source": source,
            "value": text,
        }
    )
    seen.add(str(address))


def safe_filename_component(value):
    text = to_text(value or "function")
    sanitized = []
    for character in text:
        if character.isalnum() or character in ("_", "-", "."):
            sanitized.append(character)
        else:
            sanitized.append("_")
    return "".join(sanitized).strip("_") or "function"


def describe_parameters(function):
    parameters = []
    try:
        function_parameters = function.getParameters()
    except Exception:
        return parameters
    for parameter in function_parameters or []:
        try:
            parameters.append(
                {
                    "ordinal": int(parameter.getOrdinal()),
                    "name": to_text(parameter.getName()),
                    "data_type": to_text(parameter.getDataType()),
                    "storage": to_text(parameter.getVariableStorage()),
                }
            )
        except Exception:
            continue
    return parameters


def describe_callers(function):
    callers = []
    seen = set()
    reference_manager = currentProgram.getReferenceManager()
    try:
        references = reference_manager.getReferencesTo(function.getEntryPoint())
    except Exception:
        return callers
    for reference in references:
        if len(callers) >= MAX_CALLSITE_REFS:
            break
        try:
            ref_type = reference.getReferenceType()
            if ref_type is None or (not ref_type.isCall() and ref_type != RefType.COMPUTED_CALL):
                continue
            from_address = reference.getFromAddress()
            caller = getFunctionContaining(from_address)
            key = (str(from_address), str(caller.getEntryPoint()) if caller else "")
            if key in seen:
                continue
            seen.add(key)
            callers.append(
                {
                    "from_address": str(from_address),
                    "ref_type": to_text(ref_type),
                    "caller_name": caller.getName() if caller else None,
                    "caller_entry_point": str(caller.getEntryPoint()) if caller else None,
                    "caller_signature": to_text(caller.getSignature()) if caller else None,
                    "argument_hints": describe_callsite_arguments(from_address),
                    "result_hint": describe_callsite_result_usage(from_address),
                }
            )
        except Exception:
            continue
    return callers


def describe_callees(function):
    callees = []
    seen = set()
    reference_manager = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()
    try:
        body = function.getBody()
    except Exception:
        body = None
    if body is None:
        return callees
    try:
        instructions = listing.getInstructions(body, True)
    except Exception:
        return callees
    while instructions.hasNext():
        if len(callees) >= MAX_CALLSITE_REFS:
            break
        instruction = instructions.next()
        try:
            references = reference_manager.getReferencesFrom(instruction.getAddress())
        except Exception:
            continue
        for reference in references:
            if len(callees) >= MAX_CALLSITE_REFS:
                break
            try:
                ref_type = reference.getReferenceType()
                if ref_type is None or (not ref_type.isCall() and ref_type != RefType.COMPUTED_CALL):
                    continue
                to_address = reference.getToAddress()
                if to_address is None:
                    continue
                callee = getFunctionAt(to_address)
                if callee is None:
                    callee = getFunctionContaining(to_address)
                key = (str(instruction.getAddress()), str(to_address))
                if key in seen:
                    continue
                seen.add(key)
                callees.append(
                    {
                        "from_address": str(instruction.getAddress()),
                        "to_address": str(to_address),
                        "entry_point": str(callee.getEntryPoint()) if callee else str(to_address),
                        "name": callee.getName() if callee else None,
                        "signature": to_text(callee.getSignature()) if callee else None,
                        "namespace": callee.getParentNamespace().getName(True) if callee and callee.getParentNamespace() else None,
                        "ref_type": to_text(ref_type),
                    }
                )
            except Exception:
                continue
    return callees


def pointer_size():
    try:
        return int(currentProgram.getDefaultPointerSize())
    except Exception:
        return 8


def language_id_text():
    try:
        return to_text(currentProgram.getLanguageID()).lower()
    except Exception:
        return ""


def describe_callsite_arguments(call_address):
    language_id = language_id_text()
    if "x86" not in language_id:
        return []
    if pointer_size() >= 8:
        return describe_x64_callsite_arguments(call_address)
    return describe_x86_stack_arguments(call_address)


def describe_x64_callsite_arguments(call_address):
    storages = ["RCX", "RDX", "R8", "R9"]
    hints = []
    assignments = {}
    instruction = getInstructionAt(call_address)
    if instruction is None:
        return hints
    previous = instruction.getPrevious()
    steps = 0
    while previous is not None and steps < MAX_CALLSITE_SCAN_BACK and len(assignments) < len(storages):
        mnemonic = to_text(previous.getMnemonicString()).upper()
        if previous.getFlowType().isJump() or previous.getFlowType().isTerminal():
            break
        if mnemonic in ("MOV", "LEA", "XOR"):
            destination = operand_repr(previous, 0).upper()
            if destination in storages and destination not in assignments:
                source_repr = operand_repr(previous, 1)
                assignments[destination] = classify_argument_source(source_repr, destination)
        previous = previous.getPrevious()
        steps += 1
    for index in range(len(storages)):
        storage = storages[index]
        hint = assignments.get(storage) or {"position": index, "storage": storage, "source_repr": storage}
        hint["position"] = index
        hint["storage"] = storage
        hints.append(hint)
    return hints


def describe_x86_stack_arguments(call_address):
    hints = []
    instruction = getInstructionAt(call_address)
    if instruction is None:
        return hints
    previous = instruction.getPrevious()
    pushes = []
    steps = 0
    while previous is not None and steps < MAX_CALLSITE_SCAN_BACK:
        mnemonic = to_text(previous.getMnemonicString()).upper()
        if previous.getFlowType().isJump() or previous.getFlowType().isTerminal():
            break
        if mnemonic == "PUSH":
            pushes.append(classify_argument_source(operand_repr(previous, 0), "stack"))
        elif pushes:
            break
        previous = previous.getPrevious()
        steps += 1
    pushes.reverse()
    for index in range(len(pushes)):
        hint = pushes[index]
        hint["position"] = index
        hint["storage"] = "stack[%d]" % index
        hints.append(hint)
    return hints


def operand_repr(instruction, index):
    try:
        return to_text(instruction.getDefaultOperandRepresentation(index)).strip()
    except Exception:
        return ""


def classify_argument_source(source_repr, storage):
    text = to_text(source_repr or "").strip()
    lowered = text.lower()
    hint = {
        "storage": storage,
        "source_repr": text,
        "source_kind": "value",
    }
    if not text:
        return hint
    if lowered.startswith(("0x", "0x")) or lowered.isdigit():
        hint["source_kind"] = "constant"
        hint["name_hint"] = "flags" if lowered in ("0", "1", "2", "3") else "value"
        hint["type_hint"] = "uint"
        return hint
    if '"' in text or "unicode" in lowered or "ascii" in lowered:
        hint["source_kind"] = "string"
        hint["name_hint"] = classify_string_name_hint(lowered)
        hint["type_hint"] = "const char *"
        return hint
    if any(keyword in lowered for keyword in ("flag", "mode", "option")):
        hint["name_hint"] = "flags"
        hint["type_hint"] = "uint"
    elif any(keyword in lowered for keyword in ("path", "file", ".exe", ".dll", ".json")):
        hint["name_hint"] = "path"
        hint["type_hint"] = "const char *"
    elif any(keyword in lowered for keyword in ("name", "title", "label")):
        hint["name_hint"] = "name"
        hint["type_hint"] = "const char *"
    elif any(keyword in lowered for keyword in ("text", "message", "msg", "error")):
        hint["name_hint"] = "message"
        hint["type_hint"] = "const char *"
    elif any(keyword in lowered for keyword in ("count", "length", "len", "size")):
        hint["name_hint"] = "count"
        hint["type_hint"] = "size_t"
    elif any(keyword in lowered for keyword in ("index", "slot", "id")):
        hint["name_hint"] = "index"
        hint["type_hint"] = "uint"
    elif any(keyword in lowered for keyword in ("buf", "buffer", "dst", "src")):
        hint["name_hint"] = "buffer"
        hint["type_hint"] = "void *"
    elif storage == "RCX":
        hint["name_hint"] = "this"
    if any(token in lowered for token in ("ptr", "[", "rbp", "rsp", "esp", "eax", "ecx", "edx", "rax", "rcx", "rdx", "r8", "r9")) and "type_hint" not in hint:
        hint["type_hint"] = "void *"
    return hint


def classify_string_name_hint(lowered):
    if any(keyword in lowered for keyword in ("path", "file", ".exe", ".dll", ".json")):
        return "path"
    if any(keyword in lowered for keyword in ("error", "msg", "message")):
        return "message"
    if "name" in lowered:
        return "name"
    return "text"


def describe_callsite_result_usage(call_address):
    instruction = getInstructionAt(call_address)
    if instruction is None:
        return None
    language_id = language_id_text()
    register_aliases = ["EAX", "AX", "AL"]
    if pointer_size() >= 8:
        register_aliases = ["RAX", "EAX", "AX", "AL"]
    arg_registers = ["RCX", "RDX", "R8", "R9"] if pointer_size() >= 8 else []
    current = instruction.getNext()
    pending_argument = None
    saw_zero_test = False
    steps = 0
    while current is not None and steps < MAX_RESULT_SCAN_FORWARD:
        mnemonic = to_text(current.getMnemonicString()).upper()
        op0 = operand_repr(current, 0)
        op1 = operand_repr(current, 1)
        op0_upper = op0.upper()
        op1_upper = op1.upper()
        sample = "%s %s %s" % (mnemonic, op0, op1)

        if _operand_dereferences_result(op0_upper, register_aliases) or _operand_dereferences_result(op1_upper, register_aliases):
            return {"type_hint": "void *", "reason": "result_dereferenced", "sample": sample.strip()}

        if mnemonic in ("TEST", "CMP") and _zero_test_mentions_result(op0_upper, op1_upper, register_aliases):
            saw_zero_test = True

        if mnemonic == "MOV" and _operand_mentions_result(op1_upper, register_aliases):
            if op0_upper in arg_registers:
                pending_argument = op0_upper
        elif mnemonic == "LEA" and _operand_mentions_result(op1_upper, register_aliases):
            if op0_upper in arg_registers:
                pending_argument = op0_upper
        elif mnemonic == "PUSH" and _operand_mentions_result(op0_upper, register_aliases):
            pending_argument = "STACK"

        if mnemonic == "CALL":
            target_name = resolve_call_target_name(current)
            if pending_argument is not None:
                hint = classify_result_use_target(target_name or "")
                if hint:
                    hint["sample"] = sample.strip()
                    hint["argument_storage"] = pending_argument
                    hint["argument_position"] = argument_position_for_storage(pending_argument)
                    return hint
                return {
                    "type_hint": "void *",
                    "reason": "result_passed_to_call",
                    "callee": target_name,
                    "sample": sample.strip(),
                    "argument_storage": pending_argument,
                    "argument_position": argument_position_for_storage(pending_argument),
                }

        if saw_zero_test and mnemonic.startswith("J"):
            return {"type_hint": "bool", "reason": "result_tested_for_branch", "sample": sample.strip()}

        if current.getFlowType().isTerminal():
            break
        current = current.getNext()
        steps += 1
    return None


def _operand_mentions_result(operand_upper, register_aliases):
    if not operand_upper:
        return False
    for alias in register_aliases:
        if operand_upper == alias:
            return True
        if operand_upper.endswith("," + alias):
            return True
    return False


def _operand_dereferences_result(operand_upper, register_aliases):
    if not operand_upper:
        return False
    for alias in register_aliases:
        if "[" + alias in operand_upper:
            return True
    return False


def _zero_test_mentions_result(op0_upper, op1_upper, register_aliases):
    if not _operand_mentions_result(op0_upper, register_aliases) and not _operand_mentions_result(op1_upper, register_aliases):
        return False
    if op0_upper == op1_upper and op0_upper in register_aliases:
        return True
    return op0_upper in register_aliases and op1_upper in ("0", "0X0") or op1_upper in register_aliases and op0_upper in ("0", "0X0")


def resolve_call_target_name(instruction):
    try:
        references = instruction.getReferencesFrom()
    except Exception:
        references = []
    for reference in references or []:
        try:
            to_address = reference.getToAddress()
            function = getFunctionAt(to_address)
            if function is None:
                function = getFunctionContaining(to_address)
            if function is not None:
                namespace = function.getParentNamespace()
                if namespace is not None:
                    namespace_name = namespace.getName(True)
                    if namespace_name and namespace_name not in ("Global", "global"):
                        return "%s::%s" % (namespace_name, function.getName())
                return function.getName()
        except Exception:
            continue
    return operand_repr(instruction, 0)


def classify_result_use_target(target_name):
    lowered = to_text(target_name or "").lower()
    if not lowered:
        return None
    if any(keyword in lowered for keyword in ("strlen", "strcmp", "strstr", "string", "json", "text", "name", "label", "message", "printf", "puts", "path", "file")):
        return {"type_hint": "const char *", "reason": "result_passed_to_string_like_api", "callee": target_name}
    if any(keyword in lowered for keyword in ("wcs", "widechar", "unicode")):
        return {"type_hint": "const wchar_t *", "reason": "result_passed_to_wide_string_api", "callee": target_name}
    if any(keyword in lowered for keyword in ("createfile", "openfile", "path", "fopen")):
        return {"type_hint": "const char *", "reason": "result_used_as_path", "callee": target_name}
    return None


def argument_position_for_storage(storage):
    text = to_text(storage or "").upper()
    if text == "RCX":
        return 0
    if text == "RDX":
        return 1
    if text == "R8":
        return 2
    if text == "R9":
        return 3
    if text.startswith("STACK"):
        return 0
    return None


def load_target_selection(selection_path):
    if not selection_path or not os.path.isfile(selection_path):
        return {}
    try:
        payload = read_json(selection_path)
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    by_address = {}
    for target in payload.get("targets") or []:
        if not isinstance(target, dict):
            continue
        address = to_text(target.get("address") or "").strip().lower()
        if not address:
            continue
        if not address.startswith("0x"):
            try:
                address = "0x%x" % int(address, 16)
            except Exception:
                continue
        by_address[address] = target
    return by_address


def load_target_selection_addresses(selection_path):
    if not selection_path or not os.path.isfile(selection_path):
        return []
    try:
        payload = read_json(selection_path)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    addresses = []
    seen = set()
    for target in payload.get("targets") or []:
        if not isinstance(target, dict):
            continue
        address = to_text(target.get("address") or "").strip().lower()
        if not address:
            continue
        if not address.startswith("0x"):
            try:
                address = "0x%x" % int(address, 16)
            except Exception:
                continue
        if address in seen:
            continue
        seen.add(address)
        addresses.append(address)
    return addresses


def load_target_function_addresses(manifest_path, selection_path=None):
    selection_addresses = load_target_selection_addresses(selection_path)
    if selection_addresses:
        return selection_addresses
    if not manifest_path or not os.path.isfile(manifest_path):
        return []
    try:
        payload = read_json(manifest_path)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    addresses = []
    seen = set()
    class_names = []
    for class_entry in payload.get("classes") or []:
        if not isinstance(class_entry, dict):
            continue
        class_name = to_text(class_entry.get("name") or "").strip()
        if class_name:
            class_names.append(class_name)
        for method in class_entry.get("methods") or []:
            if not isinstance(method, dict):
                continue
            address = to_text(method.get("address") or method.get("entry_point") or "").strip()
            if not address:
                continue
            lowered = address.lower()
            if not lowered.startswith("0x"):
                try:
                    lowered = "0x%x" % int(lowered, 16)
                except Exception:
                    continue
            if lowered in seen:
                continue
            seen.add(lowered)
            addresses.append(lowered)
            if len(addresses) >= MAX_TARGET_DECOMPILATIONS:
                return addresses
    for class_name in class_names:
        for address_text in discover_related_class_functions(class_name):
            if address_text in seen:
                continue
            seen.add(address_text)
            addresses.append(address_text)
            if len(addresses) >= MAX_TARGET_DECOMPILATIONS:
                return addresses
    return addresses


def discover_related_class_functions(class_name):
    related = []
    if not class_name:
        return related
    short_name = class_name.split("::")[-1]
    full_class_lower = to_text(class_name).lower()
    short_class_lower = to_text(short_name).lower()
    function_iterator = currentProgram.getFunctionManager().getFunctions(True)
    while function_iterator.hasNext():
        function = function_iterator.next()
        try:
            namespace = function.getParentNamespace()
            namespace_name = namespace.getName(True) if namespace else ""
        except Exception:
            namespace_name = ""
        try:
            signature = to_text(function.getSignature())
        except Exception:
            signature = ""
        try:
            name = to_text(function.getName())
        except Exception:
            name = ""
        namespace_lower = namespace_name.lower()
        signature_lower = signature.lower()
        name_lower = name.lower()
        if not is_related_class_function(namespace_lower, signature_lower, name_lower, full_class_lower, short_class_lower):
            continue
        related.append("0x%x" % int(str(function.getEntryPoint()), 16))
    return related


def is_related_class_function(namespace_lower, signature_lower, name_lower, full_class_lower, short_class_lower):
    if namespace_lower == full_class_lower:
        return True
    if signature_lower.startswith(short_class_lower + " * __thiscall " + short_class_lower + "("):
        return True
    if signature_lower.startswith("void __thiscall ~" + short_class_lower + "("):
        return True
    if "(" + short_class_lower + " * this" in signature_lower:
        return True
    if name_lower == short_class_lower or name_lower == "~" + short_class_lower:
        return True
    return False


def decompile_target_functions(manifest_path, output_path, selection_path=None):
    if not manifest_path or not output_path:
        return []
    selection = load_target_selection(selection_path)
    addresses = load_target_function_addresses(manifest_path, selection_path)
    if not addresses:
        return []

    output_dir = os.path.dirname(output_path)
    pseudo_dir = os.path.join(output_dir, "pseudo_code")
    ensure_dir(output_dir)
    ensure_dir(pseudo_dir)

    interface = DecompInterface()
    options = DecompileOptions()
    interface.setOptions(options)
    interface.toggleCCode(True)
    interface.toggleSyntaxTree(True)
    interface.setSimplificationStyle("decompile")
    interface.openProgram(currentProgram)

    entries = []
    try:
        for address_text in addresses:
            if monitor.isCancelled():
                break
            try:
                address_value = int(address_text, 16)
                address = toAddr(address_value)
            except Exception:
                entries.append(
                    {
                        "requested_address": address_text,
                        "decompile_success": False,
                        "error": "invalid_address",
                    }
                )
                continue
            function = getFunctionAt(address)
            if function is None:
                function = getFunctionContaining(address)
            if function is None:
                entries.append(
                    {
                        "requested_address": address_text,
                        "decompile_success": False,
                        "error": "no_function_at_address",
                    }
                )
                continue

            result = interface.decompileFunction(function, TARGET_DECOMPILE_TIMEOUT_SECONDS, monitor)
            entry = {
                "requested_address": address_text,
                "entry_point": str(function.getEntryPoint()),
                "name": function.getName(),
                "signature": to_text(function.getSignature()),
                "namespace": function.getParentNamespace().getName(True) if function.getParentNamespace() else None,
                "return_type": to_text(function.getReturnType()),
                "parameters": describe_parameters(function),
                "callers": describe_callers(function),
                "callees": describe_callees(function),
                "decompile_success": False,
            }
            entry["callee_count"] = len(entry.get("callees") or [])
            entry["caller_count"] = len(entry.get("callers") or [])
            entry["result_hints"] = [caller.get("result_hint") for caller in entry.get("callers") or [] if caller.get("result_hint")]
            target_metadata = selection.get(str(entry.get("requested_address") or "").lower()) or selection.get(str(entry.get("entry_point") or "").lower())
            if target_metadata:
                entry["target_selection"] = target_metadata
            if result is None:
                entry["error"] = "no_decompile_result"
                entries.append(entry)
                continue
            if not result.decompileCompleted():
                entry["error"] = to_text(result.getErrorMessage()) or "decompile_failed"
                entries.append(entry)
                continue
            try:
                decompiled_text = to_text(result.getDecompiledFunction().getC())
            except Exception:
                decompiled_text = None
            if not decompiled_text:
                entry["error"] = to_text(result.getErrorMessage()) or "empty_decompilation"
                entries.append(entry)
                continue
            if len(decompiled_text) > MAX_DECOMPILED_TEXT_CHARS:
                decompiled_text = decompiled_text[:MAX_DECOMPILED_TEXT_CHARS] + "\n/* truncated */"
            pseudo_name = "%s_%s.c" % (
                safe_filename_component(function.getName()),
                safe_filename_component(str(function.getEntryPoint())),
            )
            pseudo_path = os.path.join(pseudo_dir, pseudo_name)
            handle = open(pseudo_path, "w")
            try:
                handle.write(decompiled_text)
            finally:
                handle.close()
            entry["decompile_success"] = True
            entry["decompiled_c"] = decompiled_text
            entry["pseudo_path"] = pseudo_path
            entries.append(entry)
    finally:
        try:
            interface.dispose()
        except Exception:
            pass

    write_json(output_path, entries)
    return entries


def scan_ascii_strings(strings, seen):
    memory = currentProgram.getMemory()
    for block in memory.getBlocks():
        if monitor.isCancelled() or len(strings) >= MAX_STRINGS:
            break
        if not block.isInitialized() or not block.isLoaded():
            continue
        try:
            size = int(block.getSize())
        except Exception:
            continue
        if size <= 0:
            continue
        start = block.getStart()
        try:
            payload = getBytes(start, size)
        except Exception:
            continue
        current = []
        current_start = None
        for index in range(len(payload)):
            byte = payload[index]
            if byte < 0:
                byte += 256
            if 32 <= byte <= 126 or byte == 9:
                if current_start is None:
                    current_start = start.add(index)
                current.append(chr(byte))
                continue
            if len(current) >= MIN_STRING_LENGTH and current_start is not None:
                add_string(strings, seen, current_start, "ascii", len(current), "".join(current), "ascii_scan")
                if len(strings) >= MAX_STRINGS:
                    break
            current = []
            current_start = None
        if len(current) >= MIN_STRING_LENGTH and current_start is not None and len(strings) < MAX_STRINGS:
            add_string(strings, seen, current_start, "ascii", len(current), "".join(current), "ascii_scan")


args = getScriptArgs()
if len(args) < 1:
    raise ValueError("REProExport.py requires an output directory argument.")

output_dir = args[0]
rtti_manifest_path = args[1] if len(args) >= 2 else ""
targeted_decompilation_path = args[2] if len(args) >= 3 else ""
target_selection_path = args[3] if len(args) >= 4 else ""
ensure_dir(output_dir)

functions = []
function_export_truncated = False
function_iterator = currentProgram.getFunctionManager().getFunctions(True)
while function_iterator.hasNext() and not monitor.isCancelled():
    if len(functions) >= MAX_FUNCTION_EXPORTS:
        function_export_truncated = True
        break
    function = function_iterator.next()
    body = function.getBody()
    thunk_target = function.getThunkedFunction(False)
    namespace = function.getParentNamespace()
    functions.append(
        {
            "name": function.getName(),
            "entry_point": str(function.getEntryPoint()),
            "body_min": str(body.getMinAddress()) if body else None,
            "body_max": str(body.getMaxAddress()) if body else None,
            "is_thunk": function.isThunk(),
            "thunk_target": thunk_target.getName() if thunk_target else None,
            "calling_convention": function.getCallingConventionName(),
            "signature": to_text(function.getSignature()),
            "namespace": namespace.getName(True) if namespace else None,
        }
    )

strings = []
seen_string_addresses = set()
for data in DefinedStringIterator.forProgram(currentProgram, currentSelection):
    if monitor.isCancelled() or len(strings) >= MAX_STRINGS:
        break
    try:
        string_data = StringDataInstance.getStringDataInstance(data)
        text = string_data.getStringValue() if string_data is not None else None
    except Exception:
        text = None
    if text is None and data.hasStringValue():
        text = data.getValue()
    add_string(strings, seen_string_addresses, data.getMinAddress(), data.getMnemonicString(), data.getLength(), text, "defined_string")

if len(strings) < MAX_STRINGS:
    data = getFirstData()
    while data is not None and not monitor.isCancelled() and len(strings) < MAX_STRINGS:
        if data.hasStringValue():
            add_string(
                strings,
                seen_string_addresses,
                data.getMinAddress(),
                data.getMnemonicString(),
                data.getLength(),
                data.getValue(),
                "data_string",
            )
        data = getDataAfter(data)

if len(strings) < ASCII_FALLBACK_THRESHOLD:
    scan_ascii_strings(strings, seen_string_addresses)

entry_points = []
entry_iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator()
while entry_iterator.hasNext():
    entry_points.append(str(entry_iterator.next()))

analysis_timed_out = False
try:
    analysis_timed_out = bool(getHeadlessAnalysisTimeoutStatus())
except Exception:
    analysis_timed_out = False

program_info = {
    "program_name": currentProgram.getName(),
    "domain_file": currentProgram.getDomainFile().getPathname(),
    "executable_format": currentProgram.getExecutableFormat(),
    "language_id": str(currentProgram.getLanguageID()),
    "compiler_spec_id": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
    "image_base": str(currentProgram.getImageBase()),
    "function_count": len(functions),
    "function_export_limit": MAX_FUNCTION_EXPORTS,
    "function_export_truncated": function_export_truncated,
    "string_count": len(strings),
    "entry_points": entry_points,
    "analysis_timed_out": analysis_timed_out,
}

targeted_decompilations = decompile_target_functions(rtti_manifest_path, targeted_decompilation_path, target_selection_path)
write_json(os.path.join(output_dir, "program_info.json"), program_info)
write_json_compact(os.path.join(output_dir, "functions.json"), functions)
write_json(os.path.join(output_dir, "strings.json"), strings)
print("RE-Pro Ghidra export wrote %d functions and %d strings to %s" % (len(functions), len(strings), output_dir))
if targeted_decompilations:
    print("RE-Pro Ghidra export wrote %d targeted decompilation(s) to %s" % (len(targeted_decompilations), targeted_decompilation_path))
