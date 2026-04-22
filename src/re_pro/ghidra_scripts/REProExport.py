# RE-Pro Ghidra headless export script.
# @category RE-Pro
# @runtime Jython

import json
import os

from ghidra.program.model.data import StringDataInstance
from ghidra.program.util import DefinedStringIterator


MIN_STRING_LENGTH = 5
MAX_STRINGS = 1024
ASCII_FALLBACK_THRESHOLD = 256


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
ensure_dir(output_dir)

functions = []
function_iterator = currentProgram.getFunctionManager().getFunctions(True)
while function_iterator.hasNext() and not monitor.isCancelled():
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
    "string_count": len(strings),
    "entry_points": entry_points,
    "analysis_timed_out": analysis_timed_out,
}

write_json(os.path.join(output_dir, "program_info.json"), program_info)
write_json(os.path.join(output_dir, "functions.json"), functions)
write_json(os.path.join(output_dir, "strings.json"), strings)
print("RE-Pro Ghidra export wrote %d functions and %d strings to %s" % (len(functions), len(strings), output_dir))
