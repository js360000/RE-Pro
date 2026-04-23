from .android import AndroidAnalyzer
from .apple import AppleAnalyzer
from .dotnet import DotNetAnalyzer
from .electron import ElectronAnalyzer
from .external_tools import ExternalToolAnalyzer
from .game import GameNativeAnalyzer
from .installer import InstallerAnalyzer
from .linux_package import LinuxPackageAnalyzer
from .java import JavaPackageAnalyzer
from .llm import LLMAssistAnalyzer
from .native import NativeLanguageAnalyzer
from .pdb import PDBAnalyzer
from .pe import PEAnalyzer
from .porting import PortingAdvisorAnalyzer
from .python_packaged import PythonPackagedAnalyzer
from .resources import PEResourceAnalyzer
from .runtime_trace import RuntimeTraceAnalyzer
from .tauri import TauriAnalyzer
from .wasm import WasmAnalyzer

BUILTIN_ANALYZER_CLASSES = [
    AndroidAnalyzer,
    AppleAnalyzer,
    PEAnalyzer,
    PDBAnalyzer,
    PEResourceAnalyzer,
    InstallerAnalyzer,
    LinuxPackageAnalyzer,
    JavaPackageAnalyzer,
    ElectronAnalyzer,
    TauriAnalyzer,
    DotNetAnalyzer,
    PythonPackagedAnalyzer,
    NativeLanguageAnalyzer,
    GameNativeAnalyzer,
    WasmAnalyzer,
    ExternalToolAnalyzer,
    RuntimeTraceAnalyzer,
    LLMAssistAnalyzer,
    PortingAdvisorAnalyzer,
]


def builtin_analyzers():
    return [analyzer_class() for analyzer_class in BUILTIN_ANALYZER_CLASSES]


__all__ = [
    "AndroidAnalyzer",
    "AppleAnalyzer",
    "BUILTIN_ANALYZER_CLASSES",
    "DotNetAnalyzer",
    "ElectronAnalyzer",
    "ExternalToolAnalyzer",
    "GameNativeAnalyzer",
    "InstallerAnalyzer",
    "LinuxPackageAnalyzer",
    "JavaPackageAnalyzer",
    "LLMAssistAnalyzer",
    "NativeLanguageAnalyzer",
    "PDBAnalyzer",
    "PEAnalyzer",
    "PEResourceAnalyzer",
    "PortingAdvisorAnalyzer",
    "PythonPackagedAnalyzer",
    "TauriAnalyzer",
    "RuntimeTraceAnalyzer",
    "WasmAnalyzer",
    "builtin_analyzers",
]
