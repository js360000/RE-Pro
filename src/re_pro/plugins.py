from __future__ import annotations

import hashlib
import importlib.util
import inspect
import os
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Callable

from .analyzers import builtin_analyzers
from .analyzers.base import Analyzer

ENTRY_POINT_GROUP = "re_pro.analyzers"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLUGIN_DIR = REPO_ROOT / "plugins"


def resolve_plugin_dirs(plugin_dirs: list[str | Path] | None = None) -> list[Path]:
    resolved: list[Path] = []
    candidates: list[str | Path] = []
    if plugin_dirs:
        candidates.extend(plugin_dirs)
    env_value = os.environ.get("RE_PRO_PLUGIN_DIRS", "").strip()
    if env_value:
        candidates.extend(part for part in env_value.split(os.pathsep) if part)
    if DEFAULT_PLUGIN_DIR.exists():
        candidates.append(DEFAULT_PLUGIN_DIR)

    seen: set[Path] = set()
    for candidate in candidates:
        path = Path(candidate).expanduser().resolve()
        if path in seen or not path.exists() or not path.is_dir():
            continue
        seen.add(path)
        resolved.append(path)
    return resolved


def build_analyzers(
    *,
    plugin_dirs: list[str | Path] | None = None,
    logger: Callable[[str], None] | None = None,
) -> list[Analyzer]:
    analyzers = builtin_analyzers()
    analyzers.extend(discover_plugin_analyzers(plugin_dirs=plugin_dirs, logger=logger))
    return analyzers


def discover_plugin_analyzers(
    *,
    plugin_dirs: list[str | Path] | None = None,
    logger: Callable[[str], None] | None = None,
) -> list[Analyzer]:
    discovered: list[Analyzer] = []
    for entry_point in _iter_entry_points():
        try:
            loaded = entry_point.load()
            analyzers = _materialize_plugin_object(loaded, source=f"entry point {entry_point.name}", logger=logger)
            discovered.extend(analyzers)
            _log(logger, f"Loaded {len(analyzers)} analyzer plugin(s) from entry point {entry_point.name}.")
        except Exception as exc:
            _log(logger, f"Failed to load analyzer entry point {entry_point.name}: {exc}")

    for plugin_dir in resolve_plugin_dirs(plugin_dirs):
        for plugin_path in sorted(plugin_dir.glob("*.py")):
            if plugin_path.name.startswith("_"):
                continue
            try:
                module = _load_plugin_module(plugin_path)
                analyzers = _materialize_module(module, plugin_path, logger=logger)
                discovered.extend(analyzers)
                _log(logger, f"Loaded {len(analyzers)} analyzer plugin(s) from {plugin_path.name}.")
            except Exception as exc:
                _log(logger, f"Failed to load analyzer plugin {plugin_path}: {exc}")
    return discovered


def _iter_entry_points():
    try:
        return entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        return entry_points().get(ENTRY_POINT_GROUP, [])


def _load_plugin_module(plugin_path: Path) -> ModuleType:
    digest = hashlib.sha1(str(plugin_path).encode("utf-8")).hexdigest()[:12]
    module_name = f"re_pro_plugin_{plugin_path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create an import spec for {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _materialize_module(
    module: ModuleType,
    plugin_path: Path,
    *,
    logger: Callable[[str], None] | None = None,
) -> list[Analyzer]:
    if hasattr(module, "register_analyzers"):
        register = module.register_analyzers
        if not callable(register):
            raise TypeError(f"{plugin_path.name}: register_analyzers exists but is not callable")
        return _materialize_plugin_object(register(), source=str(plugin_path), logger=logger)

    if hasattr(module, "ANALYZERS"):
        return _materialize_plugin_object(module.ANALYZERS, source=str(plugin_path), logger=logger)

    classes = [
        value
        for _, value in inspect.getmembers(module, inspect.isclass)
        if issubclass(value, Analyzer) and value is not Analyzer and value.__module__ == module.__name__
    ]
    if not classes:
        raise ValueError(f"{plugin_path.name}: no analyzers were exported")
    analyzers: list[Analyzer] = []
    for cls in classes:
        analyzers.append(cls())
    return analyzers


def _materialize_plugin_object(
    loaded,
    *,
    source: str,
    logger: Callable[[str], None] | None = None,
) -> list[Analyzer]:
    if isinstance(loaded, Analyzer):
        return [loaded]
    if inspect.isclass(loaded) and issubclass(loaded, Analyzer):
        return [loaded()]
    if callable(loaded) and not isinstance(loaded, (str, bytes, os.PathLike)):
        return _materialize_plugin_object(loaded(), source=source, logger=logger)
    if isinstance(loaded, (list, tuple, set)):
        analyzers: list[Analyzer] = []
        for item in loaded:
            analyzers.extend(_materialize_plugin_object(item, source=source, logger=logger))
        return analyzers
    raise TypeError(f"{source}: unsupported analyzer plugin export {type(loaded).__name__}")


def _log(logger: Callable[[str], None] | None, message: str) -> None:
    if logger:
        logger(message)
