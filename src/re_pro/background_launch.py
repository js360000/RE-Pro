from __future__ import annotations

import os
import sys
from pathlib import Path

from .tooling import REPO_ROOT


def build_re_pro_background_command(command: str, *args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, command, *args]
    return [sys.executable, "-m", "re_pro.cli", command, *args]


def build_re_pro_background_env() -> dict[str, str]:
    env = os.environ.copy()
    if getattr(sys, "frozen", False):
        return env
    src_root = str((REPO_ROOT / "src").resolve())
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src_root if not existing_pythonpath else src_root + os.pathsep + existing_pythonpath
    return env


def re_pro_background_cwd() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return REPO_ROOT
