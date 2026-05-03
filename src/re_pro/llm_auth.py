from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LLM_AUTH_PROVIDERS = {"auto", "api-key", "codex-oauth"}


@dataclass(frozen=True)
class CodexOAuthToken:
    access_token: str
    auth_path: Path
    auth_mode: str = ""
    account_id: str = ""


def normalize_llm_auth_provider(value: str | None) -> str:
    provider = (value or "auto").strip().lower()
    return provider if provider in LLM_AUTH_PROVIDERS else "auto"


def default_codex_auth_path() -> Path:
    configured = os.environ.get("CODEX_AUTH_JSON", "").strip()
    if configured:
        return Path(configured).expanduser()
    codex_home = os.environ.get("CODEX_HOME", "").strip()
    if codex_home:
        return Path(codex_home).expanduser() / "auth.json"
    return Path.home() / ".codex" / "auth.json"


def resolve_codex_auth_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path).expanduser()
    return default_codex_auth_path()


def load_codex_oauth_token(path: str | Path | None = None) -> CodexOAuthToken | None:
    auth_path = resolve_codex_auth_path(path)
    try:
        payload = json.loads(auth_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    tokens = payload.get("tokens")
    token = ""
    if isinstance(tokens, dict):
        token = str(tokens.get("access_token") or "").strip()
    if not token:
        token = str(payload.get("access_token") or "").strip()
    if not token:
        return None
    account = payload.get("account")
    account_id = ""
    if isinstance(account, dict):
        account_id = str(account.get("id") or account.get("account_id") or "")
    return CodexOAuthToken(
        access_token=token,
        auth_path=auth_path,
        auth_mode=str(payload.get("auth_mode") or payload.get("authMode") or ""),
        account_id=account_id,
    )


def llm_auth_available(settings: Any) -> bool:
    provider = normalize_llm_auth_provider(str(getattr(settings, "auth_provider", "auto")))
    if provider in {"auto", "api-key"} and bool(os.environ.get("OPENAI_API_KEY")):
        return True
    if provider in {"auto", "codex-oauth"}:
        return load_codex_oauth_token(str(getattr(settings, "codex_auth_path", "")) or None) is not None
    return False


def llm_auth_missing_message(settings: Any) -> str:
    provider = normalize_llm_auth_provider(str(getattr(settings, "auth_provider", "auto")))
    auth_path = resolve_codex_auth_path(str(getattr(settings, "codex_auth_path", "")) or None)
    if provider == "api-key":
        return "LLM-assisted reconstruction was requested, but OPENAI_API_KEY is not set."
    if provider == "codex-oauth":
        return f"LLM-assisted reconstruction was requested, but no Codex OAuth access token was found at {auth_path}."
    return f"LLM-assisted reconstruction was requested, but neither OPENAI_API_KEY nor a Codex OAuth access token at {auth_path} is available."


def build_openai_client_for_settings(settings: Any):
    from openai import OpenAI

    provider = normalize_llm_auth_provider(str(getattr(settings, "auth_provider", "auto")))
    if provider in {"auto", "api-key"} and os.environ.get("OPENAI_API_KEY"):
        return OpenAI()
    if provider in {"auto", "codex-oauth"}:
        token = load_codex_oauth_token(str(getattr(settings, "codex_auth_path", "")) or None)
        if token is not None:
            return OpenAI(api_key=token.access_token)
    return OpenAI()


def llm_auth_status(settings: Any) -> dict[str, object]:
    provider = normalize_llm_auth_provider(str(getattr(settings, "auth_provider", "auto")))
    codex_path = resolve_codex_auth_path(str(getattr(settings, "codex_auth_path", "")) or None)
    codex_token = load_codex_oauth_token(codex_path)
    has_api_key = bool(os.environ.get("OPENAI_API_KEY"))
    return {
        "provider": provider,
        "has_openai_api_key": has_api_key,
        "codex_auth_path": str(codex_path),
        "has_codex_oauth_token": codex_token is not None,
        "codex_auth_mode": codex_token.auth_mode if codex_token else "",
        "selected": "api-key" if provider in {"auto", "api-key"} and has_api_key else ("codex-oauth" if provider in {"auto", "codex-oauth"} and codex_token else "unavailable"),
    }
