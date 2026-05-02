from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    raw = _env(name, default)
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    bind: str
    public_base_url: str
    service_slug: str
    service_name: str
    cookie_name: str
    cookie_domain: str
    allowed_wallets: tuple[str, ...]
    session_ttl_seconds: int
    challenge_ttl_seconds: int
    ticket_ttl_seconds: int
    secure_cookies: bool
    signer_network: str
    signature_verifier_mode: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            bind=_env("KBEAM_AUTH_BIND", "127.0.0.1:18090"),
            public_base_url=_env("KBEAM_AUTH_PUBLIC_BASE_URL", "https://auth.example.com").rstrip("/"),
            service_slug=_env("KBEAM_AUTH_SERVICE_SLUG", "example-service"),
            service_name=_env("KBEAM_AUTH_SERVICE_NAME", "Example Service"),
            cookie_name=_env("KBEAM_AUTH_COOKIE_NAME", "kbeam_auth_session"),
            cookie_domain=_env("KBEAM_AUTH_COOKIE_DOMAIN", ""),
            allowed_wallets=_env_csv("KBEAM_AUTH_ALLOWED_WALLETS", "kaspa:example"),
            session_ttl_seconds=_env_int("KBEAM_AUTH_SESSION_TTL_SECONDS", 28800),
            challenge_ttl_seconds=_env_int("KBEAM_AUTH_CHALLENGE_TTL_SECONDS", 300),
            ticket_ttl_seconds=_env_int("KBEAM_AUTH_TICKET_TTL_SECONDS", 300),
            secure_cookies=_env_bool("KBEAM_AUTH_SECURE_COOKIES", True),
            signer_network=_env("KBEAM_AUTH_SIGNER_NETWORK", "mainnet"),
            signature_verifier_mode=_env("KBEAM_AUTH_SIGNATURE_VERIFIER_MODE", "native"),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.public_base_url.startswith(("https://", "http://")):
            errors.append("KBEAM_AUTH_PUBLIC_BASE_URL must be an absolute URL")
        if not self.service_slug:
            errors.append("KBEAM_AUTH_SERVICE_SLUG is required")
        if not self.service_name:
            errors.append("KBEAM_AUTH_SERVICE_NAME is required")
        if not self.cookie_name:
            errors.append("KBEAM_AUTH_COOKIE_NAME is required")
        if self.session_ttl_seconds < 300:
            errors.append("KBEAM_AUTH_SESSION_TTL_SECONDS must be at least 300")
        if self.challenge_ttl_seconds < 60:
            errors.append("KBEAM_AUTH_CHALLENGE_TTL_SECONDS must be at least 60")
        if self.ticket_ttl_seconds < 60:
            errors.append("KBEAM_AUTH_TICKET_TTL_SECONDS must be at least 60")
        if self.signature_verifier_mode not in {"native", "demo", "disabled"}:
            errors.append("KBEAM_AUTH_SIGNATURE_VERIFIER_MODE must be native, demo, or disabled")
        return errors
