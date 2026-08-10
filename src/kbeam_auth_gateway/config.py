from __future__ import annotations

import os
from dataclasses import dataclass
from ipaddress import ip_network
from urllib.parse import urlparse

from dotenv import load_dotenv


def normalize_host_authority(value: str) -> str:
    """Return a strict lowercase Host authority, including an explicit port."""

    raw = value.strip()
    if (
        not raw
        or any(character.isspace() for character in raw)
        or any(character in raw for character in ("/", "\\", "?", "#", "@", "%"))
        or "://" in raw
    ):
        raise ValueError("invalid_host_authority")
    parsed = urlparse(f"//{raw}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_host_authority") from exc
    host = (parsed.hostname or "").lower()
    if (
        not host
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or host.startswith(".")
        or host.endswith(".")
    ):
        raise ValueError("invalid_host_authority")
    rendered_host = f"[{host}]" if ":" in host else host
    authority = f"{rendered_host}:{port}" if port is not None else rendered_host
    if authority != raw.lower():
        raise ValueError("invalid_host_authority")
    return authority


def normalize_public_origin(value: str) -> str:
    """Return the canonical scheme and authority for a configured public URL."""

    parsed = urlparse(value.strip())
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid_public_origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_public_origin") from exc
    host = parsed.hostname.lower()
    if "%" in host:
        raise ValueError("invalid_public_origin")
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    port_suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme.lower()}://{rendered_host}{port_suffix}"


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
    wallet_policy: str = "allowlist"
    store_backend: str = "sqlite"
    sqlite_path: str = "./var/kbeam-auth-gateway.sqlite3"
    postgres_dsn: str = ""
    admin_token: str = ""
    max_pending_tickets: int = 1000
    rate_limit_window_seconds: int = 60
    rate_limit_device_login: int = 20
    rate_limit_ticket_poll: int = 120
    rate_limit_ticket_events: int = 30
    rate_limit_challenge: int = 60
    rate_limit_approve: int = 60
    rate_limit_admin: int = 120
    trusted_proxy_cidrs: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ()
    trusted_host_mode: str = "shadow"
    trusted_rp_origins: tuple[str, ...] = ()
    allowed_return_origins: tuple[str, ...] = ()
    auth_audience: str = ""
    challenge_v2_mode: str = "shadow"
    autoapprove_enabled: bool = False
    approved_ticket_retention_seconds: int = 86400
    audit_retention_seconds: int = 2592000

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
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
            wallet_policy=_env("KBEAM_AUTH_WALLET_POLICY", "allowlist").lower(),
            store_backend=_env("KBEAM_AUTH_STORE_BACKEND", "sqlite").lower(),
            sqlite_path=_env("KBEAM_AUTH_SQLITE_PATH", "./var/kbeam-auth-gateway.sqlite3"),
            postgres_dsn=_env("KBEAM_AUTH_POSTGRES_DSN", ""),
            admin_token=_env("KBEAM_AUTH_ADMIN_TOKEN", ""),
            max_pending_tickets=_env_int("KBEAM_AUTH_MAX_PENDING_TICKETS", 1000),
            rate_limit_window_seconds=_env_int("KBEAM_AUTH_RATE_LIMIT_WINDOW_SECONDS", 60),
            rate_limit_device_login=_env_int("KBEAM_AUTH_RATE_LIMIT_DEVICE_LOGIN", 20),
            rate_limit_ticket_poll=_env_int("KBEAM_AUTH_RATE_LIMIT_TICKET_POLL", 120),
            rate_limit_ticket_events=_env_int("KBEAM_AUTH_RATE_LIMIT_TICKET_EVENTS", 30),
            rate_limit_challenge=_env_int("KBEAM_AUTH_RATE_LIMIT_CHALLENGE", 60),
            rate_limit_approve=_env_int("KBEAM_AUTH_RATE_LIMIT_APPROVE", 60),
            rate_limit_admin=_env_int("KBEAM_AUTH_RATE_LIMIT_ADMIN", 120),
            trusted_proxy_cidrs=_env_csv("KBEAM_AUTH_TRUSTED_PROXY_CIDRS", ""),
            trusted_hosts=_env_csv("KBEAM_AUTH_TRUSTED_HOSTS", ""),
            trusted_host_mode=_env("KBEAM_AUTH_TRUSTED_HOST_MODE", "shadow").lower(),
            trusted_rp_origins=_env_csv("KBEAM_AUTH_TRUSTED_RP_ORIGINS", ""),
            allowed_return_origins=_env_csv("KBEAM_AUTH_ALLOWED_RETURN_ORIGINS", ""),
            auth_audience=_env("KBEAM_AUTH_AUDIENCE", ""),
            challenge_v2_mode=_env("KBEAM_AUTH_CHALLENGE_V2_MODE", "shadow").lower(),
            autoapprove_enabled=_env_bool("KBEAM_AUTH_AUTOAPPROVE_ENABLED", False),
            approved_ticket_retention_seconds=_env_int(
                "KBEAM_AUTH_APPROVED_TICKET_RETENTION_SECONDS", 86400
            ),
            audit_retention_seconds=_env_int("KBEAM_AUTH_AUDIT_RETENTION_SECONDS", 2592000),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        parsed_public_url = urlparse(self.public_base_url)
        public_origin_valid = True
        try:
            normalize_public_origin(self.public_base_url)
        except ValueError:
            public_origin_valid = False
            errors.append("KBEAM_AUTH_PUBLIC_BASE_URL must be an absolute URL")
        if (
            public_origin_valid
            and parsed_public_url.scheme != "https"
            and parsed_public_url.hostname not in {"127.0.0.1", "::1", "localhost"}
        ):
            errors.append("KBEAM_AUTH_PUBLIC_BASE_URL must use HTTPS outside localhost")
        if parsed_public_url.scheme == "https" and not self.secure_cookies:
            errors.append("KBEAM_AUTH_SECURE_COOKIES must be true for an HTTPS public URL")
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
        if self.wallet_policy not in {"open", "allowlist"}:
            errors.append("KBEAM_AUTH_WALLET_POLICY must be open or allowlist")
        if self.store_backend not in {"memory", "sqlite", "postgres"}:
            errors.append("KBEAM_AUTH_STORE_BACKEND must be memory, sqlite, or postgres")
        if self.store_backend == "sqlite" and not self.sqlite_path:
            errors.append("KBEAM_AUTH_SQLITE_PATH is required when KBEAM_AUTH_STORE_BACKEND=sqlite")
        if self.store_backend == "postgres" and not self.postgres_dsn:
            errors.append("KBEAM_AUTH_POSTGRES_DSN is required when KBEAM_AUTH_STORE_BACKEND=postgres")
        if self.max_pending_tickets < 1:
            errors.append("KBEAM_AUTH_MAX_PENDING_TICKETS must be at least 1")
        if self.rate_limit_window_seconds < 1:
            errors.append("KBEAM_AUTH_RATE_LIMIT_WINDOW_SECONDS must be at least 1")
        for field_name, value in (
            ("KBEAM_AUTH_RATE_LIMIT_DEVICE_LOGIN", self.rate_limit_device_login),
            ("KBEAM_AUTH_RATE_LIMIT_TICKET_POLL", self.rate_limit_ticket_poll),
            ("KBEAM_AUTH_RATE_LIMIT_TICKET_EVENTS", self.rate_limit_ticket_events),
            ("KBEAM_AUTH_RATE_LIMIT_CHALLENGE", self.rate_limit_challenge),
            ("KBEAM_AUTH_RATE_LIMIT_APPROVE", self.rate_limit_approve),
            ("KBEAM_AUTH_RATE_LIMIT_ADMIN", self.rate_limit_admin),
        ):
            if value < 1:
                errors.append(f"{field_name} must be at least 1")
        for field_name, values in (
            ("KBEAM_AUTH_TRUSTED_RP_ORIGINS", self.trusted_rp_origins),
            ("KBEAM_AUTH_ALLOWED_RETURN_ORIGINS", self.allowed_return_origins),
        ):
            for value in values:
                parsed = urlparse(value)
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                    or parsed.path not in {"", "/"}
                ):
                    errors.append(f"{field_name} entries must be HTTPS origins")
        for value in self.trusted_proxy_cidrs:
            try:
                network = ip_network(value, strict=False)
                if network.prefixlen == 0:
                    errors.append("KBEAM_AUTH_TRUSTED_PROXY_CIDRS must not trust the entire Internet")
            except ValueError:
                errors.append("KBEAM_AUTH_TRUSTED_PROXY_CIDRS entries must be IP networks")
        for value in self.trusted_hosts:
            try:
                normalize_host_authority(value)
            except ValueError:
                errors.append(
                    "KBEAM_AUTH_TRUSTED_HOSTS entries must be exact host authorities"
                )
        if self.trusted_host_mode not in {"shadow", "enforce"}:
            errors.append("KBEAM_AUTH_TRUSTED_HOST_MODE must be shadow or enforce")
        if self.challenge_v2_mode not in {"off", "shadow", "dual"}:
            errors.append("KBEAM_AUTH_CHALLENGE_V2_MODE must be off, shadow, or dual")
        if self.approved_ticket_retention_seconds < 0:
            errors.append("KBEAM_AUTH_APPROVED_TICKET_RETENTION_SECONDS must not be negative")
        if self.audit_retention_seconds < 60:
            errors.append("KBEAM_AUTH_AUDIT_RETENTION_SECONDS must be at least 60")
        return errors
