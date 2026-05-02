from __future__ import annotations

from datetime import datetime

from .config import Settings
from .time import isoformat_utc

PROTOCOL_VERSION = "kbeam-auth-v1"


def build_challenge_message(
    *,
    settings: Settings,
    address: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    ticket_id: str,
    origin: str,
) -> str:
    return "\n".join(
        [
            "KBeam login",
            f"Protocol: {PROTOCOL_VERSION}",
            f"Service: {settings.service_slug}",
            f"Service Name: {settings.service_name}",
            f"Address: {address}",
            f"Nonce: {nonce}",
            f"Issued At: {isoformat_utc(issued_at)}",
            f"Expires At: {isoformat_utc(expires_at)}",
            f"Ticket: {ticket_id}",
            f"Origin: {origin}",
        ]
    )

