from __future__ import annotations

import hmac

from .config import Settings
from .models import ChallengeRecord


def expected_demo_signature(challenge: ChallengeRecord) -> str:
    return f"demo:{challenge.challengeId}"


def verify_signature(
    *,
    settings: Settings,
    challenge: ChallengeRecord,
    address: str,
    signature: str,
    public_key: str | None,
) -> str:
    if challenge.address.lower() != address.strip().lower():
        raise ValueError("auth_challenge_address_mismatch")

    if settings.signature_verifier_mode == "disabled":
        return public_key or "unverified"

    if hmac.compare_digest(signature, expected_demo_signature(challenge)):
        return public_key or "demo-public-key"

    raise ValueError("auth_signature_invalid")

