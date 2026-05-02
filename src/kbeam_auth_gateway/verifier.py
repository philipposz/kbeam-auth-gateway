from __future__ import annotations

from dataclasses import dataclass
from binascii import Error as HexError
import hmac

from coincurve import PublicKeyXOnly

from .config import Settings
from .models import ChallengeRecord

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [
    0x98F2BC8E61,
    0x79B76D99E2,
    0xF33E5FB3C4,
    0xAE2EABE2A8,
    0x1E4F43E470,
]


@dataclass(frozen=True)
class SignatureVerification:
    verifier: str
    address: str
    network: str
    public_key: str

    def as_public_dict(self) -> dict:
        return {
            "ok": True,
            "verifier": self.verifier,
            "address": self.address,
            "network": self.network,
            "publicKey": self.public_key,
        }


class SignatureVerificationError(ValueError):
    def __init__(self, code: str, *, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def expected_demo_signature(challenge: ChallengeRecord) -> str:
    return f"demo:{challenge.challengeId}"


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, item in enumerate(GENERATOR):
            if ((top >> index) & 1) == 1:
                checksum ^= item
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [(byte & 0x1F) for byte in hrp.lower().encode("ascii")] + [0]


def _create_checksum(hrp: str, values: list[int]) -> list[int]:
    encoded = _hrp_expand(hrp) + values + [0] * 8
    value = _polymod(encoded) ^ 1
    return [(value >> (5 * (7 - index))) & 31 for index in range(8)]


def _convert_bits(data: bytes, from_bits: int, to_bits: int, *, pad: bool) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1

    for value in data:
        if value >> from_bits:
            raise SignatureVerificationError("invalid_bit_conversion_input")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)

    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits:
        raise SignatureVerificationError("invalid_trailing_bits")
    elif ((accumulator << (to_bits - bits)) & max_value) != 0:
        raise SignatureVerificationError("invalid_zero_padding")

    return result


def kaspa_address_from_xonly_public_key(public_key: bytes, network: str) -> str:
    if len(public_key) != 32:
        raise SignatureVerificationError("public_key_must_be_32_bytes")
    match network:
        case "mainnet":
            hrp = "kaspa"
        case "testnet":
            hrp = "kaspatest"
        case _:
            raise SignatureVerificationError("unsupported_network")

    values = _convert_bits(bytes([0]) + public_key, 8, 5, pad=True)
    all_values = values + _create_checksum(hrp, values)
    return f"{hrp}:{''.join(CHARSET[value] for value in all_values)}"


def _decode_hex(value: str, *, field_name: str, expected_length: int) -> bytes:
    try:
        decoded = bytes.fromhex(value.strip())
    except (ValueError, HexError) as exc:
        raise SignatureVerificationError(f"{field_name}_invalid_hex") from exc
    if len(decoded) != expected_length:
        raise SignatureVerificationError(f"{field_name}_invalid_length")
    return decoded


def _verify_native_signature(
    *,
    challenge: ChallengeRecord,
    address: str,
    signature: str,
    public_key: str | None,
) -> SignatureVerification:
    if not public_key or not public_key.strip():
        raise SignatureVerificationError("public_key_required")

    normalized_network = challenge.network.strip().lower()
    public_key_bytes = _decode_hex(public_key, field_name="public_key", expected_length=32)
    signature_bytes = _decode_hex(signature, field_name="signature", expected_length=64)
    derived_address = kaspa_address_from_xonly_public_key(public_key_bytes, normalized_network)
    if derived_address.lower() != address.strip().lower():
        raise SignatureVerificationError("address_does_not_match_public_key")

    try:
        verified = PublicKeyXOnly(public_key_bytes).verify(signature_bytes, challenge.message.encode("utf-8"))
    except ValueError as exc:
        raise SignatureVerificationError("auth_signature_invalid", status_code=403) from exc
    if not verified:
        raise SignatureVerificationError("auth_signature_invalid", status_code=403)

    return SignatureVerification(
        verifier="native",
        address=derived_address.lower(),
        network=normalized_network,
        public_key=public_key.strip().lower(),
    )


def verify_signature(
    *,
    settings: Settings,
    challenge: ChallengeRecord,
    address: str,
    signature: str,
    public_key: str | None,
) -> SignatureVerification:
    if challenge.address.lower() != address.strip().lower():
        raise SignatureVerificationError("auth_challenge_address_mismatch")
    if not signature or not signature.strip():
        raise SignatureVerificationError("signature_required")

    if settings.signature_verifier_mode == "disabled":
        return SignatureVerification(
            verifier="disabled",
            address=challenge.address.lower(),
            network=challenge.network.lower(),
            public_key=public_key or "unverified",
        )

    if settings.signature_verifier_mode == "demo":
        if hmac.compare_digest(signature, expected_demo_signature(challenge)):
            return SignatureVerification(
                verifier="demo",
                address=challenge.address.lower(),
                network=challenge.network.lower(),
                public_key=public_key or "demo-public-key",
            )
        raise SignatureVerificationError("auth_signature_invalid", status_code=403)

    return _verify_native_signature(
        challenge=challenge,
        address=address,
        signature=signature,
        public_key=public_key,
    )
