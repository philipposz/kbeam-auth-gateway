from __future__ import annotations

from coincurve import PrivateKey, keys
from fastapi.testclient import TestClient

from kbeam_auth_gateway.app import create_app
from kbeam_auth_gateway.config import Settings
from kbeam_auth_gateway.protocol import build_challenge_message
from kbeam_auth_gateway.store import InMemoryStore
from kbeam_auth_gateway.time import utc_now
from kbeam_auth_gateway.verifier import (
    expected_demo_signature,
    kaspa_address_from_xonly_public_key,
)


def _settings(*, allowed_wallets: tuple[str, ...], verifier_mode: str = "native") -> Settings:
    return Settings(
        bind="127.0.0.1:18090",
        public_base_url="https://auth.example.com",
        service_slug="test-service",
        service_name="Test Service",
        cookie_name="kbeam_auth_session",
        cookie_domain="",
        allowed_wallets=allowed_wallets,
        session_ttl_seconds=28800,
        challenge_ttl_seconds=300,
        ticket_ttl_seconds=300,
        secure_cookies=False,
        signer_network="mainnet",
        signature_verifier_mode=verifier_mode,
    )


def _private_key() -> PrivateKey:
    return PrivateKey.from_int(7)


def _xonly_public_key_hex(private_key: PrivateKey) -> str:
    return bytes(private_key.public_key_xonly.format()).hex()


def _address(private_key: PrivateKey, network: str = "mainnet") -> str:
    return kaspa_address_from_xonly_public_key(
        bytes(private_key.public_key_xonly.format()),
        network,
    )


def _sign_raw_schnorr(private_key: PrivateKey, message: str) -> str:
    keypair = keys.ffi.new("secp256k1_keypair *")
    created = keys.lib.secp256k1_keypair_create(
        private_key.context.ctx,
        keypair,
        private_key.secret,
    )
    assert created == 1
    signature = keys.ffi.new("unsigned char[64]")
    message_bytes = message.encode("utf-8")
    signed = keys.lib.secp256k1_schnorrsig_sign_custom(
        private_key.context.ctx,
        signature,
        message_bytes,
        len(message_bytes),
        keypair,
        keys.ffi.NULL,
    )
    assert signed == 1
    return bytes(keys.ffi.buffer(signature)).hex()


def test_device_login_flow_sets_and_validates_session_cookie():
    private_key = _private_key()
    address = _address(private_key)
    settings = _settings(allowed_wallets=(address,))
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    created = client.post("/api/auth/device-login")
    assert created.status_code == 201
    ticket = created.json()["deviceLogin"]
    assert ticket["status"] == "pending"
    assert ticket["qrSvg"].startswith("<?xml")

    challenge_response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": address,
            "origin": "https://protected.example.com",
        },
    )
    assert challenge_response.status_code == 201
    challenge = challenge_response.json()["challenge"]
    assert "Protocol: kbeam-auth-v1" in challenge["message"]
    assert "Service: test-service" in challenge["message"]
    assert "Origin: https://protected.example.com" in challenge["message"]

    approve_response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": address,
            "signature": _sign_raw_schnorr(private_key, challenge["message"]),
            "publicKey": _xonly_public_key_hex(private_key),
        },
    )
    assert approve_response.status_code == 200
    assert approve_response.json()["signature"]["verifier"] == "native"

    poll_response = client.get(
        f"/api/auth/device-login/{ticket['ticketId']}",
        params={"pollToken": ticket["pollToken"]},
    )
    assert poll_response.status_code == 200
    assert poll_response.json()["session"]["address"] == address
    assert "kbeam_auth_session" in client.cookies

    validate_response = client.get("/api/auth/validate")
    assert validate_response.status_code == 204

    session_response = client.get("/api/auth/session")
    assert session_response.status_code == 200
    assert session_response.json()["session"]["publicKey"] == _xonly_public_key_hex(private_key)


def test_demo_page_is_served():
    client = TestClient(create_app(settings=_settings(allowed_wallets=()), store=InMemoryStore()))

    response = client.get("/demo")

    assert response.status_code == 200
    assert "KBeam Auth Gateway Demo" in response.text
    assert "/api/auth/device-login" in response.text


def test_qr_svg_has_white_background_and_scan_get_page():
    settings = _settings(allowed_wallets=(), verifier_mode="demo")
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    assert 'fill="#ffffff"' in ticket["qrSvg"]

    response = client.get(ticket["approveURL"].replace("https://auth.example.com", ""))

    assert response.status_code == 200
    assert "KBeam Login Request" in response.text
    assert ticket["ticketId"] in response.text


def test_rejects_wallet_outside_allowlist():
    private_key = _private_key()
    address = _address(private_key)
    settings = _settings(allowed_wallets=("kaspa:allowed",))
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": address,
        },
    ).json()["challenge"]

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": address,
            "signature": _sign_raw_schnorr(private_key, challenge["message"]),
            "publicKey": _xonly_public_key_hex(private_key),
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "auth_wallet_not_allowed"


def test_ticket_can_only_be_approved_once():
    private_key = _private_key()
    address = _address(private_key)
    settings = _settings(allowed_wallets=(address,))
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": address,
        },
    ).json()["challenge"]
    payload = {
        "challengeId": challenge["challengeId"],
        "address": address,
        "signature": _sign_raw_schnorr(private_key, challenge["message"]),
        "publicKey": _xonly_public_key_hex(private_key),
    }

    assert (
        client.post(f"/api/auth/device-login/{ticket['ticketId']}/approve", json=payload).status_code
        == 200
    )
    second = client.post(f"/api/auth/device-login/{ticket['ticketId']}/approve", json=payload)

    assert second.status_code == 409
    assert second.json()["error"] == "device_login_ticket_not_pending"


def test_demo_signature_mode_remains_available_for_local_flow_tests():
    settings = _settings(allowed_wallets=("kaspa:example",), verifier_mode="demo")
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": "kaspa:example",
        },
    ).json()["challenge"]
    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": "kaspa:example",
            "signature": expected_demo_signature(store.challenges[challenge["challengeId"]]),
        },
    )

    assert response.status_code == 200
    assert response.json()["signature"]["verifier"] == "demo"


def test_native_verifier_rejects_tampered_message_signature():
    private_key = _private_key()
    address = _address(private_key)
    settings = _settings(allowed_wallets=(address,))
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": address,
        },
    ).json()["challenge"]

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": address,
            "signature": _sign_raw_schnorr(private_key, challenge["message"] + "\nTampered: yes"),
            "publicKey": _xonly_public_key_hex(private_key),
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "auth_signature_invalid"


def test_challenge_message_is_byte_stable():
    settings = _settings(allowed_wallets=())
    issued_at = utc_now().replace(year=2026, month=5, day=2, hour=12, minute=0, second=0, microsecond=0)
    expires_at = issued_at.replace(minute=5)

    message = build_challenge_message(
        settings=settings,
        address="kaspa:example",
        nonce="nonce-123",
        issued_at=issued_at,
        expires_at=expires_at,
        ticket_id="ticket-123",
        origin="https://protected.example.com",
    )

    assert message == "\n".join(
        [
            "KBeam login",
            "Protocol: kbeam-auth-v1",
            "Service: test-service",
            "Service Name: Test Service",
            "Address: kaspa:example",
            "Nonce: nonce-123",
            "Issued At: 2026-05-02T12:00:00Z",
            "Expires At: 2026-05-02T12:05:00Z",
            "Ticket: ticket-123",
            "Origin: https://protected.example.com",
        ]
    )
