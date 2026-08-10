from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from coincurve import PrivateKey, keys
from fastapi import Request
from fastapi.testclient import TestClient

from kbeam_auth_gateway.app import _client_ip, _public_origin, create_app
from kbeam_auth_gateway.config import Settings
from kbeam_auth_gateway.models import ChallengeRecord, SessionRecord, TicketRecord
from kbeam_auth_gateway.protocol import build_challenge_message, build_challenge_message_v2
from kbeam_auth_gateway.store import (
    InMemoryStore,
    PostgresStore,
    SQLiteStore,
    new_id,
    new_token,
)
from kbeam_auth_gateway.time import utc_after, utc_now
from kbeam_auth_gateway.verifier import (
    expected_demo_signature,
    kaspa_address_from_xonly_public_key,
)


def _settings(
    *,
    allowed_wallets: tuple[str, ...],
    verifier_mode: str = "native",
    wallet_policy: str = "allowlist",
    admin_token: str = "",
) -> Settings:
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
        wallet_policy=wallet_policy,
        store_backend="memory",
        admin_token=admin_token,
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
    assert ticket["approveURL"].startswith("kbeam://pos-login?")
    assert "api=https%3A%2F%2Fauth.example.com%2Fapi" in ticket["approveURL"]
    assert ticket["webApproveURL"].startswith("https://auth.example.com/api/auth/device-login/")
    assert ticket["qrSvg"].startswith("<?xml")

    challenge_response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": address,
            "origin": "https://protected.example.com",
        },
    )
    assert challenge_response.status_code == 201
    challenge = challenge_response.json()["challenge"]
    assert "Protocol: kbeam-auth-v1" in challenge["message"]
    assert "Service: test-service" in challenge["message"]
    assert "Origin: https://protected.example.com" in challenge["message"]
    assert challenge["organizationSlug"] == "test-service"

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
    approved_payload = approve_response.json()
    assert approved_payload["signature"]["verifier"] == "native"
    assert approved_payload["session"]["organizationSlug"] == "test-service"
    assert approved_payload["session"]["lastSeenAt"]
    assert approved_payload["auth"]["sessionRuntimeActive"] is True

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
    assert "Success. Protected area unlocked." in response.text
    assert "logoutSuccess" in response.text
    assert "renderQrMessage" in response.text
    assert "qr.classList.add(statusClass)" in response.text
    assert "routePrefix" in response.text
    assert 'replace(/\\/+$/, "")' in response.text
    assert "appPath(`/api/auth/device-login/" in response.text
    assert "assets/kbeam-logo.png" in response.text
    assert "startDeviceLogin({ silent: true })" in response.text
    assert "createPanel" not in response.text
    assert "Check ticket" not in response.text
    assert "EventSource" in response.text
    assert "Ticket expired" in response.text
    assert "Unlock with KBeam" in response.text
    assert "Share on X" in response.text
    assert "https://x.com/kbeam_app?s=21" in response.text
    assert "appendDeviceLoginReturnTo" in response.text
    assert "visibilitychange" in response.text
    assert "Never log in again." in response.text
    assert "Use KBeam." in response.text


def test_kbeam_logo_asset_is_served():
    client = TestClient(create_app(settings=_settings(allowed_wallets=()), store=InMemoryStore()))

    response = client.get("/assets/kbeam-logo.png")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content.startswith(b"\x89PNG")


def test_qr_svg_has_white_background_and_scan_get_page():
    settings = _settings(allowed_wallets=(), verifier_mode="demo")
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    assert 'fill="#ffffff"' in ticket["qrSvg"]

    response = client.get(ticket["webApproveURL"].replace("https://auth.example.com", ""))

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
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
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

    poll_response = client.get(
        f"/api/auth/device-login/{ticket['ticketId']}",
        params={"pollToken": ticket["pollToken"]},
    )
    denied_ticket = poll_response.json()["deviceLogin"]
    assert denied_ticket["status"] == "denied"
    assert denied_ticket["failureReason"] == "auth_wallet_not_allowed"


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
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
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
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": "kaspa:example",
        },
    ).json()["challenge"]
    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": "kaspa:example",
            "signature": expected_demo_signature(store.get_challenge(challenge["challengeId"])),
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
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
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

    assert message == (
        "KBeam login\n"
        "Protocol: kbeam-auth-v1\n"
        "Service: test-service\n"
        "Service Name: Test Service\n"
        "Address: kaspa:example\n"
        "Nonce: nonce-123\n"
        "Issued At: 2026-05-02T12:00:00Z\n"
        "Expires At: 2026-05-02T12:05:00Z\n"
        "Ticket: ticket-123\n"
        "Origin: https://protected.example.com"
    )


def test_challenge_v2_message_is_byte_stable():
    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "auth_challenge_v2.json").read_text(
            encoding="utf-8"
        )
    )
    fields = vector["fields"]

    message = build_challenge_message_v2(
        address=fields["address"],
        nonce=fields["nonce"],
        issued_at=datetime.fromisoformat(fields["issuedAt"]),
        expires_at=datetime.fromisoformat(fields["expiresAt"]),
        ticket_id=fields["ticket"],
        api_origin=fields["apiOrigin"],
        relying_party=fields["relyingParty"],
        relying_party_origin=fields["relyingPartyOrigin"],
        audience=fields["audience"],
        return_origin=fields["returnOrigin"],
    )

    assert message == vector["message"]
    assert message.encode("utf-8").hex() == vector["utf8Hex"]
    assert hashlib.sha256(message.encode("utf-8")).hexdigest() == vector["sha256"]


def test_v2_requires_mobile_join_and_explicit_confirmation():
    private_key = _private_key()
    address = _address(private_key)
    settings = replace(
        _settings(allowed_wallets=(address,)),
        challenge_v2_mode="dual",
        trusted_rp_origins=("https://protected.example.com",),
        allowed_return_origins=("https://protected.example.com",),
        auth_audience="protected-area",
    )
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge_url = f"/api/auth/device-login/{ticket['ticketId']}/challenge"
    base_payload = {
        "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
        "address": address,
        "origin": "https://protected.example.com",
        "returnOrigin": "https://protected.example.com",
        "audience": "protected-area",
        "protocolVersion": "kbeam-auth-v2",
    }

    missing_join = client.post(challenge_url, json=base_payload)
    assert missing_join.status_code == 400
    assert missing_join.json()["error"] == "auth_mobile_join_required"

    challenge_response = client.post(challenge_url, json={**base_payload, "joinedByMobile": True})
    assert challenge_response.status_code == 201
    challenge = challenge_response.json()["challenge"]
    assert challenge["protocolVersion"] == "kbeam-auth-v2"
    assert challenge["apiOrigin"] == "https://auth.example.com"
    assert challenge["relyingParty"] == "test-service"
    assert "Relying Party Origin: https://protected.example.com" in challenge["message"]
    assert challenge["audience"] == "protected-area"
    assert challenge["returnOrigin"] == "https://protected.example.com"
    assert challenge["explicitConfirmationRequired"] is True

    approval = {
        "challengeId": challenge["challengeId"],
        "address": address,
        "signature": _sign_raw_schnorr(private_key, challenge["message"]),
        "publicKey": _xonly_public_key_hex(private_key),
    }
    missing_confirmation = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json=approval,
    )
    assert missing_confirmation.status_code == 400
    assert missing_confirmation.json()["error"] == "auth_explicit_confirmation_required"

    approved = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={**approval, "explicitConfirmation": True},
    )
    assert approved.status_code == 200


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"origin": "https://evil.example.com"}, "auth_origin_not_trusted"),
        ({"returnOrigin": "https://evil.example.com"}, "auth_return_origin_not_allowed"),
        ({"audience": "wrong-audience"}, "auth_audience_mismatch"),
    ],
)
def test_v2_rejects_wrong_origin_return_origin_and_audience(change, error):
    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        challenge_v2_mode="dual",
        trusted_rp_origins=("https://protected.example.com",),
        allowed_return_origins=("https://protected.example.com",),
        auth_audience="protected-area",
    )
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    payload = {
        "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
        "address": "kaspa:example",
        "origin": "https://protected.example.com",
        "returnOrigin": "https://protected.example.com",
        "audience": "protected-area",
        "protocolVersion": "kbeam-auth-v2",
        "joinedByMobile": True,
        **change,
    }

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json=payload,
    )

    assert response.status_code == 400
    assert response.json()["error"] == error


def test_v2_shadow_never_rejects_legacy_challenge():
    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        challenge_v2_mode="shadow",
    )
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": "kaspa:example",
            "origin": "http://untrusted.example.com",
            "protocolVersion": "kbeam-auth-v2",
        },
    )

    assert response.status_code == 201
    assert "Protocol: kbeam-auth-v1" in response.json()["challenge"]["message"]
    evaluations = [record for record in store.audit if record.event == "auth_challenge_v2_evaluate"]
    assert evaluations[-1].result == "shadow"
    assert evaluations[-1].details["reason"] == "auth_origin_invalid"


def test_shadow_telemetry_failure_never_rejects_request():
    class FailingShadowStore(InMemoryStore):
        def check_rate_limit(self, key: str, *, limit: int, window_seconds: int) -> bool:
            if key.startswith("host_policy_audit:"):
                return True
            return super().check_rate_limit(key, limit=limit, window_seconds=window_seconds)

        def add_audit(self, event: str, **kwargs) -> None:
            if event in {"untrusted_host", "auth_challenge_v1_origin_evaluate"}:
                raise RuntimeError("simulated shadow telemetry failure")
            super().add_audit(event, **kwargs)

    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        challenge_v2_mode="shadow",
        trusted_hosts=("auth.example.com",),
        trusted_host_mode="shadow",
    )
    store = FailingShadowStore()
    client = TestClient(create_app(settings=settings, store=store))

    assert client.get("/", headers={"host": "unexpected.example.com"}).status_code == 200
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": "kaspa:example",
        },
    )
    assert response.status_code == 201


def test_autoapprove_kill_switch_blocks_labeled_autoapproval():
    settings = _settings(allowed_wallets=("kaspa:example",), verifier_mode="demo")
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": "kaspa:example",
        },
    ).json()["challenge"]

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": "kaspa:example",
            "signature": expected_demo_signature(store.get_challenge(challenge["challengeId"])),
            "autoApprove": True,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "auth_autoapprove_disabled"


def test_forwarded_for_is_ignored_without_a_trusted_direct_proxy():
    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        rate_limit_device_login=1,
    )
    client = TestClient(
        create_app(settings=settings, store=InMemoryStore()),
        base_url="https://auth.example.com",
    )

    first = client.post("/api/auth/device-login", headers={"x-forwarded-for": "192.0.2.10"})
    second = client.post("/api/auth/device-login", headers={"x-forwarded-for": "192.0.2.11"})

    assert first.status_code == 201
    assert second.status_code == 429


def test_trusted_proxy_chain_uses_rightmost_untrusted_address():
    settings = replace(
        _settings(allowed_wallets=()),
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"x-forwarded-for", b"192.0.2.99, 198.51.100.8, 10.0.0.1"),
            ],
            "client": ("10.0.0.2", 443),
            "server": ("auth.example.com", 443),
            "scheme": "https",
        }
    )

    assert _client_ip(request, settings) == "198.51.100.8"


def test_trusted_host_enforcement_and_readiness_fail_closed():
    valid_settings = replace(
        _settings(allowed_wallets=()),
        secure_cookies=True,
        trusted_hosts=("auth.example.com",),
        trusted_host_mode="enforce",
    )
    app = create_app(settings=valid_settings, store=InMemoryStore())
    assert TestClient(app).get("/health").status_code == 400
    exact_client = TestClient(app, base_url="https://auth.example.com")
    assert exact_client.get("/ready").status_code == 200
    assert exact_client.get("/ready", headers={"host": "auth.example.com:8443"}).status_code == 400
    assert exact_client.get("/ready", headers={"host": "evil@auth.example.com"}).status_code == 400

    port_settings = replace(valid_settings, trusted_hosts=("auth.example.com:8443",))
    port_client = TestClient(
        create_app(settings=port_settings, store=InMemoryStore()),
        base_url="https://auth.example.com:8443",
    )
    assert port_client.get("/ready").status_code == 200

    invalid_settings = replace(valid_settings, public_base_url="http://auth.example.com")
    invalid_client = TestClient(
        create_app(settings=invalid_settings, store=InMemoryStore()),
        base_url="https://auth.example.com",
    )
    readiness = invalid_client.get("/ready")
    assert readiness.status_code == 503
    assert readiness.json()["config"]["ok"] is False


def test_public_base_path_keeps_links_but_v2_binds_authority_origin():
    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        public_base_url="https://auth.example.com/auth-gateway-test",
        challenge_v2_mode="dual",
        trusted_rp_origins=("https://protected.example.com",),
        allowed_return_origins=("https://protected.example.com",),
    )
    store = InMemoryStore()
    client = TestClient(
        create_app(settings=settings, store=store),
        base_url="https://auth.example.com",
    )
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    assert "api=https%3A%2F%2Fauth.example.com%2Fauth-gateway-test%2Fapi" in ticket["approveURL"]

    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": "kaspa:example",
            "origin": "https://protected.example.com",
            "returnOrigin": "https://protected.example.com",
            "protocolVersion": "kbeam-auth-v2",
            "joinedByMobile": True,
        },
    ).json()["challenge"]
    assert challenge["apiOrigin"] == "https://auth.example.com"


def test_public_origin_canonicalizes_default_ports_and_ipv6():
    settings = _settings(allowed_wallets=())
    assert _public_origin(replace(settings, public_base_url="https://auth.example.com:443/path")) == (
        "https://auth.example.com"
    )
    assert _public_origin(replace(settings, public_base_url="http://[::1]:80/path")) == "http://[::1]"


def test_retention_purges_old_approved_tickets_and_audit_records():
    settings = replace(
        _settings(allowed_wallets=()),
        approved_ticket_retention_seconds=0,
        audit_retention_seconds=60,
    )
    store = InMemoryStore()
    store.bootstrap(settings)
    old = utc_now() - timedelta(seconds=120)
    store.create_ticket(
        TicketRecord(
            ticketId="ticket_old",
            pollToken=new_token(),
            approveToken=new_token(),
            approveURL="kbeam://pos-login",
            qrSvg="",
            status="approved",
            issuedAt=old,
            expiresAt=old,
            challengeId="challenge_old",
            sessionId="session_old",
        )
    )
    store.add_audit("old_event")
    store.audit[-1].createdAt = old

    store.purge_expired()

    assert "ticket_old" not in store.tickets
    assert not store.audit


def test_sqlite_challenge_consumption_and_session_creation_are_atomic(tmp_path):
    settings = _settings(allowed_wallets=())
    store = SQLiteStore(str(tmp_path / "atomic.sqlite3"))
    store.bootstrap(settings)
    issued_at = utc_now()
    ticket = TicketRecord(
        ticketId="ticket_atomic",
        pollToken=new_token(),
        approveToken=new_token(),
        approveURL="kbeam://pos-login",
        qrSvg="",
        status="pending",
        issuedAt=issued_at,
        expiresAt=utc_after(300),
        challengeId="challenge_atomic",
    )
    challenge = ChallengeRecord(
        challengeId="challenge_atomic",
        ticketId=ticket.ticketId,
        address="kaspa:example",
        network="mainnet",
        nonce=new_token(),
        issuedAt=issued_at,
        expiresAt=utc_after(300),
        origin="https://auth.example.com",
        message="test",
    )
    store.create_ticket(ticket)
    store.create_challenge(challenge)

    first = SessionRecord(
        sessionId="session_first",
        address=challenge.address,
        network=challenge.network,
        publicKey="first",
        issuedAt=issued_at,
        expiresAt=utc_after(300),
        challengeId=challenge.challengeId,
    )
    second = first.model_copy(update={"sessionId": "session_second", "publicKey": "second"})

    assert store.consume_challenge_and_create_session(
        ticket_id=ticket.ticketId,
        challenge_id=challenge.challengeId,
        session=first,
    )
    assert not store.consume_challenge_and_create_session(
        ticket_id=ticket.ticketId,
        challenge_id=challenge.challengeId,
        session=second,
    )
    assert store.get_ticket(ticket.ticketId).sessionId == first.sessionId
    assert store.get_session(first.sessionId) is not None
    assert store.get_session(second.sessionId) is None
    assert store.get_challenge(challenge.challengeId) is None


def test_sqlite_rate_limit_is_shared_across_store_instances(tmp_path, monkeypatch):
    monkeypatch.setattr("kbeam_auth_gateway.store.time.time", lambda: 1_786_363_200.0)
    path = str(tmp_path / "shared-rate.sqlite3")
    first_worker = SQLiteStore(path)
    second_worker = SQLiteStore(path)

    assert first_worker.check_rate_limit("approve:192.0.2.10", limit=1, window_seconds=60)
    assert not second_worker.check_rate_limit("approve:192.0.2.10", limit=1, window_seconds=60)


def test_sqlite_rate_limit_remains_sliding_across_fixed_window_boundary(tmp_path, monkeypatch):
    now = [1_786_363_259.0]
    monkeypatch.setattr("kbeam_auth_gateway.store.time.time", lambda: now[0])
    path = str(tmp_path / "sliding-rate.sqlite3")
    first_worker = SQLiteStore(path)
    second_worker = SQLiteStore(path)
    key = "approve:192.0.2.20"

    assert first_worker.check_rate_limit(key, limit=2, window_seconds=60)
    assert second_worker.check_rate_limit(key, limit=2, window_seconds=60)
    now[0] = 1_786_363_261.0
    assert not first_worker.check_rate_limit(key, limit=2, window_seconds=60)
    now[0] = 1_786_363_320.0
    assert second_worker.check_rate_limit(key, limit=2, window_seconds=60)


def test_postgres_healthcheck_uses_the_store_transaction_lock():
    store = object.__new__(PostgresStore)
    store._lock = threading.RLock()
    entered = threading.Event()

    class HealthConnection:
        def healthcheck(self) -> bool:
            entered.set()
            return True

    store._conn = HealthConnection()
    with store.lock:
        worker = threading.Thread(target=store.healthcheck)
        worker.start()
        assert not entered.wait(0.05)
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert entered.is_set()


def test_sqlite_migration_keeps_legacy_challenges_readable(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        create table tickets (
            ticket_id text primary key,
            poll_token text not null,
            approve_token text not null,
            approve_url text not null,
            qr_svg text not null,
            status text not null,
            issued_at text not null,
            expires_at text not null,
            challenge_id text,
            session_id text
        );
        create table challenges (
            challenge_id text primary key,
            ticket_id text not null,
            address text not null,
            network text not null,
            nonce text not null,
            issued_at text not null,
            expires_at text not null,
            origin text not null,
            message text not null
        );
        insert into tickets values (
            'ticket_legacy', 'poll', 'approve', 'kbeam://pos-login', '', 'pending',
            '2026-08-10T12:00:00Z', '2099-08-10T12:05:00Z', 'challenge_legacy', null
        );
        insert into challenges values (
            'challenge_legacy', 'ticket_legacy', 'kaspa:example', 'mainnet', 'nonce',
            '2026-08-10T12:00:00Z', '2099-08-10T12:05:00Z',
            'https://protected.example.com', 'KBeam login'
        );
        """
    )
    connection.commit()
    connection.close()

    store = SQLiteStore(str(path))

    challenge = store.get_challenge("challenge_legacy")
    assert challenge is not None
    assert challenge.protocolVersion == "kbeam-auth-v1"
    assert challenge.joinedByMobile is False
    assert store.get_ticket("ticket_legacy").failureReason is None


def test_sse_ticket_events_emit_initial_status():
    settings = _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open")
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    ticket_record = store.get_ticket(ticket["ticketId"])
    session = SessionRecord(
        sessionId=new_id("session"),
        address="kaspa:example",
        network="mainnet",
        publicKey="demo-public-key",
        issuedAt=utc_now(),
        expiresAt=utc_after(300),
        challengeId="challenge_demo",
    )
    store.create_session(session)
    ticket_record.status = "approved"
    ticket_record.sessionId = session.sessionId
    store.save_ticket(ticket_record)

    with client.stream(
        "GET",
        f"/api/auth/device-login/{ticket['ticketId']}/events",
        params={"pollToken": ticket["pollToken"]},
    ) as response:
        assert response.status_code == 200
        first_chunk = next(response.iter_text())

    assert "event: status" in first_chunk
    assert ticket["ticketId"] in first_chunk
    assert "qrSvg" not in first_chunk
    assert "demo-public-key" in first_chunk


def test_rate_limit_blocks_excess_device_login_requests():
    settings = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        rate_limit_device_login=1,
    )
    client = TestClient(create_app(settings=settings, store=InMemoryStore()))

    assert client.post("/api/auth/device-login").status_code == 201
    blocked = client.post("/api/auth/device-login")

    assert blocked.status_code == 429
    assert blocked.json()["error"] == "rate_limit_exceeded"


def test_postgres_backend_requires_dsn():
    missing_dsn = replace(
        _settings(allowed_wallets=(), verifier_mode="demo", wallet_policy="open"),
        store_backend="postgres",
        postgres_dsn="",
    )
    assert "KBEAM_AUTH_POSTGRES_DSN is required" in "\n".join(missing_dsn.validate())

    configured = replace(missing_dsn, postgres_dsn="postgresql://example:example@localhost/example")
    assert "KBEAM_AUTH_POSTGRES_DSN is required" not in "\n".join(configured.validate())


def test_sqlite_wallet_admin_and_audit_log(tmp_path):
    private_key = _private_key()
    address = _address(private_key)
    settings = _settings(allowed_wallets=(), admin_token="secret-admin-token")
    store = SQLiteStore(str(tmp_path / "auth.sqlite3"))
    client = TestClient(create_app(settings=settings, store=store))

    assert client.get("/api/admin/wallets").status_code == 401

    headers = {"Authorization": "Bearer secret-admin-token"}
    created = client.post(
        "/api/admin/wallets",
        headers=headers,
        json={"address": address, "label": "Test Wallet", "role": "admin", "enabled": True},
    )
    assert created.status_code == 201
    assert created.json()["wallet"]["address"] == address

    listed = client.get("/api/admin/wallets", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["wallets"][0]["label"] == "Test Wallet"

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
            "address": address,
        },
    ).json()["challenge"]
    approved = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": address,
            "signature": _sign_raw_schnorr(private_key, challenge["message"]),
            "publicKey": _xonly_public_key_hex(private_key),
        },
    )
    assert approved.status_code == 200

    patched = client.patch(
        f"/api/admin/wallets/{address}",
        headers=headers,
        json={"enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["wallet"]["enabled"] is False

    audit = client.get("/api/admin/audit-log", headers=headers)
    assert audit.status_code == 200
    events = [item["event"] for item in audit.json()["auditLog"]]
    assert "admin_wallet_upsert" in events
    assert "device_login_approve" in events
