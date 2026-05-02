from __future__ import annotations

from fastapi.testclient import TestClient

from kbeam_auth_gateway.app import create_app
from kbeam_auth_gateway.config import Settings
from kbeam_auth_gateway.store import InMemoryStore
from kbeam_auth_gateway.verifier import expected_demo_signature


def test_device_login_flow_sets_and_validates_session_cookie():
    settings = Settings(
        bind="127.0.0.1:18090",
        public_base_url="https://auth.example.com",
        service_slug="test-service",
        service_name="Test Service",
        cookie_name="kbeam_auth_session",
        cookie_domain="",
        allowed_wallets=("kaspa:example",),
        session_ttl_seconds=28800,
        challenge_ttl_seconds=300,
        ticket_ttl_seconds=300,
        secure_cookies=False,
        signer_network="mainnet",
        signature_verifier_mode="demo",
    )
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
            "address": "kaspa:example",
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
            "address": "kaspa:example",
            "signature": expected_demo_signature(store.challenges[challenge["challengeId"]]),
            "publicKey": "demo-key",
        },
    )
    assert approve_response.status_code == 200

    poll_response = client.get(
        f"/api/auth/device-login/{ticket['ticketId']}",
        params={"pollToken": ticket["pollToken"]},
    )
    assert poll_response.status_code == 200
    assert poll_response.json()["session"]["address"] == "kaspa:example"
    assert "kbeam_auth_session" in client.cookies

    validate_response = client.get("/api/auth/validate")
    assert validate_response.status_code == 204

    session_response = client.get("/api/auth/session")
    assert session_response.status_code == 200
    assert session_response.json()["session"]["publicKey"] == "demo-key"


def test_rejects_wallet_outside_allowlist():
    settings = Settings(
        bind="127.0.0.1:18090",
        public_base_url="https://auth.example.com",
        service_slug="test-service",
        service_name="Test Service",
        cookie_name="kbeam_auth_session",
        cookie_domain="",
        allowed_wallets=("kaspa:allowed",),
        session_ttl_seconds=28800,
        challenge_ttl_seconds=300,
        ticket_ttl_seconds=300,
        secure_cookies=False,
        signer_network="mainnet",
        signature_verifier_mode="demo",
    )
    store = InMemoryStore()
    client = TestClient(create_app(settings=settings, store=store))

    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    challenge = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/challenge",
        json={
            "approveToken": store.tickets[ticket["ticketId"]].approveToken,
            "address": "kaspa:not-allowed",
        },
    ).json()["challenge"]

    response = client.post(
        f"/api/auth/device-login/{ticket['ticketId']}/approve",
        json={
            "challengeId": challenge["challengeId"],
            "address": "kaspa:not-allowed",
            "signature": expected_demo_signature(store.challenges[challenge["challengeId"]]),
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "auth_wallet_not_allowed"


def test_ticket_can_only_be_approved_once():
    settings = Settings(
        bind="127.0.0.1:18090",
        public_base_url="https://auth.example.com",
        service_slug="test-service",
        service_name="Test Service",
        cookie_name="kbeam_auth_session",
        cookie_domain="",
        allowed_wallets=("kaspa:example",),
        session_ttl_seconds=28800,
        challenge_ttl_seconds=300,
        ticket_ttl_seconds=300,
        secure_cookies=False,
        signer_network="mainnet",
        signature_verifier_mode="demo",
    )
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
    payload = {
        "challengeId": challenge["challengeId"],
        "address": "kaspa:example",
        "signature": expected_demo_signature(store.challenges[challenge["challengeId"]]),
    }

    assert client.post(f"/api/auth/device-login/{ticket['ticketId']}/approve", json=payload).status_code == 200
    second = client.post(f"/api/auth/device-login/{ticket['ticketId']}/approve", json=payload)

    assert second.status_code == 409
    assert second.json()["error"] == "device_login_ticket_not_pending"

