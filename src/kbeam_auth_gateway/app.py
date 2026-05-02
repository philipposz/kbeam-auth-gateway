from __future__ import annotations

import html
from http import HTTPStatus
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from .config import Settings
from .models import (
    ApproveRequest,
    ApproveResponse,
    ChallengeCreateRequest,
    ChallengeCreateResponse,
    DeviceLoginCreateResponse,
    SessionResponse,
    TicketPollResponse,
)
from .protocol import build_challenge_message
from .qr import qr_svg_for_url
from .store import InMemoryStore, new_id, new_token
from .time import isoformat_utc, utc_after, utc_now
from .verifier import SignatureVerificationError, verify_signature

STATIC_DIR = Path(__file__).parent / "static"


def _public_ticket(ticket) -> dict:
    return {
        "ticketId": ticket.ticketId,
        "status": ticket.status,
        "approveURL": ticket.approveURL,
        "qrSvg": ticket.qrSvg,
        "issuedAt": isoformat_utc(ticket.issuedAt),
        "expiresAt": isoformat_utc(ticket.expiresAt),
    }


def _session_view(session) -> dict:
    return {
        "sessionId": session.sessionId,
        "address": session.address,
        "network": session.network,
        "publicKey": session.publicKey,
        "issuedAt": isoformat_utc(session.issuedAt),
        "expiresAt": isoformat_utc(session.expiresAt),
        "challengeId": session.challengeId,
    }


def _challenge_view(challenge) -> dict:
    return {
        "challengeId": challenge.challengeId,
        "address": challenge.address,
        "network": challenge.network,
        "nonce": challenge.nonce,
        "issuedAt": isoformat_utc(challenge.issuedAt),
        "expiresAt": isoformat_utc(challenge.expiresAt),
        "origin": challenge.origin,
        "message": challenge.message,
    }


def _error(status: int, code: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"ok": False, "error": code})


def _render_scan_page(*, ticket_id: str, approve_token: str, status: str, expires_at: str) -> str:
    safe_ticket_id = html.escape(ticket_id)
    safe_approve_token = html.escape(approve_token)
    safe_status = html.escape(status)
    safe_expires_at = html.escape(expires_at)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KBeam Login Request</title>
    <style>
      :root {{
        color-scheme: light dark;
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f7f8fa;
        color: #20242c;
      }}
      body {{
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
      }}
      main {{
        width: min(560px, 100%);
        background: #ffffff;
        border: 1px solid #d9dee7;
        border-radius: 8px;
        padding: 22px;
      }}
      h1 {{
        font-size: 24px;
        margin: 0 0 12px;
        letter-spacing: 0;
      }}
      p {{
        line-height: 1.5;
      }}
      dl {{
        display: grid;
        grid-template-columns: 110px 1fr;
        gap: 8px 14px;
      }}
      dt {{
        font-weight: 700;
      }}
      dd {{
        margin: 0;
        overflow-wrap: anywhere;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }}
      @media (prefers-color-scheme: dark) {{
        :root {{
          background: #11151b;
          color: #eef2f8;
        }}
        main {{
          background: #171d25;
          border-color: #313b4b;
        }}
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>KBeam Login Request</h1>
      <p>This QR code is valid. Open it with a compatible KBeam wallet to approve
      the login request. A normal browser can only display this status page.</p>
      <dl>
        <dt>Ticket</dt>
        <dd>{safe_ticket_id}</dd>
        <dt>Status</dt>
        <dd>{safe_status}</dd>
        <dt>Expires</dt>
        <dd>{safe_expires_at}</dd>
        <dt>Token</dt>
        <dd>{safe_approve_token}</dd>
      </dl>
    </main>
  </body>
</html>"""


def create_app(settings: Settings | None = None, store: InMemoryStore | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or InMemoryStore()

    app = FastAPI(
        title="KBeam Auth Gateway",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.settings = settings
    app.state.store = store

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_request, exc: HTTPException):
        if isinstance(exc.detail, dict):
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={"ok": False, "error": str(exc.detail)},
        )

    @app.get("/health")
    @app.get("/api/health")
    def health():
        errors = settings.validate()
        return {
            "ok": not errors,
            "serverTime": isoformat_utc(utc_now()),
            "config": {
                "ok": not errors,
                "errorCount": len(errors),
                "errors": errors,
            },
        }

    @app.get("/", response_class=HTMLResponse)
    @app.get("/demo", response_class=HTMLResponse)
    def demo_page():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    @app.post(
        "/api/auth/device-login",
        status_code=HTTPStatus.CREATED,
        response_model=DeviceLoginCreateResponse,
    )
    def create_device_login():
        from .models import TicketRecord

        store.purge_expired()
        issued_at = utc_now()
        expires_at = utc_after(settings.ticket_ttl_seconds)
        ticket_id = new_id("ticket")
        poll_token = new_token()
        approve_token = new_token()
        approve_url = (
            f"{settings.public_base_url}/api/auth/device-login/{ticket_id}/challenge?"
            + urlencode({"approveToken": approve_token})
        )
        ticket = TicketRecord(
            ticketId=ticket_id,
            pollToken=poll_token,
            approveToken=approve_token,
            approveURL=approve_url,
            qrSvg=qr_svg_for_url(approve_url),
            status="pending",
            issuedAt=issued_at,
            expiresAt=expires_at,
        )
        with store.lock:
            store.tickets[ticket.ticketId] = ticket
        payload = _public_ticket(ticket)
        payload["pollToken"] = poll_token
        return {"ok": True, "deviceLogin": payload}

    @app.get("/api/auth/device-login/{ticket_id}", response_model=TicketPollResponse)
    def poll_device_login(
        ticket_id: str,
        response: Response,
        poll_token: Annotated[str, Query(alias="pollToken")],
    ):
        store.purge_expired()
        with store.lock:
            ticket = store.tickets.get(ticket_id)
            if not ticket:
                raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
            if ticket.pollToken != poll_token:
                raise _error(HTTPStatus.FORBIDDEN, "device_login_poll_forbidden")
            payload = {"ok": True, "deviceLogin": _public_ticket(ticket), "session": None}
            if ticket.status == "approved" and ticket.sessionId:
                session = store.sessions.get(ticket.sessionId)
                if session:
                    response.set_cookie(
                        settings.cookie_name,
                        session.sessionId,
                        max_age=settings.session_ttl_seconds,
                        httponly=True,
                        secure=settings.secure_cookies,
                        samesite="lax",
                        domain=settings.cookie_domain or None,
                    )
                    payload["session"] = _session_view(session)
            return payload

    @app.get("/api/auth/device-login/{ticket_id}/challenge", response_class=HTMLResponse)
    def challenge_scan_page(
        ticket_id: str,
        approve_token: Annotated[str, Query(alias="approveToken")],
    ):
        store.purge_expired()
        with store.lock:
            ticket = store.tickets.get(ticket_id)
            if not ticket:
                raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
            if ticket.approveToken != approve_token:
                raise _error(HTTPStatus.FORBIDDEN, "device_login_approve_forbidden")
            return _render_scan_page(
                ticket_id=ticket.ticketId,
                approve_token=approve_token,
                status=ticket.status,
                expires_at=isoformat_utc(ticket.expiresAt),
            )

    @app.post(
        "/api/auth/device-login/{ticket_id}/challenge",
        status_code=HTTPStatus.CREATED,
        response_model=ChallengeCreateResponse,
    )
    def create_challenge(ticket_id: str, request: ChallengeCreateRequest):
        from .models import ChallengeRecord

        store.purge_expired()
        with store.lock:
            ticket = store.tickets.get(ticket_id)
            if not ticket:
                raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
            if ticket.approveToken != request.approveToken:
                raise _error(HTTPStatus.FORBIDDEN, "device_login_approve_forbidden")
            if ticket.status != "pending":
                raise _error(HTTPStatus.CONFLICT, "device_login_ticket_not_pending")

            address = request.address.strip().lower()
            issued_at = utc_now()
            expires_at = utc_after(settings.challenge_ttl_seconds)
            challenge_id = new_id("challenge")
            nonce = new_token()
            origin = request.origin or settings.public_base_url
            challenge = ChallengeRecord(
                challengeId=challenge_id,
                ticketId=ticket.ticketId,
                address=address,
                network=request.network or settings.signer_network,
                nonce=nonce,
                issuedAt=issued_at,
                expiresAt=expires_at,
                origin=origin,
                message=build_challenge_message(
                    settings=settings,
                    address=address,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    ticket_id=ticket.ticketId,
                    origin=origin,
                ),
            )
            if ticket.challengeId:
                store.challenges.pop(ticket.challengeId, None)
            store.challenges[challenge.challengeId] = challenge
            ticket.challengeId = challenge.challengeId
            store.tickets[ticket.ticketId] = ticket

        return {
            "ok": True,
            "challenge": _challenge_view(challenge),
            "deviceLogin": _public_ticket(ticket),
        }

    @app.post(
        "/api/auth/device-login/{ticket_id}/approve",
        response_model=ApproveResponse,
    )
    def approve_device_login(ticket_id: str, request: ApproveRequest):
        from .models import SessionRecord

        store.purge_expired()
        with store.lock:
            ticket = store.tickets.get(ticket_id)
            if not ticket:
                raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
            if ticket.status != "pending":
                raise _error(HTTPStatus.CONFLICT, "device_login_ticket_not_pending")
            if ticket.challengeId != request.challengeId:
                raise _error(HTTPStatus.BAD_REQUEST, "device_login_challenge_mismatch")
            challenge = store.challenges.get(request.challengeId)
            if not challenge:
                raise _error(HTTPStatus.NOT_FOUND, "auth_challenge_not_found")
            if challenge.expiresAt <= utc_now():
                store.challenges.pop(challenge.challengeId, None)
                raise _error(HTTPStatus.GONE, "auth_challenge_expired")
            if settings.allowed_wallets and challenge.address.lower() not in settings.allowed_wallets:
                raise _error(HTTPStatus.FORBIDDEN, "auth_wallet_not_allowed")
            try:
                signature_verification = verify_signature(
                    settings=settings,
                    challenge=challenge,
                    address=request.address,
                    signature=request.signature,
                    public_key=request.publicKey,
                )
            except SignatureVerificationError as exc:
                raise _error(exc.status_code, exc.code) from exc

            issued_at = utc_now()
            session = SessionRecord(
                sessionId=new_id("session"),
                address=challenge.address,
                network=challenge.network,
                publicKey=signature_verification.public_key,
                issuedAt=issued_at,
                expiresAt=utc_after(settings.session_ttl_seconds),
                challengeId=challenge.challengeId,
            )
            store.sessions[session.sessionId] = session
            ticket.status = "approved"
            ticket.sessionId = session.sessionId
            store.tickets[ticket.ticketId] = ticket
            store.challenges.pop(challenge.challengeId, None)

        return {
            "ok": True,
            "deviceLogin": _public_ticket(ticket),
            "session": _session_view(session),
            "challenge": _challenge_view(challenge),
            "signature": signature_verification.as_public_dict(),
        }

    def current_session_id(request: Request) -> str | None:
        return request.cookies.get(settings.cookie_name)

    @app.get("/api/auth/session", response_model=SessionResponse)
    def get_session(request: Request):
        store.purge_expired()
        session_id = current_session_id(request)
        if not session_id:
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        session = store.sessions.get(session_id)
        if not session:
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        return {"ok": True, "session": _session_view(session)}

    @app.get("/api/auth/validate", status_code=HTTPStatus.NO_CONTENT)
    def validate_session(request: Request):
        store.purge_expired()
        session_id = current_session_id(request)
        if not session_id or session_id not in store.sessions:
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        return Response(status_code=HTTPStatus.NO_CONTENT)

    @app.delete("/api/auth/sessions/current")
    def delete_current_session(
        request: Request,
        response: Response,
    ):
        session_id = current_session_id(request)
        if session_id:
            with store.lock:
                store.sessions.pop(session_id, None)
        response.delete_cookie(
            settings.cookie_name,
            domain=settings.cookie_domain or None,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )
        return {"ok": True}

    return app


app = create_app()
