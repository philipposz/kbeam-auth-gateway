from __future__ import annotations

import asyncio
import html
import json
import logging
from http import HTTPStatus
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from .config import Settings, normalize_host_authority, normalize_public_origin
from .models import (
    ApproveRequest,
    ApproveResponse,
    ChallengeCreateRequest,
    ChallengeCreateResponse,
    DeviceLoginCreateResponse,
    SessionResponse,
    TicketPollResponse,
    WalletCreateRequest,
    WalletUpdateRequest,
)
from .protocol import (
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_V2,
    build_challenge_message,
    build_challenge_message_v2,
)
from .qr import qr_svg_for_url
from .store import AuthStore, create_store, new_id, new_token
from .time import isoformat_utc, utc_after, utc_now
from .verifier import SignatureVerificationError, verify_signature

STATIC_DIR = Path(__file__).parent / "static"
LOGGER = logging.getLogger(__name__)


def _normalize_origin(value: str, *, require_https: bool = True) -> str:
    parsed = urlparse(value.strip())
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.scheme not in {"https", "http"}
        or (require_https and parsed.scheme != "https")
    ):
        raise ValueError("invalid_origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_origin") from exc
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    port_suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme.lower()}://{rendered_host}{port_suffix}"


def _public_origin(settings: Settings) -> str:
    return normalize_public_origin(settings.public_base_url)


def _allowed_origins(values: tuple[str, ...], *, fallback: str) -> set[str]:
    configured = values or (fallback,)
    origins: set[str] = set()
    for value in configured:
        try:
            origins.add(_normalize_origin(value))
        except ValueError:
            continue
    return origins


def _request_authority(request: Request) -> str:
    raw_host = request.headers.get("host", "")
    try:
        return normalize_host_authority(raw_host)
    except ValueError:
        return ""


def _client_ip(request: Request, settings: Settings) -> str:
    direct = request.client.host if request.client else ""
    try:
        direct_ip = ip_address(direct)
    except ValueError:
        return direct or "unknown"
    trusted_networks = []
    for network in settings.trusted_proxy_cidrs:
        try:
            trusted_networks.append(ip_network(network, strict=False))
        except ValueError:
            continue
    if any(direct_ip in network for network in trusted_networks):
        forwarded_chain = request.headers.get("x-forwarded-for", "")
        forwarded_parts = [item.strip() for item in forwarded_chain.split(",") if item.strip()]
        if len(forwarded_parts) > 32:
            return str(direct_ip)
        forwarded_addresses = []
        try:
            forwarded_addresses = [ip_address(item) for item in forwarded_parts]
        except ValueError:
            return str(direct_ip)
        for candidate in reversed([*forwarded_addresses, direct_ip]):
            if any(candidate in network for network in trusted_networks):
                continue
            return str(candidate)
        if forwarded_addresses:
            return str(forwarded_addresses[0])
    return str(direct_ip)


def _api_base_url(settings: Settings) -> str:
    return f"{settings.public_base_url}/api"


def _kbeam_approve_url(settings: Settings, *, ticket_id: str, approve_token: str) -> str:
    return "kbeam://pos-login?" + urlencode(
        {
            "t": ticket_id,
            "a": approve_token,
            "api": _api_base_url(settings),
            "service": settings.service_slug,
        }
    )


def _web_approve_url(ticket) -> str:
    parsed = urlparse(ticket.approveURL)
    if parsed.scheme in {"http", "https"}:
        return ticket.approveURL
    query = dict(parse_qsl(parsed.query))
    api_base = query.get("api", "").rstrip("/")
    base = api_base.removesuffix("/api")
    approve_token = query.get("a") or ticket.approveToken
    if base:
        return (
            f"{base}/api/auth/device-login/{ticket.ticketId}/challenge?"
            + urlencode({"approveToken": approve_token})
        )
    return ""


def _public_ticket(ticket) -> dict:
    payload = {
        "ticketId": ticket.ticketId,
        "status": ticket.status,
        "approveURL": ticket.approveURL,
        "webApproveURL": _web_approve_url(ticket),
        "qrSvg": ticket.qrSvg,
        "issuedAt": isoformat_utc(ticket.issuedAt),
        "expiresAt": isoformat_utc(ticket.expiresAt),
    }
    if getattr(ticket, "failureReason", None):
        payload["failureReason"] = ticket.failureReason
    return payload


def _ticket_status_view(ticket) -> dict:
    return {
        "ticketId": ticket.ticketId,
        "status": ticket.status,
        "issuedAt": isoformat_utc(ticket.issuedAt),
        "expiresAt": isoformat_utc(ticket.expiresAt),
    }


def _session_view(session, *, organization_slug: str = "default") -> dict:
    return {
        "sessionId": session.sessionId,
        "address": session.address,
        "network": session.network,
        "organizationSlug": organization_slug,
        "publicKey": session.publicKey,
        "issuedAt": isoformat_utc(session.issuedAt),
        "expiresAt": isoformat_utc(session.expiresAt),
        "lastSeenAt": isoformat_utc(utc_now()),
        "challengeId": session.challengeId,
    }


def _challenge_view(challenge, *, organization_slug: str = "default") -> dict:
    payload = {
        "challengeId": challenge.challengeId,
        "address": challenge.address,
        "network": challenge.network,
        "nonce": challenge.nonce,
        "issuedAt": isoformat_utc(challenge.issuedAt),
        "expiresAt": isoformat_utc(challenge.expiresAt),
        "origin": challenge.origin,
        "message": challenge.message,
        "organizationSlug": organization_slug,
    }
    if challenge.protocolVersion == PROTOCOL_VERSION_V2:
        payload.update(
            {
                "protocolVersion": challenge.protocolVersion,
                "apiOrigin": challenge.apiOrigin,
                "relyingParty": challenge.relyingParty,
                "audience": challenge.audience,
                "returnOrigin": challenge.returnOrigin,
                "joinedByMobile": challenge.joinedByMobile,
                "explicitConfirmationRequired": True,
            }
        )
    return payload


def _wallet_view(wallet) -> dict:
    return {
        "address": wallet.address,
        "label": wallet.label,
        "role": wallet.role,
        "enabled": wallet.enabled,
        "createdAt": isoformat_utc(wallet.createdAt),
        "updatedAt": isoformat_utc(wallet.updatedAt),
    }


def _audit_view(record) -> dict:
    return {
        "id": record.id,
        "event": record.event,
        "address": record.address,
        "result": record.result,
        "details": record.details,
        "createdAt": isoformat_utc(record.createdAt),
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


def create_app(settings: Settings | None = None, store: AuthStore | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or create_store(settings)
    store.bootstrap(settings)

    app = FastAPI(
        title="KBeam Auth Gateway",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.settings = settings
    app.state.store = store

    configured_public_origin = _public_origin(settings)
    trusted_rp_origins = _allowed_origins(
        settings.trusted_rp_origins,
        fallback=configured_public_origin,
    )
    allowed_return_origins = _allowed_origins(
        settings.allowed_return_origins,
        fallback=configured_public_origin,
    )
    expected_audience = settings.auth_audience or settings.service_slug
    configured_authority = normalize_host_authority(urlparse(configured_public_origin).netloc)
    trusted_hosts: set[str] = set()
    for item in settings.trusted_hosts:
        try:
            trusted_hosts.add(normalize_host_authority(item))
        except ValueError:
            continue
    if not trusted_hosts:
        trusted_hosts = {configured_authority}

    def shadow_audit(
        event: str,
        *,
        address: str | None = None,
        result: str = "ok",
        details: dict | None = None,
    ) -> None:
        """Record observation-only telemetry without changing request behavior."""

        try:
            store.add_audit(event, address=address, result=result, details=details)
        except Exception as exc:  # noqa: BLE001 - shadow must survive any store failure
            LOGGER.warning(
                "Auth shadow audit unavailable (error_type=%s)",
                type(exc).__name__,
            )

    def shadow_audit_allowed(key: str) -> bool:
        try:
            return store.check_rate_limit(
                key,
                limit=1,
                window_seconds=settings.rate_limit_window_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - shadow must survive any store failure
            LOGGER.warning(
                "Auth shadow audit limiter unavailable (error_type=%s)",
                type(exc).__name__,
            )
            return False

    def client_key(request: Request, scope: str) -> str:
        return f"{scope}:{_client_ip(request, settings)}"

    @app.middleware("http")
    async def trusted_host_guard(request: Request, call_next):
        request_host = _request_authority(request)
        if request_host not in trusted_hosts:
            details = {"path": request.url.path, "mode": settings.trusted_host_mode}
            should_audit = shadow_audit_allowed(
                f"host_policy_audit:{_client_ip(request, settings)}"
            )
            if settings.trusted_host_mode == "enforce":
                if should_audit:
                    shadow_audit("untrusted_host", result="blocked", details=details)
                return JSONResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content={"ok": False, "error": "auth_untrusted_host"},
                )
            if should_audit:
                shadow_audit("untrusted_host", result="shadow", details=details)
        return await call_next(request)

    def require_rate(request: Request, scope: str, limit: int) -> None:
        if not store.check_rate_limit(
            client_key(request, scope),
            limit=limit,
            window_seconds=settings.rate_limit_window_seconds,
        ):
            store.add_audit(
                "rate_limit_exceeded",
                result="blocked",
                details={"scope": scope, "path": request.url.path},
            )
            raise _error(HTTPStatus.TOO_MANY_REQUESTS, "rate_limit_exceeded")

    def require_admin(
        request: Request,
        authorization: str | None,
        admin_token_header: str | None,
    ) -> None:
        require_rate(request, "admin", settings.rate_limit_admin)
        if not settings.admin_token:
            raise _error(HTTPStatus.SERVICE_UNAVAILABLE, "admin_token_not_configured")
        expected = settings.admin_token
        bearer = ""
        if authorization and authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()
        if bearer != expected and (admin_token_header or "").strip() != expected:
            store.add_audit("admin_auth", result="blocked", details={"path": request.url.path})
            raise _error(HTTPStatus.UNAUTHORIZED, "admin_auth_required")

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
        storage_ok = store.healthcheck()
        return {
            "ok": not errors and storage_ok,
            "serverTime": isoformat_utc(utc_now()),
            "config": {
                "ok": not errors,
                "errorCount": len(errors),
                "errors": errors,
            },
            "storage": {"ok": storage_ok},
        }

    @app.get("/ready")
    @app.get("/api/ready")
    def ready():
        errors = settings.validate()
        storage_ok = store.healthcheck()
        payload = {
            "ok": not errors and storage_ok,
            "serverTime": isoformat_utc(utc_now()),
            "config": {"ok": not errors, "errorCount": len(errors), "errors": errors},
            "storage": {"ok": storage_ok},
        }
        return JSONResponse(
            status_code=HTTPStatus.OK if payload["ok"] else HTTPStatus.SERVICE_UNAVAILABLE,
            content=payload,
        )

    @app.get("/", response_class=HTMLResponse)
    @app.get("/demo", response_class=HTMLResponse)
    def demo_page():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/assets/kbeam-logo.png")
    def kbeam_logo():
        return FileResponse(STATIC_DIR / "kbeam-logo.png", media_type="image/png")

    @app.post(
        "/api/auth/device-login",
        status_code=HTTPStatus.CREATED,
        response_model=DeviceLoginCreateResponse,
    )
    def create_device_login(request: Request):
        from .models import TicketRecord

        require_rate(request, "device_login", settings.rate_limit_device_login)
        store.purge_expired()
        if store.pending_ticket_count() >= settings.max_pending_tickets:
            store.add_audit(
                "device_login_ticket_create",
                result="blocked",
                details={"reason": "max_pending_tickets"},
            )
            raise _error(HTTPStatus.TOO_MANY_REQUESTS, "max_pending_tickets_reached")
        issued_at = utc_now()
        expires_at = utc_after(settings.ticket_ttl_seconds)
        ticket_id = new_id("ticket")
        poll_token = new_token()
        approve_token = new_token()
        approve_url = _kbeam_approve_url(
            settings,
            ticket_id=ticket_id,
            approve_token=approve_token,
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
        store.create_ticket(ticket)
        store.add_audit("device_login_ticket_create", details={"ticketId": ticket.ticketId})
        payload = _public_ticket(ticket)
        payload["pollToken"] = poll_token
        return {"ok": True, "deviceLogin": payload}

    @app.get("/api/auth/device-login/{ticket_id}", response_model=TicketPollResponse)
    def poll_device_login(
        ticket_id: str,
        request: Request,
        response: Response,
        poll_token: Annotated[str, Query(alias="pollToken")],
    ):
        require_rate(request, "ticket_poll", settings.rate_limit_ticket_poll)
        store.purge_expired()
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
        if ticket.pollToken != poll_token:
            raise _error(HTTPStatus.FORBIDDEN, "device_login_poll_forbidden")
        payload = {"ok": True, "deviceLogin": _public_ticket(ticket), "session": None}
        if ticket.status == "approved" and ticket.sessionId:
            session = store.get_session(ticket.sessionId)
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
                payload["session"] = _session_view(session, organization_slug=settings.service_slug)
        return payload

    @app.get("/api/auth/device-login/{ticket_id}/events")
    async def device_login_events(
        ticket_id: str,
        request: Request,
        poll_token: Annotated[str, Query(alias="pollToken")],
    ):
        require_rate(request, "ticket_events", settings.rate_limit_ticket_events)
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
        if ticket.pollToken != poll_token:
            raise _error(HTTPStatus.FORBIDDEN, "device_login_poll_forbidden")

        async def event_stream():
            last_status = ""
            while True:
                if await request.is_disconnected():
                    break
                current = store.get_ticket(ticket_id)
                if not current:
                    yield "event: expired\ndata: {\"ok\":false,\"error\":\"device_login_ticket_expired\"}\n\n"
                    break
                payload = {
                    "ok": True,
                    "deviceLogin": _ticket_status_view(current),
                    "session": None,
                }
                if current.status == "approved" and current.sessionId:
                    session = store.get_session(current.sessionId)
                    if session:
                        payload["session"] = _session_view(session, organization_slug=settings.service_slug)
                if current.status != last_status:
                    yield f"event: status\ndata: {json.dumps(payload)}\n\n"
                    last_status = current.status
                if current.status == "approved":
                    yield f"event: approved\ndata: {json.dumps(payload)}\n\n"
                    break
                await asyncio.sleep(1)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/auth/device-login/{ticket_id}/challenge", response_class=HTMLResponse)
    def challenge_scan_page(
        ticket_id: str,
        approve_token: Annotated[str, Query(alias="approveToken")],
    ):
        store.purge_expired()
        ticket = store.get_ticket(ticket_id)
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
    def create_challenge(ticket_id: str, request: Request, payload: ChallengeCreateRequest):
        from .models import ChallengeRecord

        require_rate(request, "challenge", settings.rate_limit_challenge)
        store.purge_expired()
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
        if ticket.approveToken != payload.approveToken:
            raise _error(HTTPStatus.FORBIDDEN, "device_login_approve_forbidden")
        if ticket.status != "pending":
            raise _error(HTTPStatus.CONFLICT, "device_login_ticket_not_pending")

        address = payload.address.strip().lower()
        issued_at = utc_now()
        expires_at = utc_after(settings.challenge_ttl_seconds)
        challenge_id = new_id("challenge")
        nonce = new_token()
        requested_protocol = payload.protocolVersion or PROTOCOL_VERSION
        if requested_protocol not in {PROTOCOL_VERSION, PROTOCOL_VERSION_V2}:
            raise _error(HTTPStatus.BAD_REQUEST, "auth_protocol_unsupported")

        origin = payload.origin or settings.public_base_url
        effective_protocol = PROTOCOL_VERSION
        v2_values: dict[str, str | bool | None] = {
            "api_origin": None,
            "relying_party": None,
            "audience": None,
            "return_origin": None,
            "joined_by_mobile": False,
        }
        if requested_protocol == PROTOCOL_VERSION_V2:
            v2_error = ""
            try:
                relying_party_origin = _normalize_origin(origin)
                return_origin = _normalize_origin(payload.returnOrigin or origin)
            except ValueError:
                v2_error = "auth_origin_invalid"
                relying_party_origin = ""
                return_origin = ""
            audience = payload.audience or expected_audience
            if not v2_error and relying_party_origin not in trusted_rp_origins:
                v2_error = "auth_origin_not_trusted"
            if not v2_error and return_origin not in allowed_return_origins:
                v2_error = "auth_return_origin_not_allowed"
            if not v2_error and audience != expected_audience:
                v2_error = "auth_audience_mismatch"
            if not v2_error and not payload.joinedByMobile:
                v2_error = "auth_mobile_join_required"

            if settings.challenge_v2_mode == "dual":
                if v2_error:
                    raise _error(HTTPStatus.BAD_REQUEST, v2_error)
                effective_protocol = PROTOCOL_VERSION_V2
                origin = relying_party_origin
                v2_values = {
                    "api_origin": configured_public_origin,
                    "relying_party": settings.service_slug,
                    "audience": audience,
                    "return_origin": return_origin,
                    "joined_by_mobile": True,
                }
            else:
                shadow_audit(
                    "auth_challenge_v2_evaluate",
                    address=address,
                    result="shadow" if settings.challenge_v2_mode == "shadow" else "off",
                    details={"reason": v2_error or "valid", "ticketId": ticket.ticketId},
                )
        elif settings.challenge_v2_mode == "shadow":
            try:
                normalized_v1_origin = _normalize_origin(origin)
                origin_result = (
                    "trusted" if normalized_v1_origin in trusted_rp_origins else "untrusted"
                )
            except ValueError:
                origin_result = "invalid"
            shadow_audit(
                "auth_challenge_v1_origin_evaluate",
                address=address,
                result="shadow",
                details={"result": origin_result, "ticketId": ticket.ticketId},
            )

        if effective_protocol == PROTOCOL_VERSION_V2:
            message = build_challenge_message_v2(
                address=address,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
                ticket_id=ticket.ticketId,
                api_origin=str(v2_values["api_origin"]),
                relying_party=str(v2_values["relying_party"]),
                relying_party_origin=origin,
                audience=str(v2_values["audience"]),
                return_origin=str(v2_values["return_origin"]),
            )
        else:
            message = build_challenge_message(
                settings=settings,
                address=address,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
                ticket_id=ticket.ticketId,
                origin=origin,
            )
        challenge = ChallengeRecord(
            challengeId=challenge_id,
            ticketId=ticket.ticketId,
            address=address,
            network=payload.network or settings.signer_network,
            nonce=nonce,
            issuedAt=issued_at,
            expiresAt=expires_at,
            origin=origin,
            message=message,
            protocolVersion=effective_protocol,
            apiOrigin=v2_values["api_origin"],
            relyingParty=v2_values["relying_party"],
            audience=v2_values["audience"],
            returnOrigin=v2_values["return_origin"],
            joinedByMobile=bool(v2_values["joined_by_mobile"]),
        )
        if ticket.challengeId:
            store.delete_challenge(ticket.challengeId)
        store.create_challenge(challenge)
        ticket.challengeId = challenge.challengeId
        store.save_ticket(ticket)
        store.add_audit(
            "device_login_challenge_create",
            address=address,
            details={"ticketId": ticket.ticketId, "challengeId": challenge.challengeId},
        )

        return {
            "ok": True,
            "challenge": _challenge_view(challenge, organization_slug=settings.service_slug),
            "deviceLogin": _public_ticket(ticket),
        }

    @app.post(
        "/api/auth/device-login/{ticket_id}/approve",
        response_model=ApproveResponse,
    )
    def approve_device_login(ticket_id: str, request: Request, payload: ApproveRequest):
        from .models import SessionRecord

        require_rate(request, "approve", settings.rate_limit_approve)
        store.purge_expired()
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise _error(HTTPStatus.NOT_FOUND, "device_login_ticket_not_found")
        if ticket.status != "pending":
            raise _error(HTTPStatus.CONFLICT, "device_login_ticket_not_pending")
        if ticket.challengeId != payload.challengeId:
            raise _error(HTTPStatus.BAD_REQUEST, "device_login_challenge_mismatch")
        challenge = store.get_challenge(payload.challengeId)
        if not challenge:
            raise _error(HTTPStatus.NOT_FOUND, "auth_challenge_not_found")
        if challenge.expiresAt <= utc_now():
            store.delete_challenge(challenge.challengeId)
            raise _error(HTTPStatus.GONE, "auth_challenge_expired")
        if payload.autoApprove and not settings.autoapprove_enabled:
            store.add_audit(
                "device_login_approve",
                address=challenge.address,
                result="blocked",
                details={"reason": "auth_autoapprove_disabled", "ticketId": ticket.ticketId},
            )
            raise _error(HTTPStatus.FORBIDDEN, "auth_autoapprove_disabled")
        if challenge.protocolVersion == PROTOCOL_VERSION_V2 and not payload.explicitConfirmation:
            store.add_audit(
                "device_login_approve",
                address=challenge.address,
                result="blocked",
                details={"reason": "auth_explicit_confirmation_required", "ticketId": ticket.ticketId},
            )
            raise _error(HTTPStatus.BAD_REQUEST, "auth_explicit_confirmation_required")
        if (
            challenge.protocolVersion == PROTOCOL_VERSION
            and settings.challenge_v2_mode == "shadow"
            and not payload.explicitConfirmation
        ):
            shadow_audit(
                "legacy_approval_confirmation_evaluate",
                address=challenge.address,
                result="shadow",
                details={"ticketId": ticket.ticketId},
            )
        if not store.is_wallet_allowed(challenge.address.lower(), settings):
            ticket.status = "denied"
            ticket.failureReason = "auth_wallet_not_allowed"
            store.save_ticket(ticket)
            store.delete_challenge(challenge.challengeId)
            store.add_audit(
                "device_login_approve",
                address=challenge.address,
                result="blocked",
                details={"reason": "auth_wallet_not_allowed", "ticketId": ticket.ticketId},
            )
            raise _error(HTTPStatus.FORBIDDEN, "auth_wallet_not_allowed")
        try:
            signature_verification = verify_signature(
                settings=settings,
                challenge=challenge,
                address=payload.address,
                signature=payload.signature,
                public_key=payload.publicKey,
            )
        except SignatureVerificationError as exc:
            store.add_audit(
                "device_login_approve",
                address=challenge.address,
                result="blocked",
                details={"reason": exc.code, "ticketId": ticket.ticketId},
            )
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
        consumed = store.consume_challenge_and_create_session(
            ticket_id=ticket.ticketId,
            challenge_id=challenge.challengeId,
            session=session,
        )
        if not consumed:
            store.add_audit(
                "device_login_approve",
                address=challenge.address,
                result="blocked",
                details={"reason": "auth_challenge_already_consumed", "ticketId": ticket.ticketId},
            )
            raise _error(HTTPStatus.CONFLICT, "auth_challenge_already_consumed")
        ticket = store.get_ticket(ticket.ticketId)
        if not ticket:
            raise _error(HTTPStatus.CONFLICT, "device_login_ticket_not_pending")
        store.add_audit(
            "device_login_approve",
            address=challenge.address,
            details={"ticketId": ticket.ticketId, "sessionId": session.sessionId},
        )

        return {
            "ok": True,
            "deviceLogin": _public_ticket(ticket),
            "session": _session_view(session, organization_slug=settings.service_slug),
            "challenge": _challenge_view(challenge, organization_slug=settings.service_slug),
            "signature": signature_verification.as_public_dict(),
            "auth": {
                "mode": "wallet_signature",
                "runtimeActive": True,
                "sessionRuntimeActive": True,
            },
        }

    def current_session_id(request: Request) -> str | None:
        return request.cookies.get(settings.cookie_name)

    @app.get("/api/auth/session", response_model=SessionResponse)
    def get_session(request: Request):
        store.purge_expired()
        session_id = current_session_id(request)
        if not session_id:
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        session = store.get_session(session_id)
        if not session:
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        return {"ok": True, "session": _session_view(session, organization_slug=settings.service_slug)}

    @app.get("/api/auth/validate", status_code=HTTPStatus.NO_CONTENT)
    def validate_session(request: Request):
        store.purge_expired()
        session_id = current_session_id(request)
        if not session_id or not store.get_session(session_id):
            raise _error(HTTPStatus.UNAUTHORIZED, "auth_session_required")
        return Response(status_code=HTTPStatus.NO_CONTENT)

    @app.delete("/api/auth/sessions/current")
    def delete_current_session(
        request: Request,
        response: Response,
    ):
        session_id = current_session_id(request)
        if session_id:
            store.delete_session(session_id)
            store.add_audit("session_logout", details={"sessionId": session_id})
        response.delete_cookie(
            settings.cookie_name,
            domain=settings.cookie_domain or None,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )
        return {"ok": True}

    @app.get("/api/admin/wallets")
    def admin_list_wallets(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_kbeam_admin_token: Annotated[str | None, Header()] = None,
    ):
        require_admin(request, authorization, x_kbeam_admin_token)
        return {"ok": True, "wallets": [_wallet_view(wallet) for wallet in store.list_wallets()]}

    @app.post("/api/admin/wallets", status_code=HTTPStatus.CREATED)
    def admin_create_wallet(
        payload: WalletCreateRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_kbeam_admin_token: Annotated[str | None, Header()] = None,
    ):
        from .store import _wallet_record

        require_admin(request, authorization, x_kbeam_admin_token)
        wallet = store.upsert_wallet(
            _wallet_record(
                payload.address,
                label=payload.label,
                role=payload.role,
                enabled=payload.enabled,
            )
        )
        store.add_audit("admin_wallet_upsert", address=wallet.address, details={"role": wallet.role})
        return {"ok": True, "wallet": _wallet_view(wallet)}

    @app.patch("/api/admin/wallets/{address}")
    def admin_update_wallet(
        address: str,
        payload: WalletUpdateRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_kbeam_admin_token: Annotated[str | None, Header()] = None,
    ):
        require_admin(request, authorization, x_kbeam_admin_token)
        wallet = store.update_wallet(
            address,
            label=payload.label,
            role=payload.role,
            enabled=payload.enabled,
        )
        if not wallet:
            raise _error(HTTPStatus.NOT_FOUND, "wallet_not_found")
        store.add_audit("admin_wallet_update", address=wallet.address)
        return {"ok": True, "wallet": _wallet_view(wallet)}

    @app.get("/api/admin/audit-log")
    def admin_audit_log(
        request: Request,
        limit: int = 100,
        authorization: Annotated[str | None, Header()] = None,
        x_kbeam_admin_token: Annotated[str | None, Header()] = None,
    ):
        require_admin(request, authorization, x_kbeam_admin_token)
        return {"ok": True, "auditLog": [_audit_view(record) for record in store.list_audit(limit)]}

    return app


app = create_app()
