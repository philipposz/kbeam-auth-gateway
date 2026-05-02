# FastAPI Runtime Foundation 2026-05-02

The first runtime implementation uses Python with FastAPI.

## Reasoning

The existing POS server is Python but uses `BaseHTTPRequestHandler` and manual
path routing. The standalone auth gateway should be easier to test, document,
and publish, so the HTTP layer starts fresh with FastAPI while the ticket,
challenge, and session flow stays aligned with the existing product behavior.

## Initial Runtime Scope

Implemented foundation:

- `GET /health`
- `GET /api/health`
- `POST /api/auth/device-login`
- `GET /api/auth/device-login/{ticketId}`
- `POST /api/auth/device-login/{ticketId}/challenge`
- `POST /api/auth/device-login/{ticketId}/approve`
- `GET /api/auth/session`
- `GET /api/auth/validate`
- `DELETE /api/auth/sessions/current`

The first store is in-memory and intended only for local demo and protocol
tests. Signature verification now supports native Schnorr verification. `demo`
mode remains available only for local flow tests.

## Rollback

This change is additive. To roll back the runtime foundation before the first
commit, remove:

- `pyproject.toml`
- `.env.example`
- `Dockerfile`
- `compose.yaml`
- `.github/workflows/ci.yml`
- `deploy/`
- `src/`
- `tests/`
- this document

No deployment state is affected.

## Next Step

Add persistent stores and rate limits before any production deployment.
