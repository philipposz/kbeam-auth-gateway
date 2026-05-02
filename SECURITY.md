# Security

KBeam Auth Gateway is intended to become public. Please do not report real
secrets by opening public issues.

## Threat Model

The gateway protects applications by requiring a wallet-signed challenge before
issuing a session cookie.

Main risks:

- replayed challenge approvals
- forged signatures
- mismatched wallet addresses
- stolen session cookies
- CSRF around session-changing endpoints
- brute-force attempts against ticket or approval tokens
- accidental publication of production configuration

Current mitigations:

- short-lived tickets and challenges
- one-time challenge approval
- HttpOnly session cookies
- configurable Secure cookie flag
- SameSite=Lax cookies
- native Schnorr verification over exact raw message bytes
- SQLite-backed wallet allowlist
- admin API protected by a bearer token
- per-IP rate limits
- maximum pending-ticket cap
- audit log without secrets
- placeholder-only example configuration

Planned hardening:

- Postgres or Redis-backed shared stores for multi-process deployments
- broader CSRF review before public release
- automated secret scanning in the release process

## Secret Hygiene

Never commit real API keys, tokens, passwords, private keys, certificates,
wallet files, productive `.env` files, or production infrastructure details.
