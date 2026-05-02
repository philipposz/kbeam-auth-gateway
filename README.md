# KBeam Auth Gateway

KBeam Auth Gateway is a standalone server for wallet-based login flows. It is
intended to become a public reference implementation for the KBeam login
protocol, while application-specific code and private deployment details remain
outside this repository.

## Goal

The gateway owns authentication only:

- create login tickets
- create QR codes and same-device approve links
- create deterministic challenge messages
- verify wallet signatures
- check allowed wallets or later users and organizations
- issue, validate, and revoke HttpOnly session cookies
- provide a healthcheck
- support reverse-proxy integration through nginx `auth_request`
- provide demo and integration examples

Application business logic, payment flows, mobile app source code, production
secrets, private hostnames, and internal infrastructure notes are out of scope.

## Documentation

- [Public gateway plan](docs/PUBLIC_KBEAM_AUTH_GATEWAY_PLAN_2026-05-02.md)
- [Protocol v1](docs/protocol-v1.md)
- [Native signature verifier](docs/native-signature-verifier.md)
- [Nginx auth request integration](docs/nginx-auth-request.md)
- [Deployment examples](docs/deployment-examples.md)
- [Production hardening](docs/PRODUCTION_HARDENING_2026-05-02.md)
- [Security and secret hygiene](docs/SECURITY_AND_SECRET_HYGIENE.md)
- [Rollback notes](docs/ROLLBACK.md)

## Current Status

This repository contains the extracted planning foundation, a FastAPI runtime
skeleton, native Schnorr signature verification, a local demo UI, tests, and
generic deployment examples.

## Local Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
```

Run the gateway locally:

```bash
cp .env.example .env
.venv/bin/kbeam-auth-gateway
```

The first runtime skeleton exposes `/health`, `/api/auth/device-login`,
`/api/auth/session`, `/api/auth/validate`, and logout/session endpoints. The
demo UI is available at `http://127.0.0.1:18090/demo`.

The default signature verifier mode is `native`. It verifies a 64-byte Schnorr
signature over the raw UTF-8 challenge message with a 32-byte x-only secp256k1
public key and checks that the derived Kaspa address matches the challenge
address. `demo` mode is available only for local flow tests.

## Production Features

- SQLite or Postgres-backed tickets, sessions, wallets, and audit log
- wallet policy: `open` for demos or `allowlist` for protected deployments
- admin API protected by `KBEAM_AUTH_ADMIN_TOKEN`
- per-IP rate limits for ticket creation, polling, SSE, challenge, approval, and admin routes
- maximum pending-ticket cap
- SSE ticket events with polling fallback in the demo
- automatic QR expiry handling in the demo

Admin examples:

```bash
curl -H "Authorization: Bearer $KBEAM_AUTH_ADMIN_TOKEN" \
  https://auth.example.com/api/admin/wallets

curl -X POST -H "Authorization: Bearer $KBEAM_AUTH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"address":"kaspa:example","label":"Example Wallet","role":"admin","enabled":true}' \
  https://auth.example.com/api/admin/wallets
```

Use `KBEAM_AUTH_STORE_BACKEND=postgres` with `KBEAM_AUTH_POSTGRES_DSN` when the
gateway should share durable state across rolling releases or multiple workers.

## Docker

```bash
cp .env.example .env
docker compose up -d --build
curl -f http://127.0.0.1:18090/health
```
