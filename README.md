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
- [Security and secret hygiene](docs/SECURITY_AND_SECRET_HYGIENE.md)
- [Rollback notes](docs/ROLLBACK.md)

## Current Status

This repository currently contains the extracted planning foundation. Runtime
code, tests, protocol docs, and deployment examples will be added in small,
reviewable steps.

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
signature verifier currently has a `demo` mode for protocol and flow testing
only.
