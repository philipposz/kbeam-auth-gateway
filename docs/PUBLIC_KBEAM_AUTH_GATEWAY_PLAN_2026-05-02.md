# Public KBeam Auth Gateway Plan 2026-05-02

This plan was adapted from the existing internal KBeam product planning and
rewritten for standalone, future-public development. It intentionally avoids
private hostnames, local filesystem paths, production configuration, and
infrastructure recovery details.

## Objective

Move the wallet-based KBeam login flow into a dedicated repository named
`kbeam-auth-gateway`. The repository should become publicly auditable without
publishing private mobile app source code, product-specific business logic, or
deployment internals.

## Principles

- Public: authentication protocol, server reference implementation, demo,
  examples, tests, and security documentation.
- Private: mobile app implementation, product UI, build pipeline, business
  integrations, internal deployment notes, production secrets.
- Default configuration must use placeholders such as `example.com`.
- Real secrets, productive `.env` files, tokens, certificates, private keys,
  wallet files, and production credentials must never be committed.
- The repository should be safe to make public without a cleanup scramble.

## Public Repository Scope

The gateway owns only authentication:

- create login tickets
- create QR codes and deep links
- create challenge messages
- verify wallet signatures
- check allowed wallets, later users, organizations, and roles
- set, validate, and revoke session cookies
- expose logout and healthcheck endpoints
- support nginx `auth_request`
- provide Docker Compose and systemd examples
- provide a static demo
- test message format, signature verification, sessions, and proxy flow

Out of scope:

- POS or accounting business logic
- payment and NFC workflows
- mobile app source code
- private deployment details
- production secrets
- product-specific hostnames or filesystem paths

## Target Architecture

```text
Browser
  |
  | 1. GET protected app
  v
Nginx
  |
  | 2. auth_request /_kbeam_auth
  v
KBeam Auth Gateway
  |
  | 3a. allowed: 204
  | 3b. denied: login page or 401
  v
Protected app backend or webroot
```

Login flow:

```text
Browser -> Gateway: POST /api/auth/device-login
Gateway -> Browser: ticketId, pollToken, qrSvg, approveURL
KBeam app -> Gateway: request challenge for ticketId
KBeam app -> Gateway: approve signed challenge
Browser -> Gateway: poll ticket
Gateway -> Browser: HttpOnly session cookie
```

## Protocol Versioning

The login protocol gets an explicit version:

```text
kbeam-auth-v1
```

The signed message must be stable and documented byte-for-byte:

```text
KBeam login
Protocol: kbeam-auth-v1
Service: <service-slug>
Service Name: <service-label>
Address: <kaspa-address>
Nonce: <random>
Issued At: <iso8601>
Expires At: <iso8601>
Ticket: <ticket-id>
Origin: <expected-origin>
```

Rules:

- Line breaks, field names, and field order are part of the protocol.
- `Issued At` and `Expires At` are emitted in UTC.
- Nonces must be cryptographically random.
- Challenges must be short-lived.
- A ticket can be approved only once.
- Verification must reject expired, reused, malformed, or tampered challenges.

## Security Requirements

Required before public release:

- threat model in `SECURITY.md`
- documented replay-attack handling
- CSRF assessment for logout and session endpoints
- HttpOnly session cookies
- Secure cookies in HTTPS deployments
- documented SameSite strategy
- configurable session TTL
- rate limits for ticket and challenge endpoints
- audit log without secrets
- structured error codes
- no sensitive data in QR codes beyond ticket, approve token, and public API URL
- no private domains, local paths, or production defaults
- tests for expired, duplicate, malformed, and tampered challenges

## Trust Model

The public gateway proves:

- which message is signed
- how the signature is verified
- when a session is created
- which wallets are allowed
- how logout and session validation behave

The private KBeam app proves compatibility with the public protocol:

- it scans a QR code or opens a deep link
- it displays the login request to the user
- it signs exactly the gateway-generated challenge
- it submits signature, public key, and address back to the gateway

## Intended Installation Shape

Example-only installation flow:

```bash
git clone https://github.com/<owner>/kbeam-auth-gateway.git
cd kbeam-auth-gateway
cp .env.example .env
docker compose up -d
curl -f http://127.0.0.1:18090/health
sudo nginx -t
sudo systemctl reload nginx
```

Planned files:

- `README.md`
- `SECURITY.md`
- `.env.example`
- `compose.yaml`
- `deploy/nginx/example-app.conf`
- `deploy/systemd/kbeam-auth-gateway.service.example`
- `examples/static-demo/`
- `docs/protocol-v1.md`
- `docs/nginx-auth-request.md`
- `docs/rollback.md`

Example environment values only:

```text
KBEAM_AUTH_BIND=127.0.0.1:18090
KBEAM_AUTH_PUBLIC_BASE_URL=https://auth.example.com
KBEAM_AUTH_COOKIE_NAME=kbeam_auth_session
KBEAM_AUTH_COOKIE_DOMAIN=
KBEAM_AUTH_ALLOWED_WALLETS=kaspa:example
KBEAM_AUTH_SESSION_TTL_SECONDS=28800
KBEAM_AUTH_CHALLENGE_TTL_SECONDS=300
KBEAM_AUTH_SECURE_COOKIES=true
KBEAM_AUTH_SIGNER_NETWORK=mainnet
```

## Integration Modes

### Reverse Proxy Mode

Nginx protects an existing application with `auth_request`.

Benefits:

- The protected app needs minimal changes.
- The same auth gateway can protect multiple services.
- Rollback can happen at the proxy layer.

### App API Mode

An application owns the login UI and calls gateway endpoints directly.

Benefits:

- Better control over product UI.
- Useful when the app already has an authentication surface.
- Keeps gateway responsibility narrow and testable.

## Migration Plan

### Phase 1: Repository Foundation

- Keep the repository private while the first implementation is created.
- Add runtime skeleton in the chosen language.
- Avoid application-specific names except placeholder examples.
- Write protocol documentation.
- Add tests for signatures, tickets, sessions, and logout.
- Add secret scanning before any public release.

### Phase 2: First Protected App

- Integrate one existing application through the gateway.
- Keep the previous internal auth route as compatibility mode.
- Test nginx `auth_request` with the gateway.
- Rollback: point the app or proxy back to the previous internal auth route.

### Phase 3: Second Protected App

- Integrate another existing application.
- Verify that host and origin handling remain correct.
- Keep app-specific routing outside the public repository.
- Rollback: restore that app's previous auth route.

### Phase 4: Public Readiness

- Remove private paths, domains, and recovery internals.
- Run secret scanning.
- Finalize `README.md`, `SECURITY.md`, and protocol docs.
- Use only `example.com` in public examples.
- Choose a license.
- Create first public tag, for example `v0.1.0`.

### Phase 5: Publish

- Make the repository public.
- Write release notes.
- Test installation on a fresh machine.
- Document known limitations.

## Next Concrete Implementation Step

Build a local demo with these endpoints:

1. `POST /api/auth/device-login`
2. `POST /api/auth/device-login/{ticketId}/challenge`
3. `POST /api/auth/device-login/{ticketId}/approve`
4. `GET /api/auth/session`
5. `DELETE /api/auth/sessions/current`
6. `GET /api/auth/validate`
7. Static demo page with QR code and same-device approve button

Only move toward public release when tests, docs, and secret hygiene are clean.

## Open Decisions

- Runtime language: Rust for a robust binary or Python for fast iteration.
- Session store: in-memory first, later SQLite, Postgres, or Redis.
- User model: wallet allowlist first, later organizations and roles.
- Cookie strategy: per-app domain or central auth host.
- External wallet compatibility: keep protocol open, KBeam app first.

