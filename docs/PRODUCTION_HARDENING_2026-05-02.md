# Production Hardening 2026-05-02

This change moves the gateway from protocol demo toward a production-capable
single-node deployment.

## Runtime Changes

- Device-login tickets stop being created when `KBEAM_AUTH_MAX_PENDING_TICKETS`
  is reached.
- Per-IP rate limits protect:
  - ticket creation
  - ticket polling
  - SSE ticket events
  - challenge creation
  - ticket approval
  - admin routes
- The browser demo uses Server-Sent Events for ticket status changes.
- The browser demo falls back to polling with backoff when SSE is unavailable.
- The browser demo stops automatically when the ticket expires.

## Store

`KBEAM_AUTH_STORE_BACKEND=sqlite` stores tickets, challenges, sessions, wallets,
and audit records in `KBEAM_AUTH_SQLITE_PATH`.

`KBEAM_AUTH_STORE_BACKEND=memory` remains useful for tests and throwaway demos.

Postgres is not enabled in code yet. The public store boundary is now explicit
enough to add a Postgres implementation without changing route behavior.

## Wallet Policy

`KBEAM_AUTH_WALLET_POLICY=open`

- Any wallet with a valid signature can approve a login.
- Useful only for public protocol demos.

`KBEAM_AUTH_WALLET_POLICY=allowlist`

- Only enabled wallets in the wallet store can approve a login.
- `KBEAM_AUTH_ALLOWED_WALLETS` bootstraps initial wallet rows at startup.

## Admin API

Admin routes require either:

```text
Authorization: Bearer <KBEAM_AUTH_ADMIN_TOKEN>
```

or:

```text
X-KBeam-Admin-Token: <KBEAM_AUTH_ADMIN_TOKEN>
```

Routes:

- `GET /api/admin/wallets`
- `POST /api/admin/wallets`
- `PATCH /api/admin/wallets/{address}`
- `GET /api/admin/audit-log`

## Rollback

1. Set `KBEAM_AUTH_STORE_BACKEND=memory` for a stateless rollback.
2. Set `KBEAM_AUTH_WALLET_POLICY=open` if wallet allowlist configuration blocks
   a demo environment.
3. Restart the gateway.
4. If the new demo behavior is the problem, roll back to release `cd0929e`.

SQLite data is isolated in `KBEAM_AUTH_SQLITE_PATH`; removing that file removes
runtime tickets, sessions, wallets, and audit records.
