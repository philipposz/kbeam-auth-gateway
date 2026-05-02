# Public Login Transparency 2026-05-02

This repository is meant to show everything required for the login gateway to
work. The implementation is intentionally public, reviewable, and portable.

## What Is Public Here

- the HTTP routes used by a protected website
- the device-login ticket format
- the KBeam app URL format
- the challenge message format
- the signature verification path
- the session-cookie behavior
- the SQLite and Postgres store boundaries
- the wallet allowlist and admin API shape
- the demo UI and integration examples
- rollback notes for each gateway change

No private KBeam app source code is required to understand or verify the gateway
contract. A compatible wallet client only needs to parse the public login URL,
request a challenge, sign the raw UTF-8 challenge, and submit the approval.

## What KBeam Does Not Know

KBeam does not receive the browser's poll token. KBeam does not receive the
protected website's HttpOnly session cookie. KBeam does not receive the website's
user database, private routes, internal permissions, server secrets, or protected
content.

KBeam can only see the login metadata that is explicitly placed into the login
request, such as:

- ticket id
- approve token
- API base URL
- service label
- wallet address used for signing
- optional `returnTo` URL for same-device flows

That is enough for the wallet to approve a login, but not enough for the wallet
to impersonate the waiting browser or inspect the protected area.

## Browser And Wallet Separation

The browser that wants access receives a private `pollToken`. The QR code or
same-device KBeam link receives a separate `approveToken`.

The wallet signs a challenge for the `approveToken`. The browser later polls or
listens via SSE with the `pollToken`. Only the browser response sets the
gateway's HttpOnly session cookie.

This split is the core safety property:

- the wallet can approve
- the browser can receive the session
- the wallet does not get the browser session
- the browser does not get the wallet private key

## Integrator Responsibility

Applications that embed the gateway should review the code, set a production
store backend, enable wallet allowlists when appropriate, protect admin routes,
and decide what service label and return URL they want to expose.

The protected application remains responsible for its own business logic and
authorization rules after the gateway has established a signed wallet session.

## Rollback

This document is descriptive. To roll back the public transparency changes,
remove the README link and this file. To roll back protocol or UI behavior, use
the change-specific rollback documents in `docs/`.
