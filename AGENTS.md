# KBeam Auth Gateway Agent Instructions

These instructions replace inherited repository-specific instructions for all files in this repository. Universal user-level policy still applies.

## Repository Scope

This public repository owns the standalone KBeam wallet-authentication gateway, its protocol, signature verification, tickets, sessions, stores, demo, and generic integration examples. It does not own a public website, mobile client, application business logic, payment flow, or private infrastructure.

Use `docs/context-map.md` to select no more than one to three initial sources. Current code, tests, CI, the license, and the compatibility specification are authoritative.

## Compatibility and Security Invariants

- Preserve the compatibility surface defined by `LICENSE` and `KBEAM-COMPATIBILITY.md`.
- Keep the challenge byte-stable: fixed field order and labels, LF line endings, no trailing newline, the required first line, and the required protocol identifier.
- Tickets and challenges remain short-lived, ticket-bound, address-bound, one-time, and replay-resistant.
- Signature verification must bind the exact challenge bytes, public key, claimed address, and network. Native verification is the default; demo mode is only for synthetic local-flow tests.
- Do not weaken session-cookie settings, wallet policy, rate limits, admin authentication, pending-ticket limits, or secret-free audit logging without focused security review and tests.
- This is a public repository. Examples use obvious placeholders only. Never add real credentials, wallet material, private hosts, production configuration, internal recovery details, or host-specific paths.
- Deployment requires explicit authorization, a passing healthcheck, an affected-flow smoke test, and a rollback path. Repository examples remain generic.

## Verification

Run the CI contract for code or configuration changes:

```text
python -m ruff check .
python tools/public_hygiene_check.py
python -m pytest
```

Compatibility-sensitive changes must also exercise the affected ticket, challenge, signature, event, session, and protected-area flow. A documentation-only policy migration requires static public-hygiene, Markdown-link, diff, and staging checks but no runtime build.
