# KBeam Compatibility Specification

Version 1.0 - 3 May 2026

This document describes the technical compatibility surface that must remain
available when a copy, fork, deployment, modified version, derivative work,
hosted source release, or substantial continuation includes or is based on the
KBeam-compatible login flow from KBeam Auth Gateway.

This specification is referenced by the KBeam Auth Gateway Source Available
Compatibility License 1.1. It is technical documentation, not a separate grant
of trademark rights or a replacement for the license.

## Compatibility Goal

A protected website or application must be able to create a pending login
ticket, show or open a KBeam app link, let the KBeam wallet application fetch
and sign the login challenge, receive approval, notify the waiting browser, and
unlock the browser session that requested the login.

Implementations may change internal routes, storage, UI, deployment topology,
and authorization policy, but the KBeam-compatible login flow must remain
functional and interoperable with the KBeam wallet application.

## Protected Compatibility Identifiers

The following identifiers are protected compatibility identifiers:

- `KBeam login`
- `kbeam-auth-v1`
- `kbeam://`
- KBeam auth configuration, environment, API, protocol, and integration
  identifiers beginning with `KBEAM` or `kbeam` when they are used to preserve
  KBeam auth compatibility

These identifiers must not be removed, renamed, obscured, or made
non-functional in versions that include or are based on the KBeam-compatible
login flow.

## Login Challenge

The login challenge must be deterministic for the pending login ticket and must
start with this exact first line:

```text
KBeam login
```

The challenge must include or be associated with the protocol identifier:

```text
kbeam-auth-v1
```

The challenge must be short-lived and bound to the pending ticket that requested
login. Implementations may add additional fields, but those fields must not
prevent the KBeam wallet application from identifying the challenge as a
KBeam-compatible login challenge.

## App Approval Link

The waiting website or protected application must be able to present an app
approval URI compatible with the KBeam app URI scheme:

```text
kbeam://
```

The URI may use a login route such as `pos-login`, `login-key`, or a later
KBeam-compatible login route. Implementations may add query parameters or
fallback URLs, provided the KBeam wallet application can still identify the
pending ticket, obtain the challenge, approve the ticket, and return to the
waiting website or protected application when a return flow is configured.

## Required Login Flow Capabilities

An implementation that includes or is based on the KBeam-compatible login flow
must provide equivalent capabilities for all of the following:

- ticket creation for a waiting browser or protected application
- challenge creation or challenge retrieval for a pending ticket
- wallet approval using a KBeam wallet signature over the challenge
- signature verification that binds the signature to the claimed wallet address
  and public key
- waiting-browser status updates through polling, SSE, or an equivalent event
  mechanism
- session or authorization handoff that unlocks the browser that requested the
  login
- logout or session revocation for integrations that issue browser sessions

Equivalent routes are acceptable. The public API paths do not have to match
KBeam Auth Gateway exactly, as long as the KBeam wallet application and waiting
browser can complete the same compatible flow.

## Verification Duty

Before a public deployment, public hosted service, redistributed version,
modified version, fork, derivative work, hosted source release, or substantial
continuation is made available, the operator or distributor must verify that
the KBeam-compatible login flow works.

Verification may be automated tests, documented manual tests, integration
smoke tests, or another reasonable procedure. It must cover the parts of the
flow affected by the change, including login tickets, KBeam app links,
challenge generation, signature approval, waiting-browser status updates,
session handoff, and protected-area unlock behavior when those areas are
materially changed.

## Compatibility Claim

An implementation must not knowingly claim KBeam compatibility while its
KBeam-compatible login flow is non-functional.

If the flow breaks in a public deployment or redistributed version, the operator
or distributor must make commercially reasonable efforts to repair it, disable
the broken public release until repaired, or clearly withdraw the affected
KBeam-compatible login claim.

## Relationship To Other Login Methods

Other login methods, wallet providers, identity systems, access policies,
payment flows, user interfaces, storage systems, and authorization layers may
be added. They must not remove, hide, disable, or break the KBeam-compatible
login flow when that flow is included or used.

## Versioning

This is version 1.0 of the KBeam Compatibility Specification. Later versions
may add compatible routes, clarify verification procedures, or describe newer
protocol versions. A distributed copy is governed by the compatibility
specification included with that copy unless Licensor separately authorizes
different compatibility terms in writing.
