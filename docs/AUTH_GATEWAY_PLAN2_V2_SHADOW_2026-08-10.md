# Auth Gateway v2 Shadow and Hardening

Status: implementation complete; deployment and enforcement are not authorized.

## Compatibility boundary

`kbeam-auth-v1`, its exact challenge bytes, public routes, polling/SSE behavior,
cookies, and response fields remain available. The default
`KBEAM_AUTH_CHALLENGE_V2_MODE=shadow` never rejects a v1 client and never emits a
v2 signing challenge. It records only a redacted evaluation result.

An explicitly coordinated client can request `kbeam-auth-v2` after a staging
deployment sets the mode to `dual`. The byte-stable v2 message binds:

- the configured API origin plus the relying-party identifier and HTTPS origin;
- the configured audience;
- the wallet address, ticket, nonce, issue time, and expiry;
- a separately allowlisted HTTPS return origin.

The challenge request must carry `joinedByMobile=true`. Its approval must carry
`explicitConfirmation=true`. A request labelled `autoApprove=true` is rejected
while `KBEAM_AUTH_AUTOAPPROVE_ENABLED` is false. All three values originate at
the client: they are protocol assertions, not attestation and not proof that a
confirmation UI was shown. In particular, an automated client can lie by
sending `autoApprove=false`. The server therefore does not claim a complete
autoapprove kill switch. `dual` is not production-rollout-capable until paired
mobile releases enforce the UI contract and independent tests establish that
behavior. The server cannot infer UI behavior from an unlabelled legacy v1
approval, so v1 remains shadow-observed until coordinated mobile parity is
proven.

## Independent server hardening

- A valid signature no longer leads to separate session-create, ticket-update,
  and challenge-delete commits. All supported stores use one compare-and-swap
  transaction: the ticket must still be pending and bound to the live challenge,
  otherwise no session is committed.
- `X-Forwarded-For` is ignored unless the direct peer belongs to an exact
  configured proxy CIDR. Invalid proxy configuration therefore fails safe.
- Exact request-authority policy (host plus any explicit port) starts in
  `shadow` and can be independently changed to `enforce` after proxy-path
  verification. Malformed authorities are never treated as trusted.
- `/ready` and `/api/ready` return 503 for invalid configuration or unavailable
  storage; `/health` retains the compatibility response while reporting the same
  component state.
- Expired non-approved tickets, old approved tickets, sessions, challenges, and
  audit records are bounded by explicit retention settings. These deletes are
  irreversible; operators must choose the retention values deliberately and
  back up durable stores before first activation. Rate limits retain sliding-
  window semantics and are shared atomically by the SQLite/Postgres backends;
  the explicit memory backend remains process-local and is suitable only for a
  single demo worker.

## Rollout gates

1. Keep v2 and host policy in shadow. Compare the checked-in Python vector with
   byte-identical Android and iOS vectors without changing a mobile production
   flow.
2. Deploy to staging, validate wrong audience/origin/return-origin, replay,
   missing confirmation, proxy spoofing, rotation, and expiry cases.
3. Use `dual` only in non-production staging for explicit app-version and route
   interoperability tests. Keep v1 and polling/SSE available. Production
   canaries remain blocked until mobile-enforced join/confirmation evidence is
   available.
4. Observe session-CAS conflicts, origin results, readiness, and rate-limit
   metrics. Stop the canary on unexplained deltas.
5. Reducing v1 or enabling any production enforcement needs a separate approval
   plus proven Android/iOS parity. There is no global cutoff in this change.

## Rollback

First set `KBEAM_AUTH_CHALLENGE_V2_MODE=shadow` to stop creating v2 challenges,
set `KBEAM_AUTH_TRUSTED_HOST_MODE=shadow`, and keep
`KBEAM_AUTH_AUTOAPPROVE_ENABLED=false`. Do **not** roll back the binary while a
v2 challenge can still be live: the prior binary can read its message but does
not know the v2 confirmation gates. Wait at least the configured
`KBEAM_AUTH_CHALLENGE_TTL_SECONDS` after the mode change, run the normal expiry
purge through the current binary, and verify in the durable store that no
unexpired row has `protocol_version = 'kbeam-auth-v2'`. Only then roll back the
binary. The additive columns may remain. Do not restore an older database:
doing so could resurrect consumed challenges or sessions. Existing v1 tickets
and sessions remain readable by the prior implementation.

No production service, mobile repository, wallet, or external authentication
flow was accessed while implementing or testing this slice.
