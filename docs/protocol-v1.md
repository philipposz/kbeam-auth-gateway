# KBeam Auth Protocol v1

Protocol identifier:

```text
kbeam-auth-v1
```

## Challenge Message

The gateway signs no user data itself. It creates a deterministic message that
the wallet signs as raw UTF-8 bytes.

The byte sequence is exactly:

```text
KBeam login
Protocol: kbeam-auth-v1
Service: <service-slug>
Service Name: <service-label>
Address: <kaspa-address>
Nonce: <random>
Issued At: <iso8601-utc>
Expires At: <iso8601-utc>
Ticket: <ticket-id>
Origin: <expected-origin>
```

Rules:

- Field order is fixed.
- Field labels are fixed.
- Line endings are LF (`\n`).
- No trailing newline is appended.
- Timestamps are UTC and use the `Z` suffix.
- The wallet signs the raw UTF-8 bytes of the full message.

## Approval Payload

```json
{
  "challengeId": "challenge_...",
  "address": "kaspa:...",
  "signature": "<64-byte schnorr signature as lowercase hex>",
  "publicKey": "<32-byte x-only public key as lowercase hex>"
}
```

The gateway verifies that:

- the challenge exists and has not expired
- the challenge belongs to the ticket being approved
- the submitted address equals the challenge address
- the submitted wallet is allowed by configuration
- the Kaspa address derived from the public key equals the submitted address
- the Schnorr signature validates over the raw challenge message bytes
- the ticket has not already been approved

## Replay Handling

An approved ticket becomes `approved` and cannot be approved again. The
challenge is removed from the in-memory challenge store after successful
approval.
