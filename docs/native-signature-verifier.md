# Native Signature Verifier

The gateway supports native verification with:

```text
KBEAM_AUTH_SIGNATURE_VERIFIER_MODE=native
```

Native verification mirrors the public behavior of the existing POS verifier:

- `publicKey` is a 32-byte x-only secp256k1 public key encoded as hex.
- `signature` is a 64-byte Schnorr signature encoded as hex.
- The signed message is the raw UTF-8 `kbeam-auth-v1` challenge message.
- The verifier derives a Kaspa address from the x-only public key.
- The derived address must match the challenge address.
- The Schnorr signature must verify for the exact challenge message bytes.

## Address Derivation

For `mainnet`, the address prefix is `kaspa`.

For `testnet`, the address prefix is `kaspatest`.

The public-key payload is encoded as Kaspa address type `0`, followed by the
32-byte x-only key and the Kaspa checksum.

## Error Codes

- `public_key_required`
- `public_key_invalid_hex`
- `public_key_invalid_length`
- `signature_invalid_hex`
- `signature_invalid_length`
- `address_does_not_match_public_key`
- `auth_signature_invalid`
- `auth_challenge_address_mismatch`
- `unsupported_network`

## Demo Mode

`KBEAM_AUTH_SIGNATURE_VERIFIER_MODE=demo` remains available for local flow
tests. It accepts only the synthetic signature `demo:<challengeId>` and must not
be used for production.
