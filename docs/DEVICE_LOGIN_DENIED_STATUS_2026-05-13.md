# Device Login Denied Status

Date: 2026-05-13

## Issue

When a wallet outside the allowlist attempted to approve a POS/device login, the gateway returned `auth_wallet_not_allowed` to the wallet app but left the device-login ticket in `pending`. The browser kept polling and therefore continued to show a waiting state instead of a clear denial.

## Change

- Device-login tickets can now expose an optional `failureReason`.
- A wallet rejected by the allowlist marks the ticket as `denied` with `failureReason=auth_wallet_not_allowed`.
- Polling clients can show a clear denial instead of waiting forever.
- The stale challenge is removed once the ticket is denied.

## Rollback

Revert the changes in:

- `src/kbeam_auth_gateway/app.py`
- `src/kbeam_auth_gateway/models.py`
- `src/kbeam_auth_gateway/store.py`
- `tests/test_auth_flow.py`
- `docs/DEVICE_LOGIN_DENIED_STATUS_2026-05-13.md`
