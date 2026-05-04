# Demo Unlock Button Update

## Change

The demo page button order and states were updated for desktop and mobile:

- `Unlock with KBeam` is now the first action button.
- `Start wallet login` is now the white secondary action beside it.
- `Unlock with KBeam` uses the KBeam mint color and pulses only when it is
  usable.
- The unlock button is enabled only while a fresh pending login ticket with a
  valid approve URL exists.
- On narrow mobile screens, the unlock and start buttons sit side by side, with
  logout below them.

## Verification

Run:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python tools/public_hygiene_check.py
git diff --check
```

Then open the demo in desktop and mobile viewports and verify that the unlock
button is disabled before ticket creation, active and pulsing for a fresh QR
ticket, and disabled again after success, logout, or expiry.

## Rollback

Revert the commit that introduced this document and the matching changes in
`src/kbeam_auth_gateway/static/index.html`. Redeploy the previous known-good
release through the normal deployment process.
