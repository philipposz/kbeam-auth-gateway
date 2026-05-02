# Demo Login Success 2026-05-02

The demo page now polls the device-login ticket automatically after a QR code is
created. When the KBeam app approves the ticket, the browser receives the
session cookie during polling and shows a visible `Login successful` status.

This does not require a separate demo app. The browser demo is the relying app
for this test flow, and the KBeam app remains the wallet signer.

## Rollback

Restore the previous demo page behavior by removing the automatic polling
helpers, the session success notice, and the initial `/api/auth/session` check
from `src/kbeam_auth_gateway/static/index.html`.
