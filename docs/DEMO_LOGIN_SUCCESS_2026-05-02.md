# Demo Login Success 2026-05-02

The demo page now subscribes to device-login ticket events with Server-Sent
Events after a QR code is created. When SSE is unavailable, it falls back to
polling with backoff. When the KBeam app approves the ticket, the browser makes
one poll request to receive the session cookie and shows a visible
`Login successful` status.

This does not require a separate demo app. The browser demo is the relying app
for this test flow, and the KBeam app remains the wallet signer.

## Rollback

Restore the previous demo page behavior by removing the automatic polling
helpers, the session success notice, and the initial `/api/auth/session` check
from `src/kbeam_auth_gateway/static/index.html`.
