# KBeam App Device Login Fix 2026-05-02

## Problem

The browser demo created a ticket and opened an SSE stream correctly, but the QR
code contained an HTTPS challenge URL. KBeam opened that URL with `GET`, so the
server showed the fallback page but never received the signed approval calls.
The ticket stayed `pending`, and the browser demo could not show the success
state.

Server evidence was:

- `POST /api/auth/device-login` returned `201`
- `GET /api/auth/device-login/{ticketId}/events` returned `200`
- KBeam scan produced `GET /api/auth/device-login/{ticketId}/challenge`
- no matching `POST /challenge` and no `POST /approve`

## Fix

- Device-login QR codes now use the KBeam-compatible URL format:

```text
kbeam://pos-login?t=<ticketId>&a=<approveToken>&api=<apiBase>&service=<serviceSlug>
```

- `webApproveURL` remains available for browser diagnostics.
- Challenge payloads include `organizationSlug` for KBeam decoder
  compatibility.
- Approve payloads include KBeam-compatible `session.organizationSlug`,
  `session.lastSeenAt`, and `auth` runtime fields.

## Rollback

1. Change ticket creation back to the HTTPS challenge URL in
   `src/kbeam_auth_gateway/app.py`.
2. Remove `webApproveURL` if clients should not see the fallback URL.
3. Remove the extra KBeam compatibility fields from challenge/session/approve
   responses.
4. Run tests and redeploy the previous release if needed.
