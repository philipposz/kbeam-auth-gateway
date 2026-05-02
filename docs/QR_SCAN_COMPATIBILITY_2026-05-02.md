# QR Scan Compatibility 2026-05-02

The demo QR code points to a KBeam app URL:

```text
kbeam://pos-login?t=<ticketId>&a=<approveToken>&api=<apiBase>&service=<serviceSlug>
```

KBeam uses that URL to call
`POST /api/auth/device-login/{ticketId}/challenge`, signs the returned challenge
with `rawUTF8`, and then calls
`POST /api/auth/device-login/{ticketId}/approve`.

The JSON response still includes `webApproveURL` for browser diagnostics and
manual fallback.

Normal phone camera apps open QR URLs with `GET`. Previously that produced a
`405 Method Not Allowed` response because only `POST` existed. The gateway now
also serves a small HTML status page for `GET` on the web fallback URL. This
keeps casual QR scans understandable while allowing the KBeam app to use the
native login protocol.

The generated QR SVG now includes an explicit white background rectangle, and
the demo keeps the QR preview on a white surface in dark mode.

## Rollback

Restore `approveURL` to the HTTPS challenge URL, remove the
`GET /api/auth/device-login/{ticketId}/challenge` handler if the browser fallback
is not needed, remove the white SVG background insertion in `qr.py`, and restore
the previous demo CSS.
