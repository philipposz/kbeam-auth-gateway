# QR Scan Compatibility 2026-05-02

The demo QR code points to the device-login challenge URL. Wallet clients use
that URL as the target for `POST /api/auth/device-login/{ticketId}/challenge`.

Normal phone camera apps open QR URLs with `GET`. Previously that produced a
`405 Method Not Allowed` response because only `POST` existed. The gateway now
also serves a small HTML status page for `GET` on the same URL. This keeps the
wallet protocol unchanged while making casual QR scans understandable.

The generated QR SVG now includes an explicit white background rectangle, and
the demo keeps the QR preview on a white surface in dark mode.

## Rollback

Remove the `GET /api/auth/device-login/{ticketId}/challenge` handler, remove the
white SVG background insertion in `qr.py`, and restore the previous demo CSS.
