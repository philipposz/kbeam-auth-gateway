# Same Device Demo Login 2026-05-02

## Purpose

The demo page supports same-device login for mobile browsers. The first login
ticket is created automatically when the page opens. The `Unlock with KBeam`
button opens the ticket's
`kbeam://pos-login` URL and appends:

```text
returnTo=<current demo URL>
```

KBeam can use that value to return to the browser after the wallet approval.

## Browser Behavior

- The QR code remains suitable for cross-device login.
- The first QR code is created on page load so visitors can scan immediately.
- The same-device button adds `returnTo` only to the opened app URL.
- The demo continues to listen via SSE.
- When the browser becomes visible or focused again, it polls the ticket once
  immediately. This covers mobile browsers that pause SSE while KBeam is in the
  foreground.
- The redesigned demo keeps a large visible success state so a returned browser
  clearly shows that the protected area was unlocked.
- The success state includes a local logout button for clearing the demo
  session after testing.
- The demo includes a share action for X that opens `https://x.com/kbeam_app?s=21`.
- The top navigation uses the public KBeam logo copied into this repository as
  `src/kbeam_auth_gateway/static/kbeam-logo.png`.

## Compatibility

The KBeam app must allow the demo URL as a valid `returnTo` target. If the app
does not allow that host yet, approval can still succeed, but the automatic
return to the demo page will not happen.

## Rollback

1. Remove the `openKbeam` button from `src/kbeam_auth_gateway/static/index.html`.
2. Remove the automatic `startDeviceLogin({ silent: true })` call at the end of
   the demo script.
3. Remove `appendDeviceLoginReturnTo` and the focus/visibility polling hooks.
4. Restore `approveUrl.value` to show the raw ticket `approveURL`.
5. Remove the logo asset route and `src/kbeam_auth_gateway/static/kbeam-logo.png`
   if the text-only brand mark should be restored.
6. Run the test suite and redeploy.
