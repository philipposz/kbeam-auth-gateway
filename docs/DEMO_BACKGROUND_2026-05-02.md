# Demo background wallpaper update

Date: 2026-05-02

## Change

The demo page background was aligned with the public KBeam website wallpaper
pattern:

- the existing demo background colors remain unchanged
- very low-opacity floating KBeam/Kaspa-style icons
- the same icon positions and rough animation behavior as the public website
- no external runtime asset dependency

Only `src/kbeam_auth_gateway/static/index.html` was changed for runtime behavior.

## Verification

Run:

```bash
pytest
ruff check .
python tools/public_hygiene_check.py
git diff --check
```

Then open the demo root and confirm that a QR code is still generated on first
load and the background shows the floating icon wallpaper.

## Rollback

Revert the commit that introduced this document, redeploy the previous release,
and restart the `kbeam-auth-gateway-test` service.
