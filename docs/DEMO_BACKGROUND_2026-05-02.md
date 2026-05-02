# Demo background update

Date: 2026-05-02

## Change

The demo page background was aligned more closely with the public KBeam website
style:

- dark KBeam base color
- soft green edge glow
- no checker or grid pattern
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
load and the background no longer shows checker lines.

## Rollback

Revert the commit that introduced this document, redeploy the previous release,
and restart the `kbeam-auth-gateway-test` service.
