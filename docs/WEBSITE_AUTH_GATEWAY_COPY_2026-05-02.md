# Website Auth Gateway copy

Date: 2026-05-02

## Change

An English explanatory section was added to the bottom of the demo page. It
describes:

- what KBeam Auth Gateway does
- why challenge-response login reduces password-related risk
- what KBeam does not see or control
- which security responsibilities remain with the website operator

The copy avoids absolute security promises. It explains the intended trust
boundary and makes clear that operators still need secure deployment practices.

## Verification

Run:

```bash
pytest
ruff check .
python tools/public_hygiene_check.py
git diff --check
```

Then open the demo and scroll to the bottom to confirm that the explanatory
section is readable and does not affect QR generation.

## Rollback

Revert the commit that introduced this document and the matching change in
`src/kbeam_auth_gateway/static/index.html`, then redeploy the previous release.
