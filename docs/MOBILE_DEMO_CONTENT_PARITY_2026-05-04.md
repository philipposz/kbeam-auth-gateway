# Mobile Demo Content Parity 2026-05-04

## Change

The Auth Gateway demo mobile layout now keeps the same core content as the
desktop layout:

- headline and product message stay before the login panel
- QR/login panel remains high on the page
- main actions remain visible and full-width on mobile
- proof cards are retained instead of being visually minimized away
- a compact mobile trust summary repeats the key security message near the top
- the KBeam link field remains available on mobile
- desktop layout and colors remain unchanged

## Reason

The previous mobile breakpoint moved the login panel ahead of the product
message. That made the mobile page feel like a QR-only utility, while the
desktop version communicated the full Auth Gateway story.

## Verification

Run:

```bash
pytest
ruff check .
python tools/public_hygiene_check.py
git diff --check
```

Then open the demo in a narrow mobile viewport and verify that the first screen
contains the KBeam Auth Gateway message, wallet-login actions, and the QR/login
panel without hiding the proof and trust content from the page.

## Rollback

Restore the previous mobile CSS in `src/kbeam_auth_gateway/static/index.html`,
remove the `mobile-trust-strip` markup, and delete this document.
