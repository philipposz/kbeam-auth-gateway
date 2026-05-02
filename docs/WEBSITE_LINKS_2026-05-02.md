# Website and repository links

Date: 2026-05-02

## Change

The README now links to the hosted demo:

`https://kbeam.app/auth-gateway-test/`

The demo page navigation now links back to:

- the GitHub repository
- the KBeam TestFlight page

The links use compact inline SVG symbols so the page remains self-contained and
does not depend on a third-party icon package at runtime.

## Verification

Run:

```bash
pytest
ruff check .
python tools/public_hygiene_check.py
git diff --check
```

Then open the demo and verify that the GitHub and TestFlight buttons are visible
in the top navigation and open in a new browser tab.

## Rollback

Revert the commit that introduced this document, the README live-demo link, and
the matching changes in `src/kbeam_auth_gateway/static/index.html`, then deploy
the previous release.
