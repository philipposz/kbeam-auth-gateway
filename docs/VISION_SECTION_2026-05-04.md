# Vision Section

## Change

The public demo page now includes a `Vision` section below the existing security
and trust explanation. The section describes the author's intended next stage in
plain English:

- optional user management connected to wallet-based login
- customer accounts controlled by the embedding website
- optional contact and support flows after login
- possible later product workflows such as payments

The same section is part of the responsive page, so mobile and desktop visitors
receive the same content.

The README now includes the same vision in repository documentation so the public
GitHub project explains the intended direction without implying that these
features are already part of the first release.

## Verification

Run:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python tools/public_hygiene_check.py
git diff --check
```

Then open the demo on desktop and mobile viewports and confirm that the `Vision`
section appears below `Security and trust`.

## Rollback

Revert the commit that introduced this document, the README `Vision` section,
and the matching `src/kbeam_auth_gateway/static/index.html` changes. Redeploy
the previous known-good release through the normal deployment process.
