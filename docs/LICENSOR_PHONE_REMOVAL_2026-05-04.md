# Licensor Phone Removal 2026-05-04

## Change

The public license and notice materials no longer include the licensor phone
number.

Affected files:

- `NOTICE`
- `docs/LICENSING_2026-05-02.md`

The licensor name, address, and public support email remain available for
identification and contact.

## Reason

The phone number is not required for the repository license notice. Removing it
reduces personal contact data in the public repository before changing
repository visibility.

## Verification

Run:

```bash
rg -n "<removed-phone-number>" NOTICE docs/LICENSING_2026-05-02.md
python tools/public_hygiene_check.py
pytest
ruff check .
git diff --check
```

The search should not find the removed number in public license or notice
materials.

## Rollback

Restore the previous `NOTICE` phone block and the previous `Phone:` line in
`docs/LICENSING_2026-05-02.md` if a phone contact is intentionally required
again.
