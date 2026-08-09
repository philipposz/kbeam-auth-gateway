# Context Map

Start with one task row and expand only when the affected behavior requires it.

| Task | Start here | Add only when needed |
|---|---|---|
| Purpose and local operation | [`README.md`](../README.md), [`pyproject.toml`](../pyproject.toml) | [CI workflow](../.github/workflows/ci.yml) |
| Licensed compatibility surface | [`KBEAM-COMPATIBILITY.md`](../KBEAM-COMPATIBILITY.md) | [`LICENSE`](../LICENSE), [`docs/protocol-v1.md`](protocol-v1.md) |
| Challenge construction and app flow | [`protocol.py`](../src/kbeam_auth_gateway/protocol.py) | [`app.py`](../src/kbeam_auth_gateway/app.py), [`tests/test_auth_flow.py`](../tests/test_auth_flow.py) |
| Signature or address verification | [`verifier.py`](../src/kbeam_auth_gateway/verifier.py) | [`docs/native-signature-verifier.md`](native-signature-verifier.md), verifier tests |
| Tickets, sessions, wallets, or audit | [`store.py`](../src/kbeam_auth_gateway/store.py), [`app.py`](../src/kbeam_auth_gateway/app.py) | [`config.py`](../src/kbeam_auth_gateway/config.py), affected flow tests |
| Public security and repository hygiene | [`SECURITY.md`](../SECURITY.md) | [`docs/SECURITY_AND_SECRET_HYGIENE.md`](SECURITY_AND_SECRET_HYGIENE.md), [`tools/public_hygiene_check.py`](../tools/public_hygiene_check.py) |
| Generic deployment or rollback | [`docs/deployment-examples.md`](deployment-examples.md) | [`compose.yaml`](../compose.yaml), [`docs/ROLLBACK.md`](ROLLBACK.md) |

Dated planning and demo documents provide historical context only. They do not authorize a current deployment or define private infrastructure.
