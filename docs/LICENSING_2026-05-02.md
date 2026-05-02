# Licensing 2026-05-02

## Summary

KBeam Auth Gateway is licensed under the `KBeam Auth Gateway Source Available
Compatibility License 1.0`.

The license allows users to use, host, integrate, modify, and distribute the
gateway, including in commercial and non-commercial protected areas. The central
condition is that the KBeam-compatible login path must remain working wherever
the gateway's login flow is used.

## Why This Is Source Available

The license is intentionally not described as OSI-approved open source. The
Open Source Definition expects licenses to avoid restrictions that tie use to a
specific product or technology. This project needs a compatibility requirement:
forks and deployments that use the gateway login flow must keep the KBeam
unlock path available.

For package metadata, the project uses the custom SPDX-style identifier:

```text
LicenseRef-KBeam-Auth-Gateway-1.0
```

External references used for this classification:

- Open Source Initiative, Open Source Definition:
  `https://opensource.org/osd`
- SPDX license expressions and custom `LicenseRef` identifiers:
  `https://spdx.github.io/spdx-spec/v2.2.2/SPDX-license-expressions/`

## Compatibility Terms

The protected compatibility identifiers are:

- `KBeam login`
- `kbeam-auth-v1`
- `kbeam://pos-login`
- KBeam auth identifiers beginning with `KBEAM` or `kbeam` when they are used to
  preserve KBeam auth compatibility

Integrators may add other login methods, wallet providers, policies, routes, UI,
storage systems, and authorization rules. They may not remove or break the
working KBeam-compatible login path.

## Licensor Data Source

The public gateway repository must be understandable without access to the
private KBeam repository. For that reason, the relevant licensor data has been
copied into `NOTICE`.

The source records in the private KBeam repository state:

- The KBeam repository license identifies Philippos Zachiridis as copyright
  holder for KBeam additions, branding, and current product work.
- The KBeam legal pages identify the responsible provider as:

```text
Philippos Zachiridis
Vivaldistr. 4
72124 Pliezhausen
Germany
Phone: +49 151 23030931
Email: support@kbeam.app
```

These details are included so users of this public repository do not need
access to the private KBeam repository to identify the licensor.

## Rollback

To rollback this licensing change:

1. Restore the previous `pyproject.toml` license text.
2. Remove `LICENSE`.
3. Remove `NOTICE`.
4. Remove this document.
5. Remove the README license section added with this change.
