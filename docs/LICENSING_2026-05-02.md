# Licensing 2026-05-02

## Summary

KBeam Auth Gateway is licensed under the `KBeam Auth Gateway Source Available
Compatibility License 1.1`.

The license allows users to use, host, integrate, modify, and distribute the
gateway, including in commercial and non-commercial protected areas. The central
condition is that the KBeam-compatible login path must remain working wherever
the gateway's login flow is used.

The technical compatibility requirements are kept outside the license text in
`KBEAM-COMPATIBILITY.md`. This keeps the license easier to read while preserving
the exact login identifiers and flow requirements needed for KBeam compatibility.

## Why This Is Source Available

The license is intentionally not described as OSI-approved open source. The
Open Source Definition expects licenses to avoid restrictions that tie use to a
specific product or technology. This project needs a compatibility requirement:
forks and deployments that use the gateway login flow must keep the KBeam
unlock path available.

For package metadata, the project uses the custom SPDX-style identifier:

```text
LicenseRef-KBeam-Auth-Gateway-1.1
```

External references used for this classification:

- Open Source Initiative, Open Source Definition:
  `https://opensource.org/osd`
- SPDX license expressions and custom `LicenseRef` identifiers:
  `https://spdx.github.io/spdx-spec/v2.2.2/SPDX-license-expressions/`

## Compatibility Terms

The protected compatibility identifiers are summarized in `LICENSE` and
specified in detail in `KBEAM-COMPATIBILITY.md`.

They currently include:

- `KBeam login`
- `kbeam-auth-v1`
- `kbeam://`
- KBeam auth identifiers beginning with `KBEAM` or `kbeam` when they are used to
  preserve KBeam auth compatibility

Integrators may add other login methods, wallet providers, policies, routes, UI,
storage systems, and authorization rules. They may not remove or break the
working KBeam-compatible login path.

The minimum compatibility requirements are summarized in the license and
expanded in `KBEAM-COMPATIBILITY.md`.

## Testing And Maintenance Duty

Forks, derivative works, modified versions, public deployments, redistributed
copies, hosted services, and substantial continuations that include or are
based on the KBeam-compatible login flow must test and maintain that flow.

Before public deployment or redistribution, and after material changes that
could affect login tickets, KBeam app links, challenge generation, signature
approval, waiting-browser status updates, session handoff, or protected-area
unlock behavior, integrators must run compatibility tests or equivalent
verification procedures sufficient to confirm that the KBeam-compatible login
flow still works.

If the KBeam-compatible login flow breaks in a public deployment or
redistributed version, the operator or distributor must make commercially
reasonable efforts to repair it, disable the broken public release until
repaired, or clearly withdraw the affected KBeam-compatible login claim. They
must not knowingly claim KBeam compatibility while the flow is non-functional.

## Preservation Requirement

Forks, derivative works, modified versions, redistributed copies, hosted source
releases, and substantial continuations based on this gateway must preserve:

- the `KBeam` name as the origin and compatibility identity
- the Licensor attribution and contact details from `NOTICE`
- the license name
- the protected compatibility identifiers
- the statement that KBeam-compatible login must remain available
- the KBeam compatibility specification or equivalent technical notice

Integrators may add their own attribution, product names, notices, and license
terms for their original additions, but those additions must not remove or hide
the KBeam Auth Gateway license notice or compatibility requirement.

Publicly accessible hosted deployments based on this gateway or the
KBeam-compatible login flow must make the license name, Licensor attribution,
compatibility notice, and protected compatibility identifiers reasonably
accessible, for example in a legal page, about page, documentation page, source
repository, admin documentation, or other normal notice location.

Additional license terms, service terms, technical measures, or downstream
restrictions must not remove, contradict, hide, disable, or override the KBeam
compatibility and notice-preservation requirements.

## Trademark Notice

The KBeam name, logo, icons, visual identity, trade dress, marketing copy, and
other brand assets are reserved by Philippos Zachiridis. Accurate compatibility
references are allowed as described in the license and `TRADEMARKS.md`, but the
license does not grant a general trademark, endorsement, certification,
partnership, or product naming license.

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

1. Restore `LICENSE` to the previous `KBeam Auth Gateway Source Available
   Compatibility License 1.0` text.
2. Restore the previous `NOTICE` text.
3. Remove `KBEAM-COMPATIBILITY.md`.
4. Restore `pyproject.toml` license text to
   `LicenseRef-KBeam-Auth-Gateway-1.0`.
5. Remove README references to `KBEAM-COMPATIBILITY.md` and restore the license
   name to version 1.0.
6. Restore this document to the previous version 1.0 licensing notes.
