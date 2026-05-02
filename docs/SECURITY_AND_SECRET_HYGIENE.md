# Security And Secret Hygiene

This repository is intended to become public. Treat every new file as if it may
be visible to outside reviewers later.

## Allowed

- Placeholder configuration values such as `example.com`
- `.env.example` files with clearly fake values
- Public protocol documentation
- Public nginx, Docker Compose, and systemd examples
- Threat models and generic recovery steps
- Test fixtures that cannot authenticate against real systems

## Never Commit

- Real API keys, tokens, passwords, private keys, certificates, wallet files, or
  productive `.env` files
- Host-specific infrastructure paths
- Internal recovery notes
- Private domain names
- Production configuration snippets
- Build artifacts, generated reports, test output, or temporary tool files

## Required Checks Before Commit

1. Run `git status --short --branch`.
2. Name the files that are intentionally included.
3. Inspect suspicious files for real secrets or production details.
4. Keep unrelated local changes out of the commit.
5. Run a secret scan before making the repository public.

## Public Release Gate

Before changing repository visibility to public:

- review all tracked files for private details
- run secret scanning
- verify examples use placeholder hosts only
- verify no generated artifacts are tracked
- verify protocol docs and security docs are complete enough for review
- verify CI passes
- verify native signature fixtures are synthetic and cannot authenticate against
  real services
