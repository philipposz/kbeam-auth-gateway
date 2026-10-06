# Shared authentication runtime

PostgreSQL stores for the same authentication authority share the database-wide
transaction lock. Ticket capacity, challenge replacement, approval or denial,
wallet changes and bootstrap participate in that lock. Keep separate application
authorities in separate databases. Backend selection, existing schema migration
and the default SQLite backend are unchanged.

Signature verification runs outside the transaction. Final approval rechecks the
exact challenge, current pending ticket, their binding and expiry, and the current
wallet permission after acquiring the lock. PostgreSQL reads `clock_timestamp()`
after waiting for the lock. Session insertion, ticket transition and challenge
consumption commit together. An expired session fails its direct lookup. The
challenge bytes, signature verifier, cookies, public API and per-process rate
limits retain their existing contracts. Event streams observe shared state on
their existing one-second polling interval.

After a PostgreSQL session is lost, the affected operation fails without any
SQL or commit retry. A later independent operation may reconnect using the
configured connection string, with a five-second timeout per address attempt,
and must select a writable primary. Reconnection never reruns schema migration
or bootstrap. A lost commit acknowledgement remains uncertain: inspect the
shared state before deciding on any new action. `/health` and `/api/health`
check the actual datastore tables and, for PostgreSQL, the writable-primary
binding; unavailable storage returns HTTP 503 with `ok: false`. Healthy responses
and the existing SQLite and memory backends retain their response format.

## Explicit state transfer

Stop writers for the selected source authority before the final export, and keep
the original database protected for rollback. This transfers one complete source;
it does not merge independent authorities. The bundle contains all five tables,
including approval/poll tokens, sessions, denial state, original timestamps and
audit records. Treat it as secret state: export uses exclusive creation with mode
`0600`; do not commit it or print its contents.

```sh
python tools/state_transfer.py sqlite-export --source-sqlite source.sqlite3 --bundle state.json
# Supply the target connection through KBEAM_AUTH_POSTGRES_DSN.
python tools/state_transfer.py import --bundle state.json --expected-sha256 EXPECTED_DIGEST
python tools/state_transfer.py export --bundle target-state.json
```

The reported SHA-256 is over the canonical bundle, rather than its formatted
file. Import validates that digest, requires all five target tables to be empty,
and checks a complete roundtrip inside the transaction. Source SQLite is opened
read-only, including support for the previous ticket schema without
`failure_reason`. Target constructors retain their existing schema migration.
There is no overwrite, reconciliation or automatic cutover.

Before rollback, stop target writers and export its current state. The explicit
rollback command only clears the five tables if their current digest still
matches the expected complete state:

```sh
python tools/state_transfer.py rollback --expected-sha256 EXPECTED_DIGEST \
  --confirmation 'ROLL BACK QUIESCED AUTH STATE'
```

If the digest differs, preserve both states and resolve the cutover decision
before retrying. Restore routing to the protected, still quiesced original only
after checking that no accepted target changes would be lost. No command silently
replaces a nonempty target.

## Verification

The shared-runtime tests accept `KBEAM_AUTH_TEST_CLUSTER_DSN` and
`KBEAM_AUTH_TEST_PGDATA` only for an explicitly owned disposable PostgreSQL cluster
with the synthetic `auth_synthetic` role and a `127.0.0.1` listener. Each test
creates and removes its own uniquely named database. Run them with the normal
repository CI checks; they are skipped when that explicit test cluster is absent.
