# Deployment Examples

This repository includes generic deployment examples only.

## Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
curl -f -H 'Host: auth.example.com' http://127.0.0.1:18090/ready
```

The Compose file binds the gateway to `127.0.0.1:18090` on the host and exposes
the service as `0.0.0.0:18090` inside the container.

Use `KBEAM_AUTH_WALLET_POLICY=allowlist` and set a long random
`KBEAM_AUTH_ADMIN_TOKEN` before exposing the gateway.

## systemd

Example unit:

```text
deploy/systemd/kbeam-auth-gateway.service.example
```

Example environment file path:

```text
/etc/kbeam-auth-gateway.env
```

The systemd example uses generic paths and should be copied into
deployment-specific infrastructure outside this repository.

The process user must be able to write to the directory containing
`KBEAM_AUTH_SQLITE_PATH`.

## Liveness and readiness

`/health` is the compatibility liveness response and deliberately keeps HTTP
200 while reporting component state. Deployment gates must use the fail-closed
readiness endpoint:

```bash
curl -f -H 'Host: auth.example.com' http://127.0.0.1:18090/ready
```

The `Host` value must be the exact authority configured in
`KBEAM_AUTH_TRUSTED_HOSTS`. The Compose probe derives it from the first trusted
authority, falling back to the authority in `KBEAM_AUTH_PUBLIC_BASE_URL`; it
does not broaden the runtime host allowlist for loopback traffic.

Expected result:

```json
{
  "ok": true
}
```

Before enabling retention against an existing durable database, select values
that satisfy the site's audit obligations and take a tested backup. Expiry
purges are irreversible; rollback restores code and configuration, not deleted
rows.
