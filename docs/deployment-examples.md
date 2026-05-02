# Deployment Examples

This repository includes generic deployment examples only.

## Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
curl -f http://127.0.0.1:18090/health
```

The Compose file binds the gateway to `127.0.0.1:18090` on the host and exposes
the service as `0.0.0.0:18090` inside the container.

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

## Healthcheck

```bash
curl -f http://127.0.0.1:18090/health
```

Expected result:

```json
{
  "ok": true
}
```
