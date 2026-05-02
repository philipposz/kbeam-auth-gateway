# Nginx Auth Request Integration

Use nginx `auth_request` when an existing application should be protected
without embedding KBeam login logic into that application.

## Flow

```text
Browser -> nginx -> /_kbeam_auth -> Gateway /api/auth/validate
```

If the gateway returns `204`, nginx serves the protected application. If the
gateway returns `401`, nginx redirects to the gateway demo/login route.

## Example

See:

```text
deploy/nginx/example-app.conf
```

The example intentionally uses only `example.com` and generic localhost ports.
Replace those values in deployment-specific configuration outside this public
repository.

## Rollback

1. Remove or disable `auth_request /_kbeam_auth`.
2. Restore the application's previous auth route or access control.
3. Reload nginx.
4. Stop the gateway if it is no longer used.
