# Rollback Notes

The gateway should be introduced so every protected application can return to
its previous authentication flow without code loss.

## During Early Integration

Keep the existing app-specific auth route available while testing the gateway.
Route only a narrow test environment through the gateway first.

Rollback:

1. Point the reverse proxy or application config back to the previous auth
   route.
2. Stop the gateway process or container.
3. Reload the reverse proxy.
4. Clear gateway session cookies if users remain stuck in stale sessions.
5. Record what changed and which verification failed.

## Public Repository Rollback

If private information is accidentally committed:

1. Stop pushing immediately.
2. Identify the affected commit and files.
3. Rotate any exposed secrets, even if the repository was private at the time.
4. Remove the sensitive content from the branch before further work.
5. Decide separately whether history rewrite is required.

## Runtime Rollback Requirements

Every deployment example should make these controls explicit:

- how to disable gateway routing
- how to restart or stop the gateway
- how to reload the reverse proxy
- which cookies may need clearing
- which healthcheck confirms the rollback state

