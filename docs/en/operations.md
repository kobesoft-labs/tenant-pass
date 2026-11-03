# Operations

[日本語](../ja/operations.md)

## Deployment

- Run **two or more replicas** behind a load balancer on an **internal** network. Only applications (and your monitoring) should be able to reach it.
- Use the container image (distroless, non-root, no shell), with a **read-only root filesystem**, no added capabilities, and secrets mounted as files (Docker/Swarm secrets, Kubernetes secrets, systemd credentials).
- All replicas need identical `rotation`, `nodes[].name` and directory settings. Roll out configuration changes to all replicas.
- Clocks must be synchronized (NTP). Skew must be far below `renew_before` (seconds, not minutes).
- Health checks: liveness `GET /healthz`, readiness `GET /readyz`.
- Stop grace period above `shutdown.drain + shutdown.timeout` (default 20 s).

Example (Docker Compose):

```yaml
services:
  tenant-pass:
    image: ghcr.io/kobesoft-labs/tenant-pass:<version>
    command: ["serve", "-config", "/etc/tenant-pass/config.json"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 20s
    volumes:
      - ./config.json:/etc/tenant-pass/config.json:ro
    secrets: [tenant-pass.key, rotation-2026-11, pg1-admin-password]
```

## Bootstrapping

1. Provision the stores' admin accounts and marker roles ([PostgreSQL](stores/postgres.md), [MySQL](stores/mysql.md), [Redis](stores/redis.md)).
2. `tenant-pass gen-rotation-key -out rotation-YYYY-MM` — distribute to tenant-pass replicas only.
3. `tenant-pass gen-gateway-key …` — private key to the gateway, public key to tenant-pass.
4. `tenant-pass gen-app-token` for each application — token to the application's secret store, hash into the config.
5. `tenant-pass check-config -config config.json -connect`.
6. Start tenant-pass, then switch applications over tenant by tenant. On first use, tenant-pass replaces each account's existing password; remove the old stored passwords from your systems afterwards.

## Rotation key rotation

Keys carry `not_before`, so all replicas switch at the same window without coordination.

1. `tenant-pass gen-rotation-key -out rotation-2026-12`.
2. Add it to every replica with `not_before` comfortably after the rollout finishes (for example tomorrow 03:00 UTC):
   ```json
   "keys": [
     {"id": "r-2026-11", "secret_file": "/run/secrets/rotation-2026-11", "not_before": "2026-11-01T00:00:00Z"},
     {"id": "r-2026-12", "secret_file": "/run/secrets/rotation-2026-12", "not_before": "2026-12-01T03:00:00Z"}
   ]
   ```
3. From `not_before`, every window that **starts** at or after it uses the new key. Nothing else happens.
4. After `not_before + window + renew_before`, remove the old key and roll out again.

Never change a key's `id` or secret in place: every replica must agree on which key a window uses. Adding a key whose `not_before` lies in the future is safe during a rolling update, because no replica uses it before then; make sure the rollout finishes before `not_before`.

**Emergency (key exposed):** add a new key with `not_before` = now + rollout time, roll out, then remove the old key. Passwords derived from the old key stop working when their windows end (PostgreSQL), or when the next issuance or sweep replaces them (MySQL, Redis). For an immediate cut-off on PostgreSQL, `ALTER ROLE … VALID UNTIL 'now'` on affected roles (clients will refetch).

## Changing the window

Changing `rotation.window` changes every account's window numbering and offset. During a rolling update, old and new replicas disagree and overwrite each other's settings ("unmanaged" boundaries). Change it with a short full stop: stop all replicas, deploy, start. Clients will refetch once.

## Monitoring

All events are JSON lines on stdout. Useful alerts:

| Condition | Meaning |
| --- | --- |
| `msg=credential` and `reason=account_refused` | The directory points at an account the store refuses (privileged, unmanaged, missing). Investigate immediately: misconfiguration or an attack on the directory. |
| `reason=pass_signature` or `pass_unknown_key` | Forged passes, or a gateway with a key tenant-pass does not know. |
| `reason=pass_audience` | An application presented a pass meant for another application. |
| `reason=distinct_tenants` (429) | An application is touching unusually many tenants. Possible compromise. |
| `reason=clock_skew` | A replica's clock differs from a store server's clock by more than `max_clock_skew`. That replica refuses writes; fix NTP (on the replica or the database). |
| `reason=directory_error` / `store_error` / `timeout` | Backend problems. |
| `msg=sweep` at `ERROR` | MySQL/Redis sweeps failing: expired passwords are not being removed. |
| Rate of `result=ok` per `app` | Baseline per application; alert on deviations. |
| `/readyz` failing | Backend unreachable or replica draining. |

## Incident response

| Suspected compromise | Action |
| --- | --- |
| Application | Remove its `apps` entry (or replace its token hash) and roll out: it can no longer obtain credentials. Credentials it already holds expire within one window (MySQL/Redis: plus one sweep). Review `msg=credential` for that `app` to see which tenants it accessed. |
| Gateway key | Remove the key from `gateway_keys`, roll out, deploy a new key to the gateway. |
| Rotation key | See "Emergency" above. Also review store logs for logins from unexpected addresses. |
| tenant-pass host | Treat all tenants as exposed: rotate rotation keys, store admin passwords, the TLS key; review store logs. |
| Store admin password | Change it in the store and in the secret file; restart replicas. |

## Upgrades

Replicas of adjacent versions can run side by side unless release notes say otherwise. The derivation and pass format are versioned (`tenant-pass/v1`); a change would come with a new label and a migration path.
