# tenant-pass

**Short-lived, tenant-scoped database credentials, issued only for requests your gateway actually forwarded.**

[日本語版 README はこちら](README.ja.md)

tenant-pass is a small, stateless credential broker for multi-tenant applications whose tenants have their own database accounts — a PostgreSQL role, a MySQL user, or a Redis ACL user per tenant.

Applications do not hold any tenant's database password. When an application handles a request for a tenant, it asks tenant-pass for that tenant's credential, presenting:

1. its own identity (a bearer token and/or a TLS client certificate), and
2. a **pass**: a short-lived token, signed by your gateway, that says *"I am forwarding a request for tenant X to you, right now."*

tenant-pass verifies both, looks up the tenant, sets a fresh password on the tenant's account and returns it. The password expires on its own after a short window (15 minutes by default).

```
             request for acme.example.com
  client ───────────────────────────────▶ gateway ──── signs pass {aud: billing, host: acme.example.com, exp: +30s}
                                            │
                                            ▼ request + pass
                                      application "billing"
                                            │  POST /v1/credentials
                                            │  Authorization: Bearer <app token>
                                            │  {"pass": "v4.public..."}
                                            ▼
                                       tenant-pass ── directory: acme.example.com → node pg1, role t_acme
                                            │
                                            │  ALTER ROLE t_acme PASSWORD '<SCRAM verifier>' VALID UNTIL '…'
                                            ▼
                                     PostgreSQL / MySQL / Redis
```

## Why

In a typical multi-tenant application, the application can reach every tenant's data: it either connects with one powerful account, or it can decrypt every tenant's credentials from a central table. An attacker who takes over the application process gets **all tenants at once**.

With tenant-pass:

- **No stored tenant passwords.** The application has nothing to steal at rest. The rotation key that derives passwords lives only in tenant-pass.
- **Credentials only for real requests.** A compromised application cannot mint passes. It can only use passes for requests the gateway actually sent to it, and only within the pass's lifetime (seconds).
- **Bound to one application.** A pass names the application it was forwarded to (`aud`); another application cannot use it.
- **Rate-limited blast radius.** Each application can obtain credentials for only a limited number of *distinct* tenants per minute.
- **Expiry enforced by the database.** PostgreSQL rejects the password after `VALID UNTIL` even if tenant-pass is down. MySQL and Redis have no native expiry, so tenant-pass keeps at most two windows of passwords and sweeps expired ones.
- **No plaintext on the wire to the database.** tenant-pass sends SCRAM verifiers (PostgreSQL), `caching_sha2_password` hashes (MySQL) and SHA-256 ACL hashes (Redis). Passwords never appear in database logs, statement statistics or replication streams.
- **Refuses dangerous accounts.** tenant-pass changes only accounts explicitly marked as managed, and it never touches accounts with administrative or cross-tenant privileges — including privileges inherited through role membership — even if the directory points at them.
- **Trusts the database clock, not its own.** Before writing, every replica compares its clock with the store server's; a replica with a broken clock refuses instead of pushing passwords into the future.

This is not a general secrets manager. If you need dynamic credentials without request binding, look at HashiCorp Vault / OpenBao database secrets engines. tenant-pass covers one narrower case: **request-bound, per-tenant** access for multi-tenant SaaS.

## Features

| | PostgreSQL | MySQL | Redis / Valkey |
| --- | --- | --- | --- |
| Account | role | user | ACL user |
| Supported versions | 13+ (16+ strongly recommended) | 8.0.27+, 8.4, 9.x | Redis 7.0+, Valkey 7.2+ |
| What is sent | SCRAM-SHA-256 verifier | caching_sha2_password hash | SHA-256 ACL hash |
| Expiry | hard (`VALID UNTIL`) | soft (dual passwords + sweeper) | soft (multiple passwords + sweeper) |
| Rotation overlap | none (clients retry once) | old and new both valid | old and new both valid |
| "Managed" marker | membership in a group role | granted a marker role | marker channel rule |

- Stateless: run any number of replicas behind a load balancer. All replicas derive identical passwords.
- Tenant directory: static (in the config file) or your own SQL query on PostgreSQL or MySQL.
- Pass format: PASETO v4.public (Ed25519) with domain separation, so gateways can be written in any language with a PASETO library.
- Strict configuration: unknown keys, duplicate keys, weak keys, unverified TLS and world-writable secret files are all startup errors.
- Single static binary with a small dependency set (the database drivers).

## Quick start

> The steps below use plaintext connections and are for **local evaluation only**. See [docs/en/operations.md](docs/en/operations.md) for production.

```sh
go install github.com/kobesoft-labs/tenant-pass/cmd/tenant-pass@latest

# Gateway key pair (the private key belongs to the gateway only)
tenant-pass gen-gateway-key -private gw.key -public gw.pub

# Rotation key (tenant-pass only)
tenant-pass gen-rotation-key -out rotation.key

# Application token: give the token to the application, put the hash in the config
tenant-pass gen-app-token
```

Prepare a PostgreSQL role for one tenant ([full instructions](docs/en/stores/postgres.md)):

```sql
CREATE ROLE tenant_pass_admin LOGIN CREATEROLE PASSWORD '...';
CREATE ROLE tenant_pass_managed NOLOGIN;
CREATE ROLE t_acme LOGIN IN ROLE tenant_pass_managed;
GRANT t_acme TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

Write a configuration ([reference](docs/en/configuration.md), [example](examples/config.example.json)), then:

```sh
tenant-pass check-config -config config.json -connect
tenant-pass serve -config config.json

# Act as the gateway and the application:
PASS=$(tenant-pass sign-pass -key gw.key -kid gw1 -aud billing -host acme.example.com)
curl -s https://tenant-pass.internal:8443/v1/credentials \
  -H "Authorization: Bearer $APP_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"pass\":\"$PASS\"}"
```

```json
{
  "tenant": "acme", "store": "postgres",
  "host": "pgbouncer.internal", "port": 6432, "database": "app",
  "username": "t_acme", "password": "umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM",
  "expires_at": "2026-11-03T12:13:59Z", "refresh_at": "2026-11-03T12:08:59Z"
}
```

## Documentation

| Document | Contents |
| --- | --- |
| [Design](docs/en/design.md) | Components, request flow, rotation model, design decisions |
| [Threat model](docs/en/threat-model.md) | What tenant-pass protects against, and what it does not |
| [API](docs/en/api.md) | HTTP API reference |
| [Pass format](docs/en/pass-format.md) | Pass specification and test vectors, for gateway implementers |
| [Password derivation](docs/en/derivation.md) | Window and password derivation specification and test vectors |
| [Configuration](docs/en/configuration.md) | Every configuration key |
| [PostgreSQL](docs/en/stores/postgres.md) · [MySQL](docs/en/stores/mysql.md) · [Redis](docs/en/stores/redis.md) | Store setup with least privilege |
| [Gateway integration](docs/en/gateway-integration.md) | How to sign passes correctly |
| [Client integration](docs/en/client-integration.md) | How applications should fetch, cache and refresh credentials |
| [Operations](docs/en/operations.md) | Deployment, key rotation, monitoring, incident response |

## Status

tenant-pass is **pre-1.0**. The pass format and derivation are versioned (`tenant-pass/v1`) and covered by test vectors, but configuration and API details may still change. It has **not yet had an external security audit**. Please read the [threat model](docs/en/threat-model.md) before deploying it.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
