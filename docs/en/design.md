# Design

[日本語](../ja/design.md)

This document explains how tenant-pass works and why it is built the way it is. For what it does and does not protect against, see the [threat model](threat-model.md).

## Components

| Component | Holds | Role |
| --- | --- | --- |
| **Gateway** (`tenant-pass-gateway` behind your proxy, or your own component) | Gateway Ed25519 **private** key | Authenticates the end user's session for a tenant, then signs a short-lived pass naming the tenant and the application it forwards the request to. See [gateway.md](gateway.md). |
| **Job issuer** (optional, yours: a scheduler) | Issuer Ed25519 private key | Signs job tickets for scheduled work that no request starts. See [jobs.md](jobs.md). |
| **KMS** (optional: Vault / OpenBao) | Rotation and signing keys | Computes HMACs and signatures so keys never leave it. See [kms.md](kms.md). |
| **Application** (yours) | Its own app token (and/or client certificate) | Receives the request and the pass, exchanges the pass for a tenant credential, connects to the tenant's database. |
| **tenant-pass** | Gateway **public** keys, app token hashes, rotation keys, store admin credentials | Verifies the app and the pass, resolves the tenant, sets and returns the credential. |
| **Directory** (static config, or your PostgreSQL/MySQL) | Tenant → node, account, enabled, allowed apps | Source of truth for which account belongs to which tenant. |
| **Stores** (PostgreSQL, MySQL, Redis) | Tenant accounts | Enforce the passwords tenant-pass sets. |

The private gateway key and the rotation keys never meet: the gateway can sign passes but cannot derive passwords, and tenant-pass can derive passwords but cannot sign passes. An application has neither.

## Background jobs

Passes live for seconds. Work that runs later uses **job tickets**: PASETO tokens with a separate implicit assertion (`tenant-pass/v1/job`), always naming a tenant ID, living up to `job_tickets.max_ttl`. tenant-pass issues them in exchange for a pass (`POST /v1/job-tickets`, opt-in per application), and accepts tickets from trusted issuers you run (schedulers). Redemption goes through the same directory and store checks as passes, with a separate rate limit. Details: [jobs.md](jobs.md).

## Request flow

```
Application                         tenant-pass                                Directory        Store
    │ POST /v1/credentials               │                                          │               │
    │ Authorization: Bearer tpa_…        │                                          │               │
    │ {"pass": "v4.public.…"}  ─────────▶│ 1 method / path / content type           │               │
    │                                    │ 2 authenticate app → "billing"           │               │
    │                                    │ 3 parse body strictly (≤ 4 KiB)          │               │
    │                                    │ 4 verify pass: key ID → gateway key,     │               │
    │                                    │   signature, claims, lifetime,           │               │
    │                                    │   aud == "billing"                       │               │
    │                                    │ 5 distinct-tenant rate limit             │               │
    │                                    │ 6 lookup(host or tenant, app) ──────────▶│               │
    │                                    │   ◀── tenant_id, node, account, enabled  │               │
    │                                    │ 7 store.Issue(account) ─────────────────────────────────▶│
    │                                    │   lock → safety checks → read state →    │               │
    │                                    │   plan (forward-only) → write if needed  │               │
    │ ◀───────── credential ─────────────│ audit log (never secrets)                │               │
```

Every step fails closed. Clients receive a fixed error code (`invalid_pass`, `denied`, …), never the reason; the reason is written to the audit log.

## Passes

A pass is a [PASETO v4.public](https://github.com/paseto-standard/paseto-spec) token (Ed25519). The full specification is in [pass-format.md](pass-format.md). The main decisions:

- **PASETO instead of JWT.** v4.public has exactly one algorithm. There is no `alg` header to confuse, no `none`, no RSA/HMAC key confusion. tenant-pass accepts only `v4.public.`.
- **Implicit assertion `tenant-pass/v1/pass`.** It is signed but not transmitted. A token signed by the same key for any other purpose (another product, another version of tenant-pass) cannot be accepted as a pass.
- **Mandatory key ID in the footer.** The footer selects the gateway key, which makes gateway key rotation and multiple gateways possible. The footer is authenticated by the signature; before verification it is only used to choose a key.
- **Strict claims.** Exactly `aud`, `jti`, `iat`, `exp` and one of `host` / `tenant`. Unknown or duplicate claims are rejected (duplicate JSON keys are a known source of parser differentials between languages). Times are RFC 3339 UTC with whole seconds, so each instant has one textual form.
- **Short life.** `exp - iat` is at most `pass.max_ttl` (default 60 s, hard maximum 5 min).
- **Canonical host names only.** tenant-pass does not normalize host names; it rejects anything that is not lower-case ASCII without a port or trailing dot. Normalizing in two places (gateway and tenant-pass) would invite mismatches.
- **No replay cache.** A pass may be presented several times within its lifetime (a request handler may need to reconnect). It is bound to one application and expires within seconds, so replay by another party is not possible and replay by the same application gains nothing it did not already have.

## Passwords and windows

tenant-pass runs as several identical replicas with no shared state. Two replicas asked for the same account at the same time must return the same password. Instead of coordinating, every replica derives the password from the same inputs:

```
password(n) = base64url(HMAC-SHA256(K, "tenant-pass/v1/password" || LP(store) || LP(node) || LP(account) || LP(key ID) || BE64(W) || BE64(n)))
```

- `n` is the **window** number. Windows are `rotation.window` long (default 15 min). Each account's windows are shifted by an offset derived from a hash of (store, node, account), so accounts do not all rotate at the same moment.
- `K` is the rotation key in force at the start of window `n`. Keys carry a `not_before` time, so a new key can be distributed in advance and all replicas switch at the same window.
- The output is 256 bits from a PRF: as strong as a random password.

The exact specification and test vectors (generated by an independent Python implementation) are in [derivation.md](derivation.md).

### Renewal

When less than `rotation.renew_before` (default 5 min) remains in window `n`, tenant-pass already hands out window `n+1`. Every credential is therefore valid for at least `renew_before` when the client receives it. The response tells the client when to refresh (`refresh_at = End(n) − renew_before`).

### Forward-only

Clocks drift. A replica whose clock is slightly behind must never move an account back to an older window and break the clients that already received the newer password. tenant-pass reads the account's current state *under a lock* and applies these rules:

- Already at the target window → reuse it (no write).
- Already at the next window (another replica's clock is slightly ahead) → hand out that one; never move back.
- Older, unknown or unmanaged state → write the target window.
- Two or more windows ahead → treated as unmanaged and overwritten. Leaving it would keep a password valid far into the future.

The last rule is safe because of a separate guard: **before writing, every replica compares its own clock with the store server's clock** (PostgreSQL `clock_timestamp()`, MySQL `NOW(6)`, Redis `TIME`), read in the same round trip. If they differ by more than `rotation.max_clock_skew` (default 10 s), the replica refuses with `clock_skew`. A replica whose clock jumped (failed NTP, restored VM snapshot) therefore cannot move accounts into the future or the past; only replicas that agree with the database write.

tenant-pass recognizes its own state without storing anything: in PostgreSQL by the exact `VALID UNTIL` boundary, in MySQL and Redis by recomputing the candidate hashes and comparing.

## Store models

### Hard expiry: PostgreSQL

A role has one password. tenant-pass sets `PASSWORD '<SCRAM verifier>' VALID UNTIL '<End(n)>'`. PostgreSQL itself refuses the password after `End(n)`, even if tenant-pass is unavailable. Existing connections are unaffected by password changes and expiry.

Because there is only one password, the switch from `n` to `n+1` (at the start of the renewal phase) invalidates `n` for *new* connections immediately. Clients must retry once on authentication failure (SQLSTATE `28P01`) by fetching a new credential. See [client-integration.md](client-integration.md).

### Soft expiry: MySQL and Redis

Neither has a password expiry time, but both can hold two passwords at once (MySQL dual passwords; Redis ACL users can have several). tenant-pass keeps:

- in the normal phase: the password of window `n`;
- in the renewal phase: windows `n` and `n+1`.

Old and new credentials both work during renewal, so there is no authentication-failure race. A background **sweeper** (every `rotation.sweep_interval`, default 30 s, jittered) removes passwords whose window has ended, and removes any password tenant-pass did not derive. An account nobody requested for a whole window ends up with no usable password at all. A password can therefore outlive `expires_at` by up to one sweep interval (plus the time tenant-pass is down, if it is down).

## Safety checks on accounts

tenant-pass resets passwords. Pointed at the wrong account, that is dangerous. So in addition to the directory, every store checks the account itself, under the same lock as the write:

| | PostgreSQL | MySQL | Redis |
| --- | --- | --- | --- |
| Name matches `account_pattern` (anchored regex) | ✓ | ✓ | ✓ |
| Account exists (never created) | ✓ | ✓ | ✓ |
| Marked as managed | member of `managed_group` | granted `managed_role` (and no other role) | carries the channel rule `&tenant-pass:managed` |
| No administrative privileges | none of SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS — directly **or through any ancestor role** | no global privilege at all (every `*_priv` column), no dynamic privilege, nothing on `mysql`/`sys`/`performance_schema`, no PROXY — for the account **and** the managed role | `ACL DRYRUN` proves it cannot run administrative commands (ACL, CONFIG, MODULE, FLUSHALL, FUNCTION LOAD, …) through any category or selector |
| No cross-tenant reach | not a member of predefined `pg_*` roles (e.g. `pg_read_all_data`) or of login roles; no ADMIN OPTION | (global privileges refused) | `ACL DRYRUN` proves it cannot access a random key or channel (`~*`, `&*`) |
| Not tenant-pass's own admin account | ✓ | ✓ | (marker) |

A refused account yields `403 denied` to the client and an `account_refused` error in the audit log, which should be alerted on.

The checks are deliberately strict about **administrative and server-wide** privileges: anything that reaches beyond one account's own objects at the server level (superuser-like attributes, predefined roles, global grants, wildcard database grants, unrestricted key patterns) is refused rather than evaluated.

For MySQL the system schemas are `mysql`, `sys`, `performance_schema` and `information_schema`; for Redis, key and channel patterns must start with a literal prefix.

What the checks cannot see in general is a grant on **another tenant's** objects (for example `GRANT SELECT ON acme.invoices TO t_beta`, or a NOLOGIN group that owns shared tables). Keeping each tenant's privileges to its own database, schema, tables or key prefix is the job of your provisioning, and tenant-pass relies on it.

## Statelessness and replicas

All replicas need the same configuration (rotation keys, window, renew_before, node names). Nothing else is shared:

- Concurrency on one account is serialized by the store (PostgreSQL `pg_advisory_xact_lock`, MySQL `GET_LOCK`) and, inside a replica, by an in-process lock. Redis updates are idempotent.
- The distinct-tenant rate limit and the repair rate limit are per replica. With N replicas the effective limits are up to N times higher.
- Restarting a replica loses nothing.

## What tenant-pass does not do

- It does not create, delete or grant anything. Provisioning tenants and their accounts is your job (and should be a separate, more privileged process).
- It does not proxy database traffic.
- It does not authenticate end users. The gateway does.
- It does not store credentials.
