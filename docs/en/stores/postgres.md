# PostgreSQL

[日本語](../../ja/stores/postgres.md)

## How it works

Each tenant is a `LOGIN` role. For window `n`, tenant-pass runs, inside a transaction holding `pg_advisory_xact_lock`:

```sql
ALTER ROLE "t_acme" PASSWORD 'SCRAM-SHA-256$4096:…' VALID UNTIL '2026-11-03 12:13:59+00';
```

- Only the SCRAM-SHA-256 verifier is sent; the plaintext password never reaches the server.
- PostgreSQL enforces `VALID UNTIL` itself: after it, the password opens no new connections, even if tenant-pass is down.
- Existing connections are not affected by the change or the expiry.
- A role has one password, so when tenant-pass switches to the next window (from `refresh_at`, possibly a few seconds earlier when another replica's clock is slightly ahead), the previous password stops working for new connections **even though its `expires_at` has not been reached**. Treat `refresh_at` as the practical end of a PostgreSQL credential and retry once on `28P01` (see [client integration](../client-integration.md)).

## Supported versions

PostgreSQL **16 or later** (enforced at runtime). PostgreSQL 16 changed `CREATEROLE` so that it only applies to roles the admin has `ADMIN OPTION` on. Before 16, a `CREATEROLE` role can change the password of any non-superuser role, and a role may grant membership in itself to others, so one tenant could make another tenant's role fail tenant-pass's membership checks.

`password_encryption` must be `scram-sha-256` (the default since 14) and `pg_hba.conf` must use `scram-sha-256` for tenant roles.

## Setup (PostgreSQL 16+)

Run as a superuser (or your provisioning role):

```sql
-- tenant-pass's own database. tenant-pass serializes work on each role
-- with advisory locks, which are scoped to one database: if tenants could
-- connect to it, any tenant could hold another tenant's lock and block its
-- rotation. tenant-pass refuses to work in a database that PUBLIC or any
-- managed role may connect to.
CREATE DATABASE tenant_pass;
REVOKE ALL ON DATABASE tenant_pass FROM PUBLIC;

-- The account tenant-pass logs in as.
CREATE ROLE tenant_pass_admin LOGIN CREATEROLE PASSWORD '<random>';
GRANT CONNECT ON DATABASE tenant_pass TO tenant_pass_admin;

-- Marker: tenant-pass only touches members of this role.
CREATE ROLE tenant_pass_managed NOLOGIN;
```

For each tenant (your provisioning process does this):

```sql
CREATE ROLE t_acme LOGIN IN ROLE tenant_pass_managed;
-- Let tenant-pass change t_acme's password, without being able to act as t_acme:
GRANT t_acme TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
-- Then grant t_acme what the tenant needs, e.g.:
-- CREATE SCHEMA acme AUTHORIZATION t_acme;
```

Notes:

- If `tenant_pass_admin` itself creates the tenant roles, PostgreSQL 16+ grants it `ADMIN OPTION` automatically (with `INHERIT`/`SET` depending on `createrole_self_grant`; keep that setting empty).
- `INHERIT FALSE, SET FALSE` keeps `tenant_pass_admin` from using the tenant's privileges **by default**. It is not a hard boundary: holding `ADMIN OPTION`, the admin could re-grant the role to itself with `SET TRUE`. tenant-pass never does this, but whoever controls the `tenant_pass_admin` login can. Protect that account accordingly.
- Do not give tenant roles `SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION` or `BYPASSRLS`; tenant-pass refuses such roles anyway.
- Connect tenant-pass directly to PostgreSQL, not through a transaction pooler.

Server TLS: configure `ssl = on` with a certificate whose SAN matches the address tenant-pass uses (or set `tls.server_name`), and put the CA in `tls.ca_file`.

## Safety checks

Under the advisory lock, before any change, tenant-pass reads `pg_roles` / `pg_auth_members` and refuses (audit `account_refused`) unless:

- the role name matches `account_pattern`;
- the role exists, has `LOGIN`;
- it is a member of `managed_group` (`pg_has_role(role, group, 'MEMBER')`);
- it has none of `SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`;
- no role it is a member of, directly or indirectly, has any of those attributes, is a predefined `pg_*` role (`pg_read_all_data`, `pg_write_server_files`, `pg_execute_server_program`, …), or can log in;
- neither it nor any role it is a member of holds `ADMIN OPTION` on any role;
- it is neither `managed_group` itself nor tenant-pass's own login role.

It also compares its clock with the server's `clock_timestamp()` and refuses to write when they differ by more than `rotation.max_clock_skew`, and it refuses to work at all unless the server is PostgreSQL 16+ and the admin connection's database cannot be connected to by PUBLIC or by any managed role. The isolation check runs at readiness/`check-config -connect` and is repeated at least every 5 minutes, so a later `GRANT CONNECT` is noticed.

**Connection exhaustion.** Tenants share the server's `max_connections`. If tenants can use them all, tenant-pass cannot rotate passwords and every tenant's password eventually expires. Set per-role limits (`ALTER ROLE t_acme CONNECTION LIMIT 20`) and reserve connections for the admin: `reserved_connections = 5` and `GRANT pg_use_reserved_connections TO tenant_pass_admin` (PostgreSQL 16+).

Grant tenant roles privileges on their own objects (or through NOLOGIN group roles without special attributes); anything broader is refused.

## Node configuration

```json
{
  "name": "pg1",
  "type": "postgres",
  "endpoint": {
    "address": "pg1.internal:5432",
    "user": "tenant_pass_admin",
    "password_file": "/run/secrets/pg1-admin-password",
    "database": "tenant_pass",
    "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}
  },
  "managed_group": "tenant_pass_managed",
  "account_pattern": "^t_[a-z0-9_]{1,40}$",
  "connect": {"host": "pgbouncer.internal", "port": 6432, "database": "app"}
}
```

## PgBouncer

Clients may connect through PgBouncer. Requirements:

- Use `auth_type = scram-sha-256` with `auth_query` (looking up `pg_shadow` through a `SECURITY DEFINER` function), **not** a static `userlist.txt`. PgBouncer then always checks against the current verifier.
- Keep `server_reset_query = DISCARD ALL`.
- Already-open server connections keep working after rotation.

## State recognition

tenant-pass recognizes the window it set from `rolvaliduntil`: it only ever sets an exact window boundary of that role. `NULL`, `infinity` or any other value means "not managed yet" and is overwritten. If a password is changed by hand while `VALID UNTIL` is left alone, clients get `28P01`, retry with `repair: true`, and tenant-pass rewrites the (identical) verifier.

## Logging

Even though only verifiers are sent, consider `ALTER ROLE tenant_pass_admin SET log_statement = 'none'` (requires superuser) so that DDL from tenant-pass is not logged.
