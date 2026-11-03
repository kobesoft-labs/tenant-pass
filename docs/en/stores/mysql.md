# MySQL

[日本語](../../ja/stores/mysql.md)

## How it works

Each tenant is a MySQL account `'t_acme'@'%'` using `caching_sha2_password`. MySQL has no per-password expiry, but since 8.0.14 an account can hold two passwords ("dual passwords"). tenant-pass uses them as two slots:

| Phase | Primary | Secondary |
| --- | --- | --- |
| Normal | window `n` | — |
| Renewal (from `refresh_at`) | window `n+1` | window `n` |
| After `End(n)` (sweeper) | window `n+1` | — |

The statements are, under `GET_LOCK`:

```sql
ALTER USER 't_acme'@'%' IDENTIFIED WITH caching_sha2_password AS 0x2441243030352…;              -- set primary
ALTER USER 't_acme'@'%' IDENTIFIED WITH caching_sha2_password AS 0x…  RETAIN CURRENT PASSWORD;  -- rotate
ALTER USER 't_acme'@'%' DISCARD OLD PASSWORD;                                                   -- drop secondary
```

- tenant-pass computes the `caching_sha2_password` hash itself (SHA-crypt with a 20-byte salt, 5000 rounds) and sends it as a hex literal. The plaintext never reaches the server, the binary log, the general log or performance_schema.
- During renewal, both credentials work, so clients do not see authentication failures from rotation.
- The **sweeper** (every `rotation.sweep_interval`) removes passwords whose window has ended. An account not requested for a whole window ends up with a random password nobody knows.
- Passwords not derived by tenant-pass (for example the initial password your provisioning set) are removed on first use.

## Supported versions

MySQL 8.0.27+, 8.4 LTS, 9.x. (Tested with 8.4.) MariaDB is not supported (different authentication plugins and no dual passwords).

## Setup

Run as an administrative user:

```sql
-- Marker role: tenant-pass only touches accounts granted this role.
CREATE ROLE tenant_pass_managed;

-- The account tenant-pass logs in as.
CREATE USER tenant_pass_admin IDENTIFIED BY '<random>' REQUIRE SSL;
GRANT CREATE USER ON *.* TO tenant_pass_admin;            -- needed for ALTER USER on other accounts
GRANT SELECT ON mysql.user TO tenant_pass_admin;          -- read authentication_string / privileges
GRANT SELECT ON mysql.global_grants TO tenant_pass_admin; -- check dynamic privileges
GRANT SELECT ON mysql.role_edges TO tenant_pass_admin;    -- check roles
GRANT SELECT ON mysql.db TO tenant_pass_admin;            -- check grants on system schemas
GRANT SELECT ON mysql.tables_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.columns_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.procs_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.proxies_priv TO tenant_pass_admin;  -- check proxy rights
```

The managed role must itself have no privileges (it is only a marker); give tenants their privileges directly or on their own databases.

For each tenant:

```sql
CREATE USER t_acme IDENTIFIED BY '<any initial password>';
GRANT tenant_pass_managed TO t_acme;
GRANT SELECT, INSERT, UPDATE, DELETE ON acme.* TO t_acme;   -- what the tenant needs
```

**About `CREATE USER`.** MySQL has no narrower privilege that allows changing another account's password. `CREATE USER` lets `tenant_pass_admin` alter any account that does not have `SYSTEM_USER`. Therefore:

- Make sure every administrative and application account that is not a tenant has `SYSTEM_USER` (MySQL 8.0.16+ gives it to `root` by default), or is otherwise out of reach.
- **Do not** give `tenant_pass_admin` `SYSTEM_USER`.
- tenant-pass's own safety checks (below) are a second line of defence, not the only one.

`mysql.user` contains the password hashes of all accounts. They are not usable for logging in, but allow offline guessing of weak human passwords. Treat the `tenant_pass_admin` credentials accordingly.

## Safety checks

Under the lock, tenant-pass refuses (audit `account_refused`) unless:

- the user name matches `account_pattern` and `[A-Za-z0-9_.%-]{1,64}`;
- `'user'@'account_host'` exists;
- `managed_role`@`managed_role_host` is granted to it, and **no other role** is;
- neither the account nor the managed role has **any global privilege** (every `*_priv` column of `mysql.user` must be `N` — even `SELECT ON *.*` reaches every tenant);
- neither has any dynamic privilege (`mysql.global_grants`, which includes `SYSTEM_USER`);
- neither has any privilege on the `mysql`, `sys`, `performance_schema` or `information_schema` schemas — including through wildcard database grants such as `` GRANT … ON `%`.* `` or `` `m_sql`.* `` (database names in `mysql.db` are patterns; tenant-pass tests the system schema names against them) — or PROXY rights;
- the managed role holds no privileges at all (it is only a marker);
- the managed role has no roles granted to it;
- the server's `mandatory_roles` is empty (mandatory roles apply to every account and cannot be checked per account);
- it is not tenant-pass's own account;
- the replica's clock agrees with the server's `NOW(6)` within `rotation.max_clock_skew`.

Tenant accounts are expected to have privileges on their own databases or tables only (`GRANT … ON acme.* TO t_acme`).

## Node configuration

```json
{
  "name": "my1",
  "type": "mysql",
  "endpoint": {
    "address": "my1.internal:3306",
    "user": "tenant_pass_admin",
    "password_file": "/run/secrets/my1-admin-password",
    "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}
  },
  "managed_role": "tenant_pass_managed",
  "account_host": "%",
  "account_pattern": "^t_[a-z0-9_]{1,30}$",
  "connect": {"host": "my1.internal", "port": 3306, "database": "app"}
}
```

TLS is required for the admin connection in practice: `caching_sha2_password` full authentication over an unencrypted connection needs RSA key exchange, which tenant-pass does not enable. MySQL's auto-generated certificates have no SAN for your host name; issue a proper server certificate.

## Replication

`ALTER USER` is replicated, so configure only the source as a node. Clients connecting to replicas see the change once it is applied there; replication lag adds to the time before a new password works on a replica.

## State recognition

tenant-pass reads `authentication_string` (primary) and `User_attributes.additional_password` (secondary) and recognizes its windows by recomputing the hash with the stored salt. It does not trust any metadata it did not compute.
