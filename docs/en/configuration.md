# Configuration

[日本語](../ja/configuration.md)

tenant-pass reads one JSON file (`-config`). A complete example is [examples/config.example.json](../../examples/config.example.json).

## Rules

- **Strict parsing.** Unknown keys, duplicate keys and trailing data are errors. A typo cannot silently disable a setting.
- **No secrets in the file.** Every secret is a path to a separate file (`*_file`). Secret files must be regular files, not writable by group or others, and **owned by the user tenant-pass runs as or by root** (another user could rewrite their own file regardless of its mode); a warning is logged if they are readable by group or others. A single trailing newline is removed.
- **Trust files too.** Public keys, CA bundles, certificates, JWKS files and the configuration file itself decide what is trusted, so they get the same integrity checks (mode and owner), without the readability warning.
- **Validated at startup.** Everything is checked before the server starts; any error stops startup, and all errors are reported together. `tenant-pass check-config -config FILE` runs the same checks, and `-connect` also connects to the directory and every node.
- **The config file itself** must not be writable by group or others.
- **Durations** are Go duration strings: `"30s"`, `"15m"`, `"1h"`.
- **Insecure modes need two switches.** Plaintext HTTP or plaintext store connections require the item's own `insecure_plaintext*` setting **and** the top-level `allow_insecure_plaintext: true`. Testing only.

## Top level

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `":8443"` | Listen address. |
| `tls` | required | Server TLS, see below. |
| `insecure_plaintext_http` | `false` | Serve plain HTTP. Requires `allow_insecure_plaintext`; cannot be combined with `tls`. |
| `allow_insecure_plaintext` | `false` | Global opt-in for any plaintext setting. Never in production. |
| `gateway_keys` | required | Trusted gateway public keys. |
| `pass` | | Pass verification settings. |
| `apps` | required | Applications allowed to call the API. |
| `directory` | required | Tenant directory: exactly one of `static` or `sql`. |
| `rotation` | required | Rotation keys and timing. |
| `kms` | | Key management system connection ([kms.md](kms.md)). |
| `job_tickets` | | Job tickets ([jobs.md](jobs.md)). |
| `nodes` | required | Stores tenant-pass manages. |
| `limits` | | Request limits. |
| `shutdown` | | Graceful shutdown timing. |
| `log_level` | `"info"` | `debug`, `info`, `warn`, `error`. |

## `tls`

| Key | Description |
| --- | --- |
| `cert_file` | Server certificate chain (PEM). |
| `key_file` | Server private key (PEM). Secret-file rules apply. |
| `client_ca_file` | Optional. CA bundle for client certificates. Enables `apps[].client_cert_uri`. Certificates are verified when presented; whether one is required is decided per application. |

TLS 1.2 is the minimum; Go's default cipher suites apply (no known-weak suites).

## `gateway_keys[]`

| Key | Description |
| --- | --- |
| `id` | Key ID, the `kid` in pass footers. `^[a-z][a-z0-9_-]{0,62}$`. |
| `public_key_file` | Ed25519 public key, PEM `PUBLIC KEY` (PKIX). Created by `tenant-pass gen-gateway-key`. |

Several keys may be configured at once (several gateways, or rotation).

## `pass`

| Key | Default | Range | Description |
| --- | --- | --- | --- |
| `max_ttl` | `"60s"` | 1s–5m | Maximum `exp − iat` of a pass. |
| `leeway` | `"5s"` | 0–30s | Tolerated clock difference for `iat`. Never applied to `exp`. An explicit `"0s"` means no leeway. |

## `apps[]`

| Key | Description |
| --- | --- |
| `name` | Application name; must equal the `aud` of passes the gateway signs for it. `^[a-z][a-z0-9_-]{0,62}$`. |
| `token_sha256` | SHA-256 of the app token, 64 lowercase hex characters. Created by `tenant-pass gen-app-token`. |
| `client_cert_uri` | URI SAN the application's client certificate must carry (for example a SPIFFE ID). Requires `tls.client_ca_file`. |
| `jobs` | Optional. Enables job tickets for this application: `issue` (bool, may call `POST /v1/job-tickets`), `max_ttl` (default `1h`, 1m–24h, cap for issued tickets), `max_tenants_per_minute` (default 60, distinct tenants per minute for ticket redemption, per replica; a budget **in addition** to `limits.max_tenants_per_minute`), `trusted_issuers` (IDs from `job_tickets.trusted_issuers` whose tickets this application may redeem). Ticket lifetimes above `max_ttl` are refused on redemption too. Without `jobs`, the application can neither obtain nor redeem tickets. |

At least one of `token_sha256` / `client_cert_uri` is required. If both are set, both are required on every request. Token hashes and certificate URIs must be unique.

## `directory`

### `directory.static`

```json
"directory": {"static": {"tenants": [
  {"id": "acme", "hosts": ["acme.example.com"], "node": "pg1", "account": "t_acme", "enabled": true, "apps": ["billing"]}
]}}
```

| Key | Description |
| --- | --- |
| `id` | Tenant ID, `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. Unique. |
| `hosts` | Canonical host names served by this tenant. Each host may belong to one tenant only. |
| `node` | A `nodes[].name`. |
| `account` | Account name on that node. |
| `enabled` | `false` refuses credentials (`403 denied`). |
| `apps` | Applications allowed to obtain credentials for this tenant. Required, non-empty. |

### `directory.sql`

Runs your queries against a PostgreSQL or MySQL database that already knows your tenants.

```json
"directory": {"sql": {
  "driver": "postgres",
  "endpoint": {"address": "central-db.internal:5432", "user": "tenant_pass_reader", "password_file": "/run/secrets/directory_pw", "database": "control"},
  "by_host":   "SELECT t.id AS tenant_id, t.node, t.role AS account, t.status = 'active' AS enabled FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id WHERE d.domain = $1 AND d.verified AND t.app = $2",
  "by_tenant": "SELECT id AS tenant_id, node, role AS account, status = 'active' AS enabled FROM tenants WHERE id = $1 AND app = $2"
}}
```

| Key | Description |
| --- | --- |
| `driver` | `postgres` or `mysql`. |
| `endpoint` | Connection, see [Endpoints](#endpoints). Use a read-only account with `SELECT` on the needed columns only. |
| `by_host` | Query for passes with `host`. Parameters: `$1`/`?` = host name, `$2`/`?` = application name. |
| `by_tenant` | Query for passes with `tenant`. Parameters: tenant ID, application name. |

The directory must map each account to at most one tenant (tenant-pass cannot detect two rows, or two node names for the same server, pointing at one account).

Each query must return **exactly** the columns `tenant_id`, `node`, `account`, `enabled` (in this order, with these names — use `AS`), and zero or one row. More than one row is an error (fail closed). Queries run inside a **read-only transaction**. Both queries are run once at startup with a dummy key to check that they parse and return the right columns.

Restricting tenants to applications is the query's job, via the second parameter. If every application may access every tenant, say so explicitly, for example `AND $2::text IS NOT NULL`.

## `rotation`

| Key | Default | Description |
| --- | --- | --- |
| `window` | `"15m"` | Window length: whole seconds, 1m–24h. |
| `renew_before` | `"5m"` | Hand out the next window when this much or less remains. 0 < `renew_before` ≤ `window`/2. |
| `sweep_interval` | `"30s"` | How often MySQL and Redis nodes are swept for expired passwords. 5s ≤ `sweep_interval` ≤ `renew_before`. |
| `max_clock_skew` | `"10s"` | Largest tolerated difference between a replica's clock and a store server's clock. Writes are refused (`clock_skew`) beyond it. 1s ≤ `max_clock_skew` ≤ `renew_before`/4. |
| `keys` | required | Rotation keys. |

`rotation.keys[]`:

| Key | Description |
| --- | --- |
| `id` | Key ID (`^[a-z][a-z0-9_-]{0,62}$`). Part of the derivation: renaming a key changes all its passwords. |
| `secret_file` | Base64 of at least 32 random bytes. Created by `tenant-pass gen-rotation-key`. Obvious placeholder values (repeated patterns) are rejected. |
| `transit` | Instead of `secret_file`: `{"key": "<Transit hmac key>", "version": N}` in Vault/OpenBao (requires `kms.vault`). The version is pinned. |
| `not_before` | RFC 3339 time. Window `n` uses the key with the latest `not_before ≤ Start(n)`. The earliest key must be at least one window in the past at startup. |

All replicas must have identical `rotation` settings and node names. Changing `window` changes every account's window boundaries: see [operations.md](operations.md#changing-the-window).

## `nodes[]`

| Key | Types | Description |
| --- | --- | --- |
| `name` | all | Node name, referenced by the directory. Part of the derivation. |
| `type` | all | `postgres`, `mysql` or `redis`. |
| `endpoint` | postgres, mysql | Admin connection. |
| `servers` | redis | Admin connections to **every** server holding the ACL users (primary, replicas, all cluster nodes). |
| `account_pattern` | all | Required. Regular expression (Go RE2 syntax) that managed account names must match. Must be written with `^…$`, and is always compiled as `^(?:…)$` so that alternation cannot escape the anchors. Choose a prefix no administrative account uses, for example `^t_[a-z0-9_]{1,40}$`. |
| `managed_group` | postgres | Required. Role every managed role must be a member of. |
| `managed_role` | mysql | Required. Role every managed account must have been granted. |
| `managed_role_host` | mysql | Host part of `managed_role`. Default `%`. |
| `account_host` | mysql | Host part of managed accounts. Default `%`. |
| `acl_save` | redis | Run `ACL SAVE` after changes (for servers using an aclfile). |
| `managed_marker` | redis | Channel pattern that marks a user as managed (the user must carry the rule `&<marker>`). Default `tenant-pass:managed`. |
| `max_conns` | postgres, mysql | Admin connection pool size. Default 4. |
| `connect` | all | What clients receive: `host`, `port`, `database` (not for Redis). Usually your pooler/proxy, for example PgBouncer. |

See the store guides for the privileges the admin account needs: [PostgreSQL](stores/postgres.md), [MySQL](stores/mysql.md), [Redis](stores/redis.md).

## Endpoints

Used by `directory.sql.endpoint`, `nodes[].endpoint` and `nodes[].servers[]`. tenant-pass does not accept driver connection strings (DSNs): their insecure defaults and environment-variable lookups are avoided by construction.

| Key | Description |
| --- | --- |
| `address` | `host:port`. |
| `user` | Login name. |
| `password_file` | File containing the password. |
| `database` | Database name. **Required for PostgreSQL nodes**: tenant-pass's own database, which neither PUBLIC nor any managed role may connect to (see [PostgreSQL](stores/postgres.md)). Also used by the PostgreSQL/MySQL directory. |
| `tls.ca_file` | CA bundle to verify the server. Default: system roots. |
| `tls.server_name` | Name checked against the server certificate. Default: the host in `address`. |
| `tls.cert_file`, `tls.key_file` | Client certificate for the connection (optional). |
| `insecure_plaintext` | Disable TLS. Requires top-level `allow_insecure_plaintext`. Testing only. |

TLS always verifies the certificate chain and the host name. There is no "skip verify" option.

## `kms`

```json
"kms": {"vault": {"address": "https://vault.internal:8200", "token_file": "/run/vault/token", "mount": "transit", "tls": {"ca_file": "/etc/tenant-pass/vault-ca.pem"}}}
```

| Key | Description |
| --- | --- |
| `vault.address` | Base URL; `https` unless `insecure_plaintext` (with top-level `allow_insecure_plaintext`, testing only). |
| `vault.token_file` | Vault token file, re-read on every request. |
| `vault.namespace` | Optional `X-Vault-Namespace`. |
| `vault.mount` | Transit mount, default `transit`. |
| `vault.tls` | As for endpoints. |

## `job_tickets`

| Key | Default | Description |
| --- | --- | --- |
| `signing_key` | | tenant-pass's own ticket key: `id` and either `private_key_file` (PEM, `tenant-pass gen-signing-key`) or `transit` (`key`, `version`). Required for `POST /v1/job-tickets`. |
| `trusted_issuers` | | External issuers (schedulers): `[{"id", "public_key_file"}]`. |
| `max_ttl` | `"1h"` | Largest ticket lifetime accepted (1m–24h). |

At least one of `signing_key` / `trusted_issuers` is required. Key IDs **and key material** must differ from each other and from `gateway_keys` (a Transit signing key is checked at startup).

## `limits`

| Key | Default | Description |
| --- | --- | --- |
| `max_tenants_per_minute` | `60` | Distinct tenants per application per minute, per replica. |
| `issue_timeout` | `"5s"` | Upper bound for directory lookup plus store update (100ms–1m). |
| `max_concurrent_requests` | `256` | In-flight credential requests per replica; more get `503 busy`. |

## `shutdown`

| Key | Default | Description |
| --- | --- | --- |
| `drain` | `"5s"` | After SIGTERM, `/readyz` returns 503 for this long before the listener closes, so load balancers stop routing. |
| `timeout` | `"10s"` | Then wait at most this long for in-flight requests. |

Set your orchestrator's stop grace period above `drain + timeout` (for example 20 s with the defaults; Docker's default 10 s is too short).
