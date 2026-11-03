# Redis / Valkey

[日本語](../../ja/stores/redis.md)

## How it works

Each tenant is a Redis ACL user. ACL users can hold several passwords; tenant-pass keeps the password of the current window and, during renewal, the next one:

```
ACL SETUSER t_acme resetpass #<sha256 of password(n)> [#<sha256 of password(n+1)>]
```

- Passwords are set by SHA-256 hash (`#…`), so the plaintext never reaches Redis, its slow log or `MONITOR`.
- `resetpass` removes all other passwords and the `nopass` flag. Nothing else about the user (commands, keys, channels, on/off) is changed.
- During renewal, both credentials work.
- The **sweeper** (every `rotation.sweep_interval`) removes passwords whose window has ended and any password tenant-pass did not derive. A user not requested for a whole window ends up with no password at all and cannot log in.

## Supported versions

Redis 7.0+ and Valkey 7.2+ (tenant-pass needs `ACL DRYRUN`). Tested with Redis 8.

## ACLs are per server

Redis does **not** replicate ACLs. Every server keeps its own users: a primary and its replicas, every Sentinel-managed instance, every Redis Cluster node. List **all** of them in the node's `servers`; tenant-pass reads every server, plans once, and writes the same password set to each. A server that lost its state (for example restarted without an aclfile) is brought back in line on the next request or sweep.

If your servers load users from an `aclfile`, set `acl_save: true` so tenant-pass runs `ACL SAVE` after each change. Otherwise a restarted server comes back with stale passwords until tenant-pass fixes it.

## Setup

On every server (or in the aclfile), create the admin user with only the ACL commands tenant-pass uses:

```
ACL SETUSER tenant_pass_admin on ><random> -@all +acl|getuser +acl|setuser +acl|users +acl|dryrun +acl|save +time +ping +auth +hello
```

`+acl|setuser` is powerful: it can change any user, including granting permissions. Redis has no narrower option. Protect the `tenant_pass_admin` credentials like an administrator password, and restrict network access to Redis.

Create tenant users (your provisioning does this), with only what the tenant needs, **and the managed marker** `&tenant-pass:managed`:

```
ACL SETUSER t_acme on resetchannels &tenant-pass:managed &t:acme:* -@all +@read +@write ~t:acme:*
```

The marker is a channel rule. It grants nothing unless the user may also use pub/sub commands, and then only that one channel name. tenant-pass — including the sweeper — never touches a user without it. Configure a different marker with `managed_marker`.

## Safety checks

Before issuing, on every server, tenant-pass refuses (audit `account_refused`) unless:

- the user name matches `account_pattern` and `[A-Za-z0-9_.:-]{1,128}`, and is not `default`;
- the user exists (tenant-pass never creates users) and carries the managed marker;
- **`ACL DRYRUN`** reports that the user can run none of: `ACL …`, `CONFIG …`, `MODULE …`, `DEBUG`, `SHUTDOWN`, `FLUSHALL`, `FLUSHDB`, `SWAPDB`, `KEYS`, `CLIENT KILL/LIST/PAUSE`, `SCRIPT FLUSH`, `FUNCTION LOAD/DELETE/FLUSH`, `REPLICAOF`, `SLAVEOF`, `FAILOVER`, `CLUSTER …`, `SAVE`, `BGSAVE`, `BGREWRITEAOF`, `MONITOR`, `SYNC`, `PSYNC`, `SLOWLOG RESET`, `LATENCY RESET`, `MEMORY PURGE`;
- **`ACL DRYRUN`** reports that the user cannot `GET`/`SET` a random key or `PUBLISH`/`SUBSCRIBE` to a random channel (that is, its key and channel patterns are restricted);
- a static check of the rule text finds no `allcommands`, `allkeys`, `+@all`, `+@admin`, `+@dangerous`, or explicit grants of the commands above;
- the server's `TIME` agrees with the replica's clock within `rotation.max_clock_skew`.

`ACL DRYRUN` evaluates the user's *effective* permissions, including categories and selectors. This matters: categories such as `@slow` contain `ACL` and `CONFIG`. Grant tenants individual commands or narrow categories (`@read`, `@write`, `@string`, `@hash`, …).

The sweeper only removes passwords, so it checks the marker but skips the `DRYRUN` probes.

## Node configuration

```json
{
  "name": "cache1",
  "type": "redis",
  "servers": [
    {"address": "cache1-a.internal:6380", "user": "tenant_pass_admin", "password_file": "/run/secrets/cache1-admin-password", "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}},
    {"address": "cache1-b.internal:6380", "user": "tenant_pass_admin", "password_file": "/run/secrets/cache1-admin-password", "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}}
  ],
  "account_pattern": "^t_[a-z0-9_]{1,40}$",
  "acl_save": false,
  "connect": {"host": "cache1.internal", "port": 6380}
}
```

Enable TLS on Redis (`tls-port`, `tls-cert-file`, …) and disable the plaintext port.

## Concurrency

Updates are idempotent (the same window always yields the same hash) and forward-only. Two replicas racing on the same user can, at worst, briefly re-add the previous window's password; the sweeper removes it again. They can never install a password tenant-pass did not derive.

## Client notes

Clients authenticate with `AUTH <username> <password>` (or `HELLO 3 AUTH …`). A user that lacks `+ping` gets `NOPERM` for `PING` after a successful `AUTH`; that is not an authentication failure.
