# Threat model

[日本語](../ja/threat-model.md)

This document states what tenant-pass is designed to protect, against whom, and — just as important — what it does **not** protect. Read it before deploying.

## Assets

1. **Tenant data** in the stores (PostgreSQL, MySQL, Redis).
2. **Tenant credentials**: the per-window passwords.
3. **Rotation keys**: whoever holds one can compute every password derived from it.
4. **Store admin credentials**: the accounts tenant-pass uses to set passwords.
5. **Gateway signing keys**: whoever holds one can mint passes.
6. **App tokens / client certificates**.

## Trust assumptions

| Component | Assumed |
| --- | --- |
| tenant-pass host and process | Trusted. It holds rotation keys and store admin credentials. |
| Gateway | Trusted to sign passes **only** for requests it has authenticated for that tenant. |
| Directory | Trusted to map tenants to the right accounts. (Store safety checks limit the damage of mistakes.) |
| Stores | Trusted to enforce passwords and expiry. |
| Network | Untrusted. All connections use TLS with certificate and host name verification. |
| Applications | **Not trusted.** The design goal is to limit what a compromised application can do. |
| Clocks | Roughly synchronized (NTP). Skew must be well below `renew_before`. |

## Primary threat: a compromised application

An attacker gains code execution in an application process (RCE, a malicious dependency, a stolen deployment credential).

**Without tenant-pass**, the application typically holds credentials for every tenant (or the key that decrypts them). The attacker reads all tenants immediately.

**With tenant-pass**, the attacker has the app token, but:

| Attack | Outcome |
| --- | --- |
| Request credentials for an arbitrary tenant | Fails: needs a pass, which only the gateway can sign. |
| Forge a pass | Fails: the application does not have a gateway private key. |
| Reuse a pass captured from another application | Fails: `aud` must equal the authenticated application. |
| Reuse passes the application legitimately received | Works, but only for those tenants and only until `exp` (seconds). |
| Read credentials other workers of the same application received | Works for tenants with live credentials in that process's memory: only tenants actively being served. Credentials expire within one window. |
| Read stored tenant passwords | Nothing is stored. |
| Make the gateway forward requests for many tenants to it | See "Residual risk: the gateway" below. Bounded by the distinct-tenant rate limit. With tenant-pass-gateway, impossible without a valid user session for each tenant. |
| Turn passes into longer-lived job tickets | Only if the application has `jobs.issue`; limited to tenants it legitimately received passes for, and to `jobs.max_ttl`. |
| Sign its own job tickets | Not possible: issuer keys belong to tenant-pass and to separately run schedulers. |
| Point tenant-pass at an admin account | Not possible from the application: the directory decides the account, and the store refuses privileged and unmanaged accounts. |

So a compromised application exposes **tenants that are actively used while the attacker is present**, at a rate bounded by `limits.max_tenants_per_minute`, instead of all tenants at once. Detection (audit log volume, `rate_limited` events) buys time to respond.

## Residual risk: the gateway

A pass proves only *"the gateway forwarded a request for this tenant to this application"*. If an attacker can **cause** the gateway to forward a request for an arbitrary tenant to the compromised application — for example by sending `Host: victim.example.com` to the public gateway — they obtain a valid pass for that tenant.

This is why the gateway must sign a pass **only after authenticating the end user's session (or a job's own signed authorization) for that tenant**. Unauthenticated endpoints (login pages, health checks, public assets, webhooks) must not receive passes. See [gateway-integration.md](gateway-integration.md). In addition:

- The application must not be able to reach the gateway from inside (it would otherwise call the gateway itself with chosen host names). Restrict this at the network level.
- The distinct-tenant rate limit bounds how fast this can be abused.

If your gateway signs passes for unauthenticated traffic, tenant-pass reduces to "an application can get the credential of any tenant whose host name it knows, at a limited rate". That is still better than a stored password table, but it is not the intended guarantee.

## Other threats

### Compromised tenant-pass

tenant-pass holds rotation keys and store admin credentials. Its compromise exposes **all** tenants — the same as the status quo without tenant-pass, but concentrated in one small service instead of every application. Mitigations:

- Run it on dedicated, minimal hosts or containers (distroless image, non-root, read-only root filesystem, no shell).
- Give its store admin accounts the least privilege documented in the store guides.
- Restrict network access to it to the applications that need it.
- Keep the rotation keys only in tenant-pass's secret mounts.

### Compromised job issuer (scheduler)

A trusted issuer can sign tickets for any tenant and any application that has `jobs`. It is as sensitive as a gateway key. Run it separately from applications, keep its key in Vault Transit if possible, and remove it from `trusted_issuers` to revoke it.

### Session token replay by a compromised application

Behind tenant-pass-gateway, the application may receive the user's session cookie or token like any web application. A compromised application could then try to obtain passes for every tenant in that user's tenant claim, until the token expires — by replaying the token, or by making the user's browser request the other tenants' hosts. tenant-pass-gateway counters replay with `forward_claims` (the proxy strips the token before it reaches the application) and caller authentication (no direct calls). The browser path is closed only by **scoping sessions per tenant**: host-only session cookies and `identity.single_tenant_tokens`. Fetch Metadata enforcement blocks passive cross-host requests but is not a boundary against a compromised application that serves the other tenants' pages too. Without session scoping, exposure is bounded by the tenants in the user's own tenant claim while the session is valid. See [gateway.md](gateway.md#cookie-sessions-across-tenant-hosts).

### Compromised identity provider

tenant-pass-gateway trusts tokens signed by your identity provider. Whoever controls the provider (or its signing keys) can create sessions for any tenant. This is outside tenant-pass's protection, as it is for every other system that relies on that provider.

### Leaked rotation key

Whoever holds a rotation key can compute every password derived from it **offline**, for every past and future window in which it is in force, without contacting tenant-pass. They still need network access to the stores. Response: rotate the key immediately (see [operations.md](operations.md#rotation-key-rotation)); after one window all old passwords are invalid (PostgreSQL by `VALID UNTIL`, MySQL/Redis by the sweeper and by issuance).

With rotation keys in Vault / OpenBao Transit ([kms.md](kms.md)), the key cannot be copied: an attacker on the host can derive passwords only while they keep access to the host and its Vault token.

### Leaked gateway key

Whoever holds it can mint passes for any tenant and any application — but must still authenticate as that application (app token / certificate). Response: remove the key from `gateway_keys` and roll out a new one.

### Leaked app token

Useless without passes. Response: replace the token hash in the configuration.

### Network attacker

All connections — application to tenant-pass, tenant-pass to stores and directory — use TLS 1.2+ with certificate and host name verification. Plaintext requires two explicit settings and is for testing only. Database drivers are configured without DSNs, so insecure driver defaults (for example libpq's `sslmode=prefer`) cannot apply.

### Passwords in transit to the store and in store logs

tenant-pass sends only verifiers/hashes: SCRAM-SHA-256 verifiers (PostgreSQL), `caching_sha2_password` hashes (MySQL), SHA-256 ACL hashes (Redis). They do not allow logging in. The plaintext exists only in tenant-pass memory and in the API response.

Note: a SCRAM verifier or a `caching_sha2_password` hash does allow an **offline guessing attack** against the password. tenant-pass passwords are 256-bit random values, so guessing is infeasible. Still, keep `log_statement = ddl` and similar settings off for the admin role if you can.

### Clock manipulation

Every replica compares its clock with the store server's clock before writing and refuses (`clock_skew`) when they differ by more than `rotation.max_clock_skew`. A replica with a broken clock therefore cannot extend passwords into the future or move accounts backwards. If the **store server's** clock is wrong, tenant-pass follows it; run NTP on database servers too and monitor `clock_skew`.

### Denial of service

- Bodies are limited to 4 KiB, headers to 16 KiB; read/write timeouts are set.
- Concurrent requests are limited (`limits.max_concurrent_requests`); excess requests get `503 busy` immediately.
- Each request is bounded by `limits.issue_timeout`.
- Readiness probes are cached for 5 s, so they cannot be used to load the stores.
- `repair` rewrites are limited to one per account per 10 s per replica.

tenant-pass is not designed to be exposed to the internet. Put it on an internal network.

## Explicit non-goals

- Protecting tenant data from a compromised **gateway**, **directory**, **tenant-pass host** or **store**.
- Protecting a tenant from a compromised application **while that tenant is being served** by it.
- Hiding which tenants exist from authenticated applications (`denied` does not distinguish "no such tenant" from "not allowed", but timing may).
- Detecting grants on **another tenant's** objects (for example a table-level grant from tenant A's schema to tenant B's role). Isolation between tenants' objects is set up by your provisioning; tenant-pass refuses administrative and server-wide privileges, not every possible cross-tenant grant.
- Protecting against connection exhaustion of a shared database server by tenants (reserve connections for the admin role; see the store guides).
- Detecting two directory entries (SQL directory) or two node names pointing at the same account; the static directory refuses shared accounts, the SQL directory relies on your schema.
- Closing database sessions that are already open when a credential expires or an application is revoked (see [operations.md](operations.md#incident-response)).
- Protecting against a tenant account's own actions inside its store. For example, a PostgreSQL role can change its own password; that only locks out its own tenant until the next window or a `repair`.
- Replacing database-level authorization. Tenant accounts should have only the privileges the tenant's data needs (for example, ownership of one schema or database).
