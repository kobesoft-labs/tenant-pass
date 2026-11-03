# Background jobs (job tickets)

[日本語](../ja/jobs.md)

A pass lives for seconds because it is tied to one request. Work that runs **later**, outside any request, needs its own authorization for one tenant. That is a **job ticket**.

| | Pass | Job ticket |
| --- | --- | --- |
| Signed by | the gateway | tenant-pass itself, or a trusted issuer you run (a scheduler) |
| Names | a host or a tenant | always a tenant ID |
| Lifetime | seconds (`pass.max_ttl`, ≤ 5 min) | minutes to hours (`job_tickets.max_ttl`, ≤ 24 h) |
| Implicit assertion | `tenant-pass/v1/pass` | `tenant-pass/v1/job` |
| Redeemed at | `POST /v1/credentials` `{"pass": …}` | `POST /v1/credentials` `{"ticket": …}` |
| Rate limit | `limits.max_tenants_per_minute` | `apps[].jobs.max_tenants_per_minute` (separate budget) |

The different implicit assertions mean a pass can never be used as a ticket, or a ticket as a pass, even if the same key signed both.

## Two ways to get a ticket

### 1. Continue a request: `POST /v1/job-tickets`

While handling a user's request (with a fresh pass), the application exchanges the pass for a ticket and puts the ticket in the job's payload. The job later redeems the ticket for credentials, as often as it needs, until the ticket expires.

```
user request ──▶ gateway ──pass──▶ app ──POST /v1/job-tickets {"pass"}──▶ tenant-pass
                                    │ ◀──────────── {"ticket", "tenant", "expires_at"}
                                    └─ enqueue job {tenant: acme, ticket: …}
later:  worker ──POST /v1/credentials {"ticket"}──▶ tenant-pass ──▶ credential for acme
```

Use this for work a user started: an export, an import, sending a report they requested.

Requirements:

- `job_tickets.signing_key` is configured (local key or Vault Transit).
- The application has `"jobs": {"issue": true}`.
- The pass is valid for that application, and the tenant is enabled and allowed for the application. tenant-pass resolves the tenant **when it issues the ticket**, so the ticket names the canonical tenant ID.
- Issuing counts against the same distinct-tenant budget as credentials, so it cannot be used to get around that limit.

### 2. Scheduled work: a trusted issuer

Some work is not started by any request: nightly reports, cleanups, migrations, billing runs. Nobody can produce a pass for them. Instead, a component **you operate and trust** — a scheduler, an admin panel's job runner — signs tickets with its own key, which tenant-pass trusts as `job_tickets.trusted_issuers`.

```
scheduler (holds issuer key) ──signs ticket {aud: reports, tenant: acme, exp: +1h}──▶ worker
worker ──POST /v1/credentials {"ticket"}──▶ tenant-pass ──▶ credential for acme
```

The issuer decides which tenants to run work for. tenant-pass still checks, on every redemption, that the tenant exists, is enabled and is allowed for the application, and applies the application's job rate limit.

Signing options for an issuer:

- Go: `pass.Signer{KeyID: "scheduler-1", Key: key}.SignJob(ctx, pass.JobClaims{...})`, or with `Remote:` for a Vault Transit key.
- Command line: `tenant-pass sign-job-ticket -key scheduler.key -kid scheduler-1 -aud reports -tenant acme -ttl 1h`.
- Other languages: any PASETO v4.public library, following the format below.

**Keep the issuer separate from the applications.** If an application could sign tickets, a compromised application could obtain credentials for every tenant, which is exactly what tenant-pass exists to prevent. An issuer key belongs to a separately deployed, separately secured component.

## Configuration

```json
"job_tickets": {
  "signing_key": {"id": "tp-jobs-2026-11", "transit": {"key": "tenant-pass-jobs", "version": 1}},
  "trusted_issuers": [{"id": "scheduler-1", "public_key_file": "/etc/tenant-pass/scheduler-1.pub"}],
  "max_ttl": "1h"
},
"apps": [
  {"name": "billing", "token_sha256": "…", "jobs": {"issue": true, "max_ttl": "30m", "max_tenants_per_minute": 60}},
  {"name": "reports", "token_sha256": "…", "jobs": {"trusted_issuers": ["scheduler-1"], "max_tenants_per_minute": 600}}
]
```

- An application without `jobs` can neither obtain nor redeem tickets (`403 denied`).
- `jobs.issue` allows `POST /v1/job-tickets`.
- `jobs.trusted_issuers` lists which external issuers' tickets the application may redeem. Tickets signed by tenant-pass's own key are always accepted (tenant-pass issues them only to the application named in them). A ticket from an issuer not listed is refused (`403`, audit `issuer_not_allowed`).
- Ticket lifetime (`exp − iat`) must not exceed the application's `jobs.max_ttl` — when issuing **and** when redeeming, also for external issuers — nor `job_tickets.max_ttl`. Keep both as short as your jobs allow.

See [configuration.md](configuration.md#job_tickets).

## Ticket format

Same construction as a pass ([pass-format.md](pass-format.md)), with these differences:

- Implicit assertion: `tenant-pass/v1/job`.
- Footer `{"kid": "<issuer key ID>"}`: tenant-pass's own `signing_key.id` or a `trusted_issuers[].id`.
- Claims, exactly: `aud` (application), `tenant` (tenant ID), `iat`, `exp`, `jti`. No `host`.
- `exp − iat ≤ job_tickets.max_ttl` (default 1 h, hard maximum 24 h).

## Security properties and limits

- A ticket is a bearer capability for one tenant and one application until it expires. Store it like a secret: in the job payload only, never in logs. tenant-pass never logs tickets.
- There is no revocation list. To revoke, remove the issuer key (or rotate tenant-pass's own `signing_key`) and roll out; or disable the tenant in the directory.
- A compromised application that has `jobs.issue` can turn passes it legitimately receives into tickets, extending its access to those tenants from seconds to `jobs.max_ttl`. Enable `issue` only for applications that need it and keep `max_ttl` short.
- Credentials obtained with a ticket follow the normal window rules and can outlive the ticket by up to one window.
- The job rate limit is a **separate** budget: an application can reach up to `limits.max_tenants_per_minute` tenants with passes **plus** `jobs.max_tenants_per_minute` with tickets (per replica). Set the job budget to what your jobs actually need.
- One pass can be exchanged for several tickets within its lifetime (there is no replay cache). All are for the same tenant and application, but each is a bearer token that may sit in a queue: protect the queue.
- Scope issuers narrowly: an issuer listed for an application can sign tickets for **any** tenant that application may access.
