# HTTP API

[日本語](../ja/api.md)

tenant-pass serves HTTPS (TLS 1.2+) on `listen`. All responses carry `Cache-Control: no-store`. It is meant for internal networks only.

## `POST /v1/credentials`

Exchange a pass (or a job ticket) for a tenant credential.

### Request

```http
POST /v1/credentials HTTP/1.1
Host: tenant-pass.internal:8443
Authorization: Bearer tpa_9b0Z…
Content-Type: application/json

{"pass": "v4.public.…", "repair": false}
```

| | |
| --- | --- |
| `Authorization` | `Bearer <app token>`. Exactly one header. Omit only for applications that authenticate with a client certificate alone. |
| Client certificate | Required for applications configured with `client_cert_uri`. |
| `Content-Type` | `application/json` (parameters such as `charset` are allowed). |
| Body | At most 4096 bytes. A JSON object with exactly the members below; unknown or duplicate members are rejected. |

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `pass` | string | one of `pass` / `ticket` | The pass received from the gateway. See [pass-format.md](pass-format.md). |
| `ticket` | string | one of `pass` / `ticket` | A job ticket. Requires `jobs` on the application. See [jobs.md](jobs.md). |
| `repair` | bool | no | Set to `true` when a credential from tenant-pass was just rejected by the store (authentication failure). For PostgreSQL, tenant-pass then rewrites the role even if it looks up to date (at most once per account per 10 s per replica; further requests are served normally). MySQL and Redis verify the actual password hashes on every request, so `repair` has no extra effect there. |

### Response `200 OK`

```json
{
  "tenant": "acme",
  "store": "postgres",
  "host": "pgbouncer.internal",
  "port": 6432,
  "database": "app",
  "username": "t_acme",
  "password": "umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM",
  "expires_at": "2026-11-03T12:13:59Z",
  "refresh_at": "2026-11-03T12:08:59Z"
}
```

| Member | Meaning |
| --- | --- |
| `tenant` | Tenant ID as returned by the directory. |
| `store` | `postgres`, `mysql` or `redis`. |
| `host`, `port`, `database` | Where to connect (`nodes[].connect`). `database` is omitted when not configured, and always for Redis. |
| `username` | Account name. |
| `password` | 43 characters of base64url. Treat as a secret: keep only in process memory. |
| `expires_at` | After this time the password no longer opens new connections (PostgreSQL), or may be removed at the next sweep (MySQL, Redis). Existing connections are not affected. |
| `refresh_at` | Fetch a new credential at or after this time. From `refresh_at` on, tenant-pass hands out the next window. |

The same password is returned for every request in the same window, to every replica and every worker.

### Errors

The body is always `{"error": "<code>"}`. The reason is never returned; it is in the audit log.

| Status | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Body is not a JSON object with a non-empty `pass`, has unknown or duplicate members, or trailing data. |
| 400 | `invalid_pass` | Pass rejected: malformed, unknown key, bad signature, invalid claims, expired, or `aud` is not the calling application. |
| 400 | `invalid_ticket` | Job ticket rejected, for the same reasons. |
| 401 | `unauthorized` | Application authentication failed. Has `WWW-Authenticate: Bearer realm="tenant-pass"`. |
| 403 | `denied` | No such tenant, the application is not allowed for it, the tenant is disabled, the store refused the account, or (tickets) job tickets are not enabled for the application. |
| 404 | `not_found` | Unknown path. |
| 405 | `method_not_allowed` | Not `POST`. |
| 413 | `request_too_large` | Body over 4096 bytes. |
| 415 | `unsupported_media_type` | Content type is not `application/json`. |
| 429 | `rate_limited` | The application exceeded `limits.max_tenants_per_minute` distinct tenants in the last minute (on this replica). Repeated requests for a tenant already seen are not limited. |
| 503 | `busy` | `limits.max_concurrent_requests` reached. Retry with backoff. |
| 503 | `unavailable` | Directory or store error, timeout, or clock skew between this replica and the store server. Retry with backoff (another replica may succeed). |

Clients should treat 400, 401 and 403 as permanent for that pass, and 429/503 as retryable.

## `POST /v1/job-tickets`

Exchange a pass for a job ticket for the same tenant, so that work that runs later can obtain credentials. Requires `job_tickets.signing_key` and `"jobs": {"issue": true}` on the application. See [jobs.md](jobs.md).

```http
POST /v1/job-tickets HTTP/1.1
Authorization: Bearer tpa_…
Content-Type: application/json

{"pass": "v4.public.…", "ttl": "15m"}
```

| Member | Required | Meaning |
| --- | --- | --- |
| `pass` | yes | A valid pass for the calling application. |
| `ttl` | no | Requested lifetime, whole seconds, at least `1m`. Capped by `apps[].jobs.max_ttl` and `job_tickets.max_ttl`. Default: the application's `jobs.max_ttl`. |

Response `200`:

```json
{"ticket": "v4.public.…", "tenant": "acme", "expires_at": "2026-11-03T12:30:00Z"}
```

The tenant is resolved at issuance (it must exist, be enabled and be allowed for the application). Issuance counts against the application's distinct-tenant budget. Errors are as for `/v1/credentials`; `403 denied` also when issuing is not enabled for the application.

## `GET /healthz`

Liveness. `200 {"status":"ok"}` while the process runs. Unauthenticated.

## `GET /readyz`

Readiness. Unauthenticated.

- `200 {"status":"ready"}`: the directory and every node answer.
- `503 {"status":"draining"}`: shutdown has started (SIGTERM). Remove the replica from the load balancer.
- `503 {"status":"unavailable"}`: the directory or a node is unreachable.

Backend checks are cached for 5 s.

## Audit log

tenant-pass writes one JSON line per request to standard output: `"msg":"credential"` for `/v1/credentials`, `"msg":"job_ticket"` for `/v1/job-tickets`:

```json
{"time":"2026-11-03T12:00:01Z","level":"INFO","msg":"credential","request_id":"43f007226bb0e766","app":"billing","repair":false,"jti":"hamSSKegCc-kk82SdW2dpw","host":"acme.example.com","tenant":"acme","node":"pg1","account":"t_acme","store":"postgres","window":1993007,"key_id":"k1","changed":true,"expires_at":"2026-11-03T12:13:59Z","result":"ok","duration_ms":7}
```

| Field | Meaning |
| --- | --- |
| `via` | `pass` or `ticket`. |
| `issuer` | For tickets: the key ID that signed it. |
| `result` | `ok` or the error code returned to the client. |
| `reason` | Why it failed: `app_auth`, `body_size`, `body_json`, `content_type`, `pass_malformed`, `pass_unknown_key`, `pass_signature`, `pass_claims`, `pass_expired`, `pass_audience`, `distinct_tenants`, `distinct_tenants_jobs`, `pass_or_ticket`, `jobs_not_enabled`, `job_issue_not_enabled`, `issuer_not_allowed`, `ticket_lifetime`, `ticket_*` (as `pass_*`), `ttl`, `sign_error`, `tenant_not_found`, `tenant_disabled`, `directory_error`, `directory_mismatch`, `unknown_node`, `account_refused`, `clock_skew`, `timeout`, `store_error`, `max_concurrent_requests`. |
| `error` | For `directory_error` / `store_error` / `account_refused`: the error class (SQLSTATE, MySQL error number, Redis error prefix, refusal reason). Server error messages are not copied. |
| `changed` | Whether the store was modified. |
| `window`, `key_id` | Which window and rotation key the credential belongs to. |

Never logged: passwords, verifiers, hashes, passes, job tickets, app tokens, rotation keys. The client IP is not logged by tenant-pass; take it from your load balancer if needed.

Levels: `INFO` for success, `WARN` for client errors, `ERROR` for `directory_error`, `store_error`, `account_refused`, `clock_skew`, `unknown_node`, `directory_mismatch`. See [operations.md](operations.md#monitoring) for what to alert on.
