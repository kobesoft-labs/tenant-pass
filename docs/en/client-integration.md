# Client integration

[日本語](../ja/client-integration.md)

How an application should obtain, keep and refresh tenant credentials.

## Flow per request

1. Read the pass from the header your gateway uses (for example `Tenant-Pass`). If it is missing, the request is not entitled to tenant data: fail the request.
2. Look up a cached credential for the tenant **in process memory**. If it exists and `now < refresh_at`, use it.
3. Otherwise call `POST /v1/credentials` with the pass, cache the result until `refresh_at`, and use it.
4. Connect to `host:port` (and `database`) as `username` / `password`.

```text
credential = cache.get(tenant)
if credential is None or now >= credential.refresh_at:
    credential = tenant_pass.fetch(pass)          # POST /v1/credentials
    cache.put(tenant, credential)
conn = connect(credential)
if conn failed with authentication error:
    credential = tenant_pass.fetch(pass, repair=True)
    cache.put(tenant, credential)
    conn = connect(credential)                    # once; do not loop
```

The cache key is the tenant you resolved from the pass (or the `tenant` field of the response). Never use the cache across processes or hosts.

## Rules

- **Memory only.** Never write credentials to disk, a shared cache (Redis, memcached), a database, logs, error reports or metrics labels. Keep the app token in the process environment or a secret mount, not in code.
- **Refresh at `refresh_at`.** From that point tenant-pass hands out the next window. Refreshing earlier is harmless (same password). On PostgreSQL, treat `refresh_at` as the practical end of the credential: once any client refreshes, the previous password stops opening new connections. On MySQL and Redis the previous password keeps working until `expires_at` (plus up to one sweep).
- **Retry once on authentication failure**, with `"repair": true`:
  - PostgreSQL: SQLSTATE `28P01` (`invalid_password`).
  - MySQL: error `1045` (`ER_ACCESS_DENIED_ERROR`).
  - Redis: `WRONGPASS`.
  
  On PostgreSQL this is expected right after rotation (one password per role), on MySQL/Redis it should be rare. Do not retry in a loop.
- **Open connections are fine.** A password change or expiry does not close existing connections. Connection pools can keep them; only new connections need the current password.
- **Need a pass to refresh.** A credential can only be refreshed while handling a request that carries a fresh pass. Long-running work that outlives the window must obtain its own authorization (see [gateway integration](gateway-integration.md#background-jobs)).
- **Errors**: `400`/`401`/`403` are permanent for that pass (log and fail the request); `429`/`503` are retryable with backoff.
- **TLS**: verify tenant-pass's certificate. Do not disable verification.

## Connection pools

- Key pools by tenant. A pool for tenant A must never be used for tenant B.
- When the cached credential is refreshed, new connections in the pool should use the new password. Pools that take a static password at creation must be recreated (or use a password callback; for example `pgx`'s `BeforeConnect`, or `lib/pq`'s connector).
- Close idle pools for tenants that are no longer active, so that their credentials leave memory.

## PgBouncer and proxies

Point `connect` at the pooler. See [PostgreSQL › PgBouncer](stores/postgres.md#pgbouncer).

## Example (Go)

```go
type cred struct {
	Username, Password, Host, Database string
	Port                               int
	RefreshAt                          time.Time `json:"refresh_at"`
}

func fetch(ctx context.Context, hc *http.Client, token, pass string, repair bool) (*cred, error) {
	body, _ := json.Marshal(map[string]any{"pass": pass, "repair": repair})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://tenant-pass.internal:8443/v1/credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tenant-pass: %s", resp.Status)
	}
	var c cred
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
```
