# tenant-pass-gateway

[日本語](../ja/gateway.md)

`tenant-pass-gateway` is a ready-made gateway component. It plugs into your reverse proxy as a **forward-auth** service and signs passes only for requests whose end user has a valid session for the tenant of the requested host. If you would rather build passes into an existing component, read [gateway-integration.md](gateway-integration.md) for the rules.

```
browser ──▶ proxy (Caddy / nginx / Traefik / Envoy)
              │ 1. strip client-supplied Tenant-Pass
              │ 2. ask tenant-pass-gateway (headers only)
              │      ├─ host → route → app, tenant
              │      ├─ session JWT → verify with your IdP's JWKS
              │      ├─ tenant ∈ token's tenant claim?
              │      └─ 200 + Tenant-Pass: v4.public…   (or 200 without, or 403)
              │ 3. copy Tenant-Pass onto the request
              ▼
          application ──pass──▶ tenant-pass
```

The application is never trusted for any of this. It receives the pass but cannot create one.

## Decisions

| Situation | Response | Pass |
| --- | --- | --- |
| Valid session, tenant of host ∈ tenant claim | `200` | yes |
| Valid session for another tenant | `403` | no (the proxy refuses the request) |
| No / invalid / expired session | `200` (default `pass_through`) or `401` (`deny`) | no |
| Host matches no route | `200` | no |
| Host header malformed or ambiguous | `400` | no |
| `caller_secret_file` set and header missing/wrong | `401` | no |

With `pass_through`, requests without a session still reach the application, so it can render a login page. Without a pass it cannot obtain tenant credentials, so this is safe.

## Session tokens

The gateway verifies a JWT issued by your identity provider (OIDC ID token, access token, or a session JWT your login service issues):

- signature with the provider's **JWKS** (`jwks_url` over HTTPS, or `jwks_file`), selecting the key by `kid`;
- only asymmetric algorithms (`RS256`, `ES256`, `EdDSA` by default; `HS*` and `none` are never accepted); if a JWK pins `alg`, the token must use it;
- `iss` must equal `identity.issuer`; `aud` must contain one of `identity.audiences`; `exp` is required; `nbf` and `iat` are honoured; optional `max_token_age`;
- the tenant claim (`identity.tenant_claim`, dotted paths allowed) is a string or an array of strings;
- optional `identity.forward_claims`: claims returned as headers with the pass, so the application need not see the token (see below);
- optional `identity.required_claims`: string claims that must match exactly, for example `{"azp": "web-app"}` or `{"typ": "Bearer"}`, so that tokens issued to other clients or for other purposes (an ID token where an access token is expected) are not accepted just because their audience overlaps.

The token is read from `Authorization: Bearer` (if `authorization_header` is true), then from the cookie named `identity.cookie`.

JWKS handling: only public signature keys with a `kid` are used; keys with a duplicated `kid` are dropped. A URL source is refreshed in the background every 10 minutes, and on an unknown `kid` at most once per 30 seconds; refreshes cannot be cancelled by the client that triggered them. If no refresh has succeeded for **one hour**, the gateway stops trusting the old keys and refuses all tokens (fail closed), so a key your provider has revoked does not stay trusted while refreshes fail.

## Routes

```json
"routes": [
  {"host": "{tenant}.billing.example.com", "app": "billing"},
  {"host": "shop.acme-corp.com",           "app": "billing", "tenant": "acme"},
  {"host": "app.example.com",              "app": "crm",     "tenant_from_token": true}
]
```

| Form | Tenant comes from | Check |
| --- | --- | --- |
| `{tenant}` as one whole label | the host label | label ∈ token's tenants |
| exact host + `tenant` | configuration (custom domains) | that tenant ∈ token's tenants |
| exact host + `tenant_from_token` | the token | the token names exactly one tenant |

Exact hosts take precedence over patterns. `{tenant}` matches exactly one label: `x.acme.billing.example.com` does not match `{tenant}.billing.example.com`.

The host is read from `request.host_header` (default `X-Forwarded-Host`; use `Host` for Envoy ext_authz), lower-cased, stripped of port and trailing dot, and must then be a canonical host name. Non-ASCII input is rejected before lower-casing (Unicode case folding would turn some characters into ASCII letters). A list of hosts (`a, b`) and repeated header lines are rejected: configure the proxy to **set** the header, not append to a client-supplied one.

Passes always carry the **tenant ID** (`tenant` claim), with `aud` = the route's `app`.

## Configuration

```json
{
  "listen": "127.0.0.1:9180",
  "insecure_plaintext_http": true,
  "caller_secret_file": "/run/secrets/gateway-caller-secret",

  "signing_key": {"id": "gw-2026-11", "private_key_file": "/run/secrets/gateway.key"},

  "identity": {
    "issuer": "https://login.example.com/",
    "audiences": ["tenant-apps"],
    "jwks_url": "https://login.example.com/.well-known/jwks.json",
    "algorithms": ["RS256", "ES256", "EdDSA"],
    "authorization_header": true,
    "cookie": "session",
    "tenant_claim": "tenant_id",
    "leeway": "30s",
    "cookie_fetch_metadata": "enforce"
  },
  "routes": [{"host": "{tenant}.billing.example.com", "app": "billing"}],
  "unauthenticated": "pass_through",
  "pass": {"ttl": "30s", "header": "Tenant-Pass"},
  "request": {"host_header": "X-Forwarded-Host"},
  "log_level": "info"
}
```

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `127.0.0.1:9180` | Listen address. |
| `tls` | | `cert_file`, `key_file`; `client_ca_file` makes client certificates **required**, and then `client_uris` and/or `client_dns_names` must name the proxy: a certificate from the CA is accepted only if one of its SANs matches (in a service mesh every workload, including the applications, has a certificate from the same CA). |
| `max_concurrent_requests` | `256` | In-flight authorization requests; excess requests get `503`. |
| `identity.leeway` | `30s` | Clock tolerance for `exp`/`nbf`/`iat` (0–5m; `"0s"` means none). |
| `identity.single_tenant_tokens` | `false` | Require the tenant claim to name exactly one tenant (see "Cookie sessions across tenant hosts"). |
| `identity.cookie_fetch_metadata` | `enforce` | Fetch Metadata check for cookie tokens: `enforce` or `off`. |
| `allow_insecure_plaintext` | `false` | Testing only: allows plaintext settings off loopback. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |
| `health_listen` | | Optional address for `GET /healthz`. The forward-auth listener treats every path as an authorization request, so it has no health path. |
| `insecure_plaintext_http` | `false` | Plain HTTP. Allowed on a loopback address (sidecar next to the proxy); elsewhere requires `allow_insecure_plaintext` (testing only). |
| `caller_secret_file` | | If set, callers must send `Tenant-Pass-Gateway-Secret` with this value (≥ 16 characters). On a non-loopback `listen`, `caller_secret_file` or `tls.client_ca_file` is **required**. |
| `kms.vault` | | Vault/OpenBao connection, see [kms.md](kms.md). |
| `signing_key` | required | `id` (the pass `kid`) and either `private_key_file` (PEM) or `transit` (`key`, `version`). |
| `identity.*` | | See above. `jwks_tls` (`ca_file`, …) for a private IdP CA. `max_token_age` rejects tokens whose `iat` is older. |
| `routes` | required | See above. |
| `unauthenticated` | `pass_through` | or `deny`. |
| `pass.ttl` | `30s` | 5 s – 5 min; must not exceed tenant-pass's `pass.max_ttl`. |
| `pass.header` | `Tenant-Pass` | Response header carrying the pass. |
| `request.host_header` | `X-Forwarded-Host` | Header carrying the original host. |

Commands: `tenant-pass-gateway serve -config FILE`, `tenant-pass-gateway check-config -config FILE`.

On the tenant-pass side, add the gateway's public key to `gateway_keys` with the same `id` (`tenant-pass gen-gateway-key` creates a local pair; for Transit see [kms.md](kms.md#public-keys)).

## Proxy configuration

The proxy **must** remove any `Tenant-Pass` header sent by the client before calling the gateway, and copy the gateway's header afterwards. Otherwise a client without a session could send its own (stolen) pass to the application.

### Caddy (tested)

```caddyfile
*.billing.example.com {
	# route{} keeps the written order. Caddy's default directive order
	# runs forward_auth before request_header, which would delete the
	# pass the gateway just added.
	route {
		request_header -Tenant-Pass
		forward_auth 127.0.0.1:9180 {
			uri /
			header_up Tenant-Pass-Gateway-Secret {env.TP_GATEWAY_SECRET}
			copy_headers Tenant-Pass
		}
		reverse_proxy billing:8080
	}
}
```

### nginx (tested)

```nginx
location = /_tenant_pass_auth {
    internal;
    proxy_pass http://127.0.0.1:9180/;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Uri $request_uri;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Cookie $http_cookie;
    include /etc/nginx/tenant-pass-secret.conf;   # proxy_set_header Tenant-Pass-Gateway-Secret "..."; (mode 0600)
}

location / {
    auth_request /_tenant_pass_auth;
    auth_request_set $tenant_pass $upstream_http_tenant_pass;
    # Always set: an empty value removes any client-supplied header.
    proxy_set_header Tenant-Pass $tenant_pass;
    proxy_set_header X-Forwarded-Host $host;   # never pass on a client-supplied value
    proxy_pass http://billing:8080;
}
```

### Traefik

Traefik's ForwardAuth cannot add a header to the authorization request alone (a headers middleware would send it to the application too), so `caller_secret_file` cannot be used safely with Traefik. Off loopback, use mTLS: `forwardAuth.tls` with a client certificate, and the gateway's `client_ca_file` plus `client_uris`/`client_dns_names`.

```yaml
http:
  middlewares:
    strip-pass:
      headers:
        customRequestHeaders:
          Tenant-Pass: ""          # removes the client's header
          Tenant-Pass-User: ""     # and every forward_claims header
    tenant-pass:
      forwardAuth:
        address: http://127.0.0.1:9180/
        authResponseHeaders: ["Tenant-Pass", "Tenant-Pass-User"]
        authRequestHeaders: ["Authorization", "Cookie", "X-Forwarded-Host", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User"]
  routers:
    billing:
      rule: HostRegexp(`^[a-z0-9-]+\.billing\.example\.com$`)
      middlewares: [strip-pass, tenant-pass]
      service: billing
```

### Envoy (ext_authz, HTTP)

Set `request.host_header` to `Host`. In the ext_authz filter, allow `authorization`, `cookie`, `sec-fetch-site`, `sec-fetch-mode` and `sec-fetch-user` in `allowed_headers`, and add `tenant-pass` (and every `forward_claims` header) to `allowed_upstream_headers`.

Remove client-supplied `tenant-pass` and identity headers **before** the ext_authz filter runs — with a header-mutation filter placed ahead of ext_authz in the HTTP filter chain — not with the route's `request_headers_to_remove`, which is applied after ext_authz and would also remove the gateway's pass. Also set `headers_with_underscores_action: REJECT_REQUEST` on the connection manager, so that `tenant_pass` cannot reach applications that normalize underscores to dashes.

Verify your proxy before going live: a request **without** a session but **with** a forged `Tenant-Pass` header must reach the application without that header.

In every proxy, also **set** `X-Forwarded-Host` (do not pass on a client-supplied one) for the request to the application, and have applications take the tenant only from the credentials response (`tenant`), never from host headers.

## Keeping session tokens away from the application

The strongest protection against a compromised application replaying session tokens is to never give it one. With `identity.forward_claims`, the gateway returns verified claims as headers (only together with a pass), and the proxy forwards those instead of the token:

```json
"identity": { "...": "...", "forward_claims": {"Tenant-Pass-User": "sub"} }
```

```caddyfile
route {
	request_header -Tenant-Pass
	request_header -Tenant-Pass-User
	forward_auth 127.0.0.1:9180 {
		uri /
		copy_headers Tenant-Pass Tenant-Pass-User
	}
	# The application gets the user ID, never the session token.
	request_header -Authorization
	reverse_proxy billing:8080
}
```

(Tested with Caddy 2: the application receives the pass and `Tenant-Pass-User`, no `Authorization`, and client-supplied `Tenant-Pass-User` headers are removed.)

Forward a stable, provider-controlled identifier such as `sub`. Do not forward `email` or other claims users can change (or that may be unverified) as an identity, unless you also require `email_verified` through `required_claims`.

Rules: a forwarded claim must be a string of printable ASCII (at most 256 bytes); if it is missing or unsafe, the token is treated as invalid and no pass is issued. Header names such as `Authorization`, `Cookie` and `Host` are refused. **Strip every forwarded header name from client requests** at the proxy, as for `Tenant-Pass`.

For cookie sessions, use a dedicated cookie for the identity provider session and remove it in the proxy (nginx: rewrite `$http_cookie`; Caddy: a `request_header` with a regular-expression replacement), so the application keeps its own cookies but never sees the IdP session.

## Cookie sessions across tenant hosts

When one application serves the hosts of many tenants and a user's session cookie is sent to all of them (a cookie with `Domain=.billing.example.com`), a compromised application can make the user's browser visit **other** tenants' hosts and collect a pass for each tenant the user belongs to. It can embed them (images, iframes), redirect through them, or navigate to them. Every such request goes through the proxy to the same compromised application.

**The boundary that stops this is session scoping, not request headers:**

1. **Host-only session cookies.** Issue the session cookie per tenant host, without a `Domain` attribute, ideally with the `__Host-` prefix (`Set-Cookie: __Host-session=…; Secure; Path=/; HttpOnly; SameSite=Lax`). The browser then sends the acme session only to `acme.billing.example.com`, and a visit to another tenant's host carries no session at all.
2. **Single-tenant tokens.** Set `identity.single_tenant_tokens: true` and have your login service issue one token per tenant (a tenant claim naming exactly one tenant). A token for acme can then never yield a pass for any other tenant, whatever the browser is made to do.

Users who belong to several tenants then log in (or use single sign-on) per tenant host. Use both measures for any deployment where tenants share an application.

**Fetch Metadata (defence in depth).** With `identity.cookie_fetch_metadata: "enforce"` (the default), a token from the **cookie** is used only when the browser's Fetch Metadata headers show a same-origin request (`Sec-Fetch-Site: same-origin`), a typed address or bookmark (`none`), or a top-level navigation the user activated (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-User: ?1`); requests without Fetch Metadata get no pass. This stops passive cross-host requests (an `<img>` pointing at another tenant's host). It is **not** a boundary against a compromised application, because that application also serves the other tenants' pages. It can frame or navigate to them and have them make same-origin requests, and user activation survives redirects. The proxy must pass `Sec-Fetch-*` headers to the gateway (Caddy and nginx do by default; see Traefik and Envoy above). Set `"off"` only for non-browser clients that use cookies.

Tokens in the `Authorization` header are not affected (browsers do not send them automatically). Several cookies with the session name are treated as no session (a cookie tossed in from a sibling host could otherwise log the user into an attacker's session).

## Residual risks

- **Multi-tenant sessions.** Unless sessions are scoped per tenant (host-only cookies and `single_tenant_tokens`, above), a compromised application can obtain passes for every tenant in a user's tenant claim while the user's session is valid — by replaying a token it has seen, or by making the user's browser visit the other tenants' hosts. `forward_claims` with token stripping removes the replay path; caller authentication (mandatory off loopback) blocks direct calls to the gateway; Fetch Metadata blocks passive cross-host requests. Only session scoping closes the browser path completely.
- **Load on the KMS.** With a Transit signing key, every authenticated request causes one Vault sign operation. Size Vault accordingly, and rate-limit at the proxy if needed.

## Deployment

- Run next to the proxy (same host or pod) on loopback, or on an internal network with TLS and `client_ca_file` or `caller_secret_file`.
- Applications must not be able to reach the gateway. If they could, they could ask for passes with any `X-Forwarded-Host` — but they would still need a valid user session for that tenant.
- Keep the signing key only here (or in Vault Transit). tenant-pass needs only the public key.
- The gateway logs one JSON line per decision (`host`, `app`, `tenant`, `result`, `reason`) and never logs tokens or passes.
