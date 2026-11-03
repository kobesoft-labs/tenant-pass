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
    "leeway": "30s"
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
| `tls` | | `cert_file`, `key_file`; `client_ca_file` makes client certificates **required** (only the proxy may call). |
| `insecure_plaintext_http` | `false` | Plain HTTP. Allowed on a loopback address (sidecar next to the proxy); elsewhere requires `allow_insecure_plaintext` (testing only). |
| `caller_secret_file` | | If set, callers must send `Tenant-Pass-Gateway-Secret` with this value (≥ 16 characters). |
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
    proxy_set_header Tenant-Pass-Gateway-Secret "<secret>";
}

location / {
    auth_request /_tenant_pass_auth;
    auth_request_set $tenant_pass $upstream_http_tenant_pass;
    # Always set: an empty value removes any client-supplied header.
    proxy_set_header Tenant-Pass $tenant_pass;
    proxy_pass http://billing:8080;
}
```

### Traefik

```yaml
http:
  middlewares:
    strip-pass:
      headers:
        customRequestHeaders:
          Tenant-Pass: ""          # removes the client's header
    tenant-pass:
      forwardAuth:
        address: http://127.0.0.1:9180/
        authResponseHeaders: ["Tenant-Pass"]
        authRequestHeaders: ["Authorization", "Cookie", "X-Forwarded-Host"]
  routers:
    billing:
      rule: HostRegexp(`^[a-z0-9-]+\.billing\.example\.com$`)
      middlewares: [strip-pass, tenant-pass]
      service: billing
```

### Envoy (ext_authz, HTTP)

Set `request.host_header` to `Host`, allow `authorization` and `cookie` in `allowed_headers`, add `tenant-pass` to `allowed_upstream_headers`, and remove `tenant-pass` from incoming requests with `request_headers_to_remove` on the route.

Verify your proxy before going live: a request **without** a session but **with** a forged `Tenant-Pass` header must reach the application without that header.

## Residual risks

- **The application sees the user's session token.** The proxy forwards cookies and `Authorization` to the application, as usual. A compromised application can replay a user's session token to the gateway (or through the proxy) and obtain passes for every tenant in that user's tenant claim, until the token expires. Mitigations: protect the gateway with `caller_secret_file` or mTLS (`client_ca_file`) so only the proxy can call it; keep session tokens short-lived or set `identity.max_token_age`; give staff accounts that belong to many tenants separate, short sessions; and where the application does not need the raw session credential, have the proxy remove it before forwarding.
- **Load on the KMS.** With a Transit signing key, every authenticated request causes one Vault sign operation. Size Vault accordingly, and rate-limit at the proxy if needed.

## Deployment

- Run next to the proxy (same host or pod) on loopback, or on an internal network with TLS and `client_ca_file` or `caller_secret_file`.
- Applications must not be able to reach the gateway. If they could, they could ask for passes with any `X-Forwarded-Host` — but they would still need a valid user session for that tenant.
- Keep the signing key only here (or in Vault Transit). tenant-pass needs only the public key.
- The gateway logs one JSON line per decision (`host`, `app`, `tenant`, `result`, `reason`) and never logs tokens or passes.
