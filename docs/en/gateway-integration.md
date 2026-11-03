# Gateway integration

[日本語](../ja/gateway-integration.md)

The gateway is the component that decides which requests deserve a pass. **The security of tenant-pass depends on this decision.** Read the [threat model](threat-model.md#residual-risk-the-gateway) first.

tenant-pass ships a ready-made gateway, [tenant-pass-gateway](gateway.md), which follows every rule below. This page is for building passes into a component of your own.

## The rule

> Sign a pass for tenant T and application A **only** when the gateway itself has verified that the request is authorized for tenant T — an authenticated user session that belongs to T, or a signed job authorization for T — and the gateway is forwarding that request to A.

A pass is not a routing hint. It is a capability: "you may obtain tenant T's credential now".

## Do

- Authenticate the end user's session (cookie, OIDC token, mTLS) **before** signing, and check that the session belongs to the tenant of the requested host. A valid session for tenant B must not produce a pass for tenant A's host.
- Use the canonical host name (lower case, no port, no trailing dot, IDN as A-label). Do not copy the `Host` header verbatim without normalizing and validating it against your list of tenant domains.
- Set `aud` to the application that will actually receive the request (the upstream you route to), not to something from the request.
- Keep passes short: `exp = iat + 30s` is plenty for a request handler.
- Generate `jti` from a CSPRNG (16 bytes, base64url) and log it, so audit logs can be correlated.
- Pass the token to the application in a request header that clients cannot set, for example `Tenant-Pass`. **Strip that header from incoming client requests** first, at the edge.
- Keep the private key only on the gateway, in a file readable by the gateway process alone, or in an HSM/KMS.
- Prefer one key per gateway deployment (`kid` per environment/cluster), so a single key can be revoked.

## Don't

- Don't sign passes for unauthenticated routes: login, sign-up, password reset, health checks, static assets, public APIs, webhooks from third parties.
- Don't let applications reach the gateway's signing path from inside the network. An application that can send itself a request "through the gateway" with a chosen `Host` header can obtain passes for any tenant. Block it at the network level, or make the gateway sign only for traffic arriving on its public listener.
- Don't sign passes for a host name your tenant directory considers unverified (for example a custom domain whose ownership has not been confirmed).
- Don't reuse a gateway key for anything else. The implicit assertion prevents cross-protocol confusion within PASETO, but separate keys are still simpler to reason about.

## Background jobs

Requests that are not caused by an end user (queues, cron, migrations) have no session for the gateway to check. Do not stretch pass lifetimes for them: use [job tickets](jobs.md).

## Key rotation

1. Generate a new key: `tenant-pass gen-gateway-key -private gw-2026-12.key -public gw-2026-12.pub`.
2. Add the public key to `gateway_keys` on every tenant-pass replica (with a new `id`) and roll them out.
3. Switch the gateway to sign with the new key and `kid`.
4. After `pass.max_ttl` has passed, remove the old key from `gateway_keys` and roll out again.

## Verifying your implementation

Your signer must reproduce the [test vector](pass-format.md#test-vector) byte for byte. You can also check passes against a running tenant-pass with `curl` (see the [README](../../README.md#quick-start)), or decode them locally:

```sh
tenant-pass sign-pass -key gw.key -kid gw1 -aud billing -host acme.example.com   # reference output
```

## Example: forward-auth

Many proxies (Caddy `forward_auth`, nginx `auth_request`, Traefik ForwardAuth, Envoy `ext_authz`) can call an authorization service before forwarding. A small service can then:

1. receive the original request's headers;
2. validate the session and map it to a tenant;
3. check that the requested host belongs to that tenant;
4. return `200` with a `Tenant-Pass: <pass>` response header, which the proxy copies onto the upstream request;
5. return `401`/`403` otherwise (and never a pass).

The `pass` Go package (`pass.Signer`) is all such a service needs from tenant-pass.
