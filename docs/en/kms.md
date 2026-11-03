# Key management (Vault / OpenBao Transit)

[日本語](../ja/kms.md)

tenant-pass and tenant-pass-gateway can keep their keys in a key management system instead of in files. Supported: **HashiCorp Vault** and **OpenBao**, using the **Transit** secrets engine.

| Key | Used by | Transit key type | Operation |
| --- | --- | --- | --- |
| Rotation keys (password derivation) | tenant-pass | `hmac` | `transit/hmac/<key>/sha2-256` |
| Job ticket signing key | tenant-pass | `ed25519` | `transit/sign/<key>` |
| Gateway signing key | tenant-pass-gateway | `ed25519` | `transit/sign/<key>` |

## What it buys

With file keys, an attacker who gets into a tenant-pass host can copy the rotation key and derive every tenant's passwords **offline, for as long as the key is in force**, even after you have evicted them.

With Transit, the key never leaves Vault. The attacker can use it only **while** they control the host and its Vault token; once you revoke the token, they cannot derive anything. Vault's audit log records every use.

It does not protect against an attacker who is in control of the host right now.

## Correctness

- **HMAC is standard.** Transit's `hmac/…/sha2-256` is plain HMAC-SHA256 with the key material, so the [derivation specification](derivation.md) and its test vectors are unchanged. (Tested by comparing Transit's output with a local HMAC over an exported test key.)
- **Versions are pinned.** Each rotation key names a Transit key **and** a version. Passwords must stay the same for as long as a rotation key is in force, so tenant-pass always asks for that exact version and rejects a response for any other.
- **Signatures are checked locally.** After Transit signs, tenant-pass verifies the signature with the public key it read at startup. A misconfigured Transit key cannot make tenant-pass emit tokens that fail verification.
- **Caching.** Derived values are cached in memory per account and window (bounded, expiring), so Transit is called about twice per account per window, not on every request.

## Setup

```sh
vault secrets enable transit
vault write -f transit/keys/tenant-pass-rotation type=hmac key_size=32
vault write -f transit/keys/tenant-pass-jobs type=ed25519
vault write -f transit/keys/tenant-pass-gateway type=ed25519
```

Do not make the keys exportable.

Policies (least privilege, one per component):

```hcl
# tenant-pass
path "transit/hmac/tenant-pass-rotation/*" { capabilities = ["update"] }
path "transit/sign/tenant-pass-jobs"       { capabilities = ["update"] }
path "transit/keys/tenant-pass-jobs"       { capabilities = ["read"] }
```

```hcl
# tenant-pass-gateway
path "transit/sign/tenant-pass-gateway" { capabilities = ["update"] }
path "transit/keys/tenant-pass-gateway" { capabilities = ["read"] }
```

Authenticate with any Vault auth method (Kubernetes, AppRole, cloud IAM) through **Vault Agent** or a sidecar that writes the token to a file. tenant-pass re-reads the token file on every request, so renewed tokens are picked up without a restart.

## Configuration

```json
"kms": {
  "vault": {
    "address": "https://vault.internal:8200",
    "token_file": "/run/vault/token",
    "namespace": "",
    "mount": "transit",
    "tls": {"ca_file": "/etc/tenant-pass/vault-ca.pem"}
  }
},
"rotation": {
  "keys": [
    {"id": "r-2026-11", "transit": {"key": "tenant-pass-rotation", "version": 1}, "not_before": "2026-11-01T00:00:00Z"}
  ]
},
"job_tickets": {
  "signing_key": {"id": "tp-jobs-1", "transit": {"key": "tenant-pass-jobs", "version": 1}}
}
```

| Key | Description |
| --- | --- |
| `address` | Base URL. `https` required unless `insecure_plaintext` (plus top-level `allow_insecure_plaintext`, testing only). |
| `token_file` | File with the Vault token. Secret-file rules apply; re-read on every request. |
| `namespace` | Sent as `X-Vault-Namespace` (Vault Enterprise / HCP). |
| `mount` | Transit mount path, default `transit`. |
| `tls` | `ca_file`, `server_name`, `cert_file`/`key_file` (client certificate auth). Verification is always on. |

The client never follows redirects (which could send the token elsewhere) and does not use an HTTP proxy from the environment. Point `address` at the active node (or a load balancer that routes only to it): a standby that answers with a redirect is treated as an error. Errors report the HTTP status only, never response bodies or the token.

The gateway uses the same `kms.vault` block and `signing_key.transit`.

## Rotating Transit keys

**Rotation key.** `vault write -f transit/keys/tenant-pass-rotation/rotate` creates version 2. Add it as a **new** rotation key with a future `not_before`, exactly like a file key ([operations.md](operations.md#rotation-key-rotation)):

```json
{"id": "r-2026-12", "transit": {"key": "tenant-pass-rotation", "version": 2}, "not_before": "2026-12-01T03:00:00Z"}
```

Keep version 1 available in Transit (`min_available_version`) until the old rotation key is removed from the configuration.

**Signing keys.** Rotate in Transit, then configure the new version under a new `id`, and publish the new public key to the verifiers (tenant-pass `gateway_keys` for the gateway; the job verifier picks up tenant-pass's own job key automatically). Keep the old key ID trusted until passes or tickets signed with it have expired.

## Public keys

To configure tenant-pass's `gateway_keys` for a Transit-held gateway key, convert the public key to PEM:

```sh
vault read -field=keys -format=json transit/keys/tenant-pass-gateway \
  | jq -r '."1".public_key' | base64 -d > gw.raw
# Ed25519 SubjectPublicKeyInfo prefix (octal escapes work in every POSIX printf)
( printf '\060\052\060\005\006\003\053\145\160\003\041\000'; cat gw.raw ) \
  | openssl pkey -pubin -inform DER -outform PEM > gateway-2026-11.pub
```

## Availability

With Transit keys, tenant-pass needs Vault to derive passwords that are not cached. If Vault is unreachable, requests for uncached windows fail with `503 unavailable` (audit `store_error`, error mentions `kms`). Run Vault highly available, and alert on these errors.
