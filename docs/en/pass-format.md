# Pass format (tenant-pass/v1)

[日本語](../ja/pass-format.md)

This is the normative specification of a pass. Gateway implementers need only this document and a PASETO v4 library. The Go implementation is in the [`pass`](../../pass) package and can be imported directly.

## Token

A pass is a [PASETO](https://github.com/paseto-standard/paseto-spec) **v4.public** token (Ed25519):

```
v4.public.<base64url(message || signature)>.<base64url(footer)>
```

| Part | Value |
| --- | --- |
| Version / purpose | `v4.public` only. Any other header is rejected. |
| Implicit assertion | The exact ASCII bytes `tenant-pass/v1/pass`. Required. Signed, not transmitted. |
| Footer | Required. JSON object `{"kid":"<key ID>"}` — nothing else. At most 256 bytes. |
| Message | JSON object with the claims below. |
| Total length | At most 2048 bytes. |

Base64url is unpadded, and non-canonical encodings (non-zero unused bits) are rejected.

The implicit assertion provides domain separation: a token signed with the same key for any other purpose — or for a future tenant-pass version — fails verification. **Do not omit it.** Most PASETO libraries accept it as a parameter of `sign` / `verify` (sometimes called "implicit assertion" or `i`).

## Footer

```json
{"kid":"gw1"}
```

`kid` must match `^[a-z][a-z0-9_-]{0,62}$` and must be one of the `gateway_keys[].id` values configured in tenant-pass. tenant-pass reads the footer before verification only to choose the key; the footer is covered by the signature.

## Claims

The message is a JSON object with **exactly** these members. Unknown members and duplicate members are rejected.

| Claim | Required | Format | Meaning |
| --- | --- | --- | --- |
| `aud` | yes | `^[a-z][a-z0-9_-]{0,62}$` | Name of the application the gateway forwards the request to (an `apps[].name` in tenant-pass). |
| `host` | one of `host` / `tenant` | canonical host name (below) | Host name of the request. tenant-pass resolves it with the directory's `by_host` lookup. |
| `tenant` | one of `host` / `tenant` | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | Tenant ID, if the gateway already knows it. Resolved with `by_tenant`. |
| `iat` | yes | `YYYY-MM-DDTHH:MM:SSZ` | Issued at. UTC, whole seconds, `Z` suffix. |
| `exp` | yes | `YYYY-MM-DDTHH:MM:SSZ` | Expires at. Same format. |
| `jti` | yes | `^[A-Za-z0-9_-]{16,128}$` | Random identifier, at least 128 bits recommended. Logged by tenant-pass for correlation with gateway logs. |

### Canonical host names

tenant-pass does not normalize; the gateway must send exactly:

- lower-case ASCII letters, digits and `-`, in labels separated by `.`;
- internationalized names converted to A-labels (`xn--…`);
- no port, no trailing dot, no empty labels;
- each label 1–63 characters, not starting or ending with `-`;
- at most 253 characters, at least two labels;
- not an IP address.

### Time rules

With `now` = tenant-pass's clock and `leeway` = `pass.leeway` (default 5 s):

- `exp > iat`
- `exp − iat ≤ pass.max_ttl` (default 60 s; hard maximum 300 s)
- `now < exp` (no leeway on expiry)
- `iat ≤ now + leeway`

Recommended: `exp = iat + 30s`.

## Verification order (tenant-pass)

1. Length ≤ 2048, header `v4.public.`, footer present.
2. Footer parsed strictly; `kid` looked up. Unknown → reject.
3. Signature verified with that key and the implicit assertion.
4. Claims parsed strictly and validated (formats, exactly one of `host`/`tenant`).
5. Lifetime and time rules.
6. `aud` compared with the authenticated application.

## Test vector

| Input | Value |
| --- | --- |
| Ed25519 seed | 32 bytes of `0x01` |
| Public key (hex) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| Footer | `{"kid":"gw1"}` |
| Implicit assertion | `tenant-pass/v1/pass` |
| Message | `{"aud":"billing","host":"acme.example.com","iat":"2026-11-03T12:00:00Z","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA"}` |

Expected token (Ed25519 is deterministic, so a conforming signer produces exactly this):

```
v4.public.eyJhdWQiOiJiaWxsaW5nIiwiaG9zdCI6ImFjbWUuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDI2LTExLTAzVDEyOjAwOjAwWiIsImV4cCI6IjIwMjYtMTEtMDNUMTI6MDA6MzBaIiwianRpIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9lGRulfEQdJnx_Iagf4Fp94_8eSIifNPHT82HGA8KqWhSX_KikCQafPjF2Ntupw3XnYtRoZ6xe1-uf46uZcHoDQ.eyJraWQiOiJndzEifQ
```

Your implementation should produce this token byte for byte, and tenant-pass's verifier (with a clock between `iat` and `exp`) accepts it. The test is `TestPublishedVector` in `pass/pass_test.go`. The underlying PASETO implementation is checked against the official PASETO v4 test vectors.

## Examples

### Go

```go
import "github.com/kobesoft-labs/tenant-pass/pass"

s := pass.Signer{KeyID: "gw1", Key: privateKey} // ed25519.PrivateKey
now := time.Now()
p, err := s.Sign(pass.Claims{
    Audience: "billing",
    Host:     "acme.example.com",
    IssuedAt: now,
    Expiry:   now.Add(30 * time.Second),
})
```

### PHP (paragonie/paseto, low-level API)

paragonie/paseto's high-level `Builder` JSON-encodes implicit assertions, so use the protocol class directly, which takes the implicit assertion as a raw string:

```php
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;

$now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$claims = json_encode([
    'aud'  => 'billing',
    'host' => 'acme.example.com',
    'iat'  => $now->format('Y-m-d\TH:i:s\Z'),
    'exp'  => $now->modify('+30 seconds')->format('Y-m-d\TH:i:s\Z'),
    'jti'  => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

$token = Version4::sign(
    $claims,
    new AsymmetricSecretKey($secretKeyBytes, new Version4()),
    '{"kid":"gw1"}',          // footer
    'tenant-pass/v1/pass'     // implicit assertion (exact bytes)
);
```

Note: some libraries add their own claims by default (for example a default `exp` in a different format, or `nbf`) or encode implicit assertions as JSON. Library APIs also change between major versions. tenant-pass rejects unknown claims and requires the implicit assertion to be the exact bytes `tenant-pass/v1/pass`. Check your library's output against the test vector above before deploying; if the library cannot produce it, use the low-level PASETO sign primitive directly.
