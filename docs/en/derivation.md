# Password derivation (tenant-pass/v1)

[日本語](../ja/derivation.md)

This document specifies how tenant-pass computes windows and passwords, so that the scheme can be reviewed and re-implemented. The Go implementation is `internal/rotation`; an independent Python implementation, used to generate the test vectors below, is `scripts/derivation_vectors.py`.

## Notation

- `LP(x)`: 4-byte big-endian length of `x` in bytes, followed by `x` (UTF-8).
- `BE64(n)`: `n` as a signed 64-bit big-endian integer (two's complement).
- `||`: concatenation.
- `A = LP(store) || LP(node) || LP(account)` where `store` is `postgres`, `mysql` or `redis`, `node` is the configured node name and `account` the account name.
- `W`: window length in seconds (`rotation.window`).

## Window offset and numbering

```
offset = uint64_be(SHA-256("tenant-pass/v1/offset" || A)[0:8]) mod W
n(t)   = floor((unix(t) − offset) / W)
Start(n) = n·W + offset          (Unix seconds)
End(n)   = Start(n + 1)
```

The offset spreads account rotations evenly over the window. It does not depend on any key.

## Key selection

Each rotation key has an ID and a `not_before` time. Window `n` uses the key with the latest `not_before ≤ Start(n)`. If no key qualifies, no password exists for that window.

## Password and salt

With `K` the selected key's secret and `id` its ID:

```
password(n) = base64url_nopad( HMAC-SHA256(K, "tenant-pass/v1/password" || A || LP(id) || BE64(n)) )   → 43 chars
salt(n)     =                  HMAC-SHA256(K, "tenant-pass/v1/salt"     || A || LP(id) || BE64(n))     → 32 bytes
```

The salt is used by stores that hash passwords on the client side:

- **PostgreSQL** SCRAM-SHA-256 verifier: salt = `salt(n)[0:16]`, 4096 iterations.
- **MySQL** `caching_sha2_password`: the first 20 bytes of `salt(n)`, each mapped to the crypt alphabet `./0-9A-Za-z` by `alphabet[b & 0x3f]`; 5000 rounds.
- **Redis**: no salt; the ACL hash is `hex(SHA-256(password))`.

## Target window and renewal

```
target(t) = n(t) + 1   if End(n(t)) − t ≤ renew_before
          = n(t)       otherwise
refresh_at(n) = End(n) − renew_before
```

## Test vectors

Key secret: bytes `00 01 02 … 1f` (32 bytes). Key ID `k1`, `not_before` before all windows. `W = 900`. Time `t = 2026-11-03T12:00:00Z` (Unix 1793707200).

| store / node / account | offset | n | Start | password(n) |
| --- | --- | --- | --- | --- |
| postgres / pg1 / t_acme | 539 | 1993007 | 1793706839 | `umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM` |
| mysql / my1 / t_acme | 601 | 1993007 | 1793706901 | `lRJgB4tM38aEGO4myi2zfoNWJK1vHuH-yu08BLhnjoU` |
| redis / rd1 / t_acme | 86 | 1993007 | 1793706386 | `tCGHXsj_Vw3vLJeWcto3NlgDT5WlxI3kq_yAAHsajeg` |

Salts (hex):

- postgres: `ad3ceaff85f2029e16b5cf5890e411627895fe6d5367e8fc9818f4cd3b8ac398`
- mysql: `fa0dfbe05a2c07ae34e8eeec3d7a69aeaa9b60ab100db11c12d05615995b40f6`
- redis: `c493c646278a7ec0e7d27fe9acc557c08f7e8842fead295a7ef5a3107f9f0a84`

PostgreSQL SCRAM verifier for the postgres row:

```
SCRAM-SHA-256$4096:rTzq/4XyAp4Wtc9YkOQRYg==$dwzLPDwP/7CwnPhHw/zWb7+XLxlpfEhoPyPLHE7dO9M=:7ljzKIBLT3xRViFwPrWVsXfr5RljubwmeqecuseE4yU=
```

Redis ACL hash for the redis row: `bd4475de5ef98729dc284dc27d1add155bb43ee7e74f34c45631e5fc3ffbb501`.

The MySQL SHA-crypt implementation is tested against OpenSSL (`openssl passwd -5`) and against hashes produced by a real MySQL 8.4 server (`internal/pwhash/pwhash_test.go`).

## Security notes

- Length prefixes make the HMAC input injective: `("ab","c")` and `("a","bc")` cannot collide.
- Distinct labels (`password`, `salt`, `offset`) separate the uses of the key and the hash.
- The store type is part of the input, so the same account name on a PostgreSQL and a Redis node gets unrelated passwords even under the same key.
- The key ID is part of the input, so renaming a key changes every password derived from it.
- Anyone holding `K` can compute any password derived from it. Protect rotation keys accordingly, and rotate them if exposure is suspected.
