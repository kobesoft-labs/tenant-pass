# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `POST /v1/credentials`: exchange a gateway-signed pass for a short-lived tenant credential.
- Pass format `tenant-pass/v1` (PASETO v4.public, Ed25519) with test vectors, and the `pass` Go package for gateways.
- Deterministic, stateless password derivation `tenant-pass/v1` with per-account window offsets, key schedule with `not_before`, and test vectors from an independent Python implementation.
- Stores: PostgreSQL (SCRAM verifier, `VALID UNTIL`), MySQL (`caching_sha2_password` hash, dual passwords, sweeper), Redis/Valkey (ACL hashes, multiple passwords, sweeper, multi-server).
- Account safety checks per store, including inherited privileges (PostgreSQL), global/role/proxy privileges (MySQL) and `ACL DRYRUN` probes plus a managed marker (Redis).
- Clock check against each store server before writing.
- Directories: static and SQL (PostgreSQL/MySQL, read-only transactions, validated at startup).
- Application authentication by bearer token hash and/or client certificate URI SAN.
- Distinct-tenant rate limit per application; repair rate limit; concurrency limit.
- Commands: `serve`, `check-config`, `gen-gateway-key`, `gen-rotation-key`, `gen-app-token`, `sign-pass`, `version`.
- Job tickets (`tenant-pass/v1/job`): `POST /v1/job-tickets` (opt-in per application) and trusted external issuers for scheduled work; `sign-job-ticket` and `gen-signing-key` commands.
- Key management through HashiCorp Vault / OpenBao Transit: rotation keys (HMAC, version-pinned), job ticket signing key and gateway signing key (Ed25519, verified locally).
- `tenant-pass-gateway`: forward-auth gateway for Caddy, nginx, Traefik and Envoy. Verifies identity-provider JWTs (JWKS, asymmetric algorithms only) and signs passes only for the user's own tenant.
- Gateway `identity.forward_claims`: forward verified user claims as headers so applications never need the session token; caller authentication (secret or mTLS) is mandatory on non-loopback addresses.
- Each pass can be exchanged for at most one job ticket (per replica).
- Documentation in English and Japanese.

### Security (third review)

- Reject small-order and non-canonical Ed25519 public keys (gateway keys, job ticket issuers, Transit keys): a degenerate key would let anyone forge passes.
- Trust anchors (public keys, CA bundles, certificates, JWKS, configuration) get the same integrity checks as secrets, including file owner; files are opened once and checked on the open descriptor; TLS key pairs are loaded from the checked bytes.
- Strict JSON: object keys must match field names exactly (Go's case-insensitive matching, including Unicode folding, re-opened parser differentials).
- Derivation now includes the window length, so changing `rotation.window` cannot revive old passwords. (Test vectors changed.)
- PostgreSQL: requires 16+, a dedicated admin database that tenants cannot connect to (advisory-lock contention by tenants), and refuses ADMIN OPTION held through parent roles.
- MySQL: wildcard database grants matching system schemas are refused; the managed role must be empty; lock names are unpredictable; the server clock is read time-zone independently.
- Redis: probes for SCAN/RANDOMKEY/PUBSUB/DBSIZE/OBJECT and partial key patterns; a user deleted mid-check is refused; the sweeper skips privileged users and sweeps each server independently.
- Gateway: mTLS callers must match pinned SANs; duplicate session cookies are refused; Fetch Metadata enforcement for cookie sessions; no health path on the forward-auth listener.
- Job tickets: per-application replay quota with FIFO expiry; a pass is released if issuing fails.
- Ambiguous client certificates (several matching URI SANs) are refused; static directory refuses two tenants sharing an account; LRU derive cache; explicit zero leeway honoured; `check-config` runs every startup check.
- Release workflow: images pushed with SBOM and SLSA provenance and signed with Sigstore.
