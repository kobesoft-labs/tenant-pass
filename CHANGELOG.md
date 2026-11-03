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
- Documentation in English and Japanese.
