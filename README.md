# Better Auth for Rust

This repository is the initial Rust rewrite foundation described by the
attached architecture roadmap. It is framework-neutral: an Axum, Actix, or
other integration can translate its native requests into `RequestMetadata` and
use the same auth context and security behavior.

## Workspace layout

- `crates/better-auth-core` contains shared options, adapter traits, schema
  definitions, and the plugin registry.
- `crates/better-auth` contains the runtime `AuthContext`, per-request base URL
  resolution, cookies, secret rotation, scrypt password hashing, and CSRF/IP
  helpers.

## Current implementation

The workspace now covers all roadmap phases at a framework-neutral baseline:

- configuration validation and the no-durable-store cookie-cache defaults;
- static, request-derived, and allowed-host dynamic base URLs;
- relational and secondary-storage adapter contracts, including TTL and atomic
  increment semantics;
- core schema plus conflict-safe plugin schema merging;
- plugin endpoints, hooks, and error-code aggregation;
- versioned HMAC envelopes for direct secret-version lookup during rotation;
- scrypt password hashing;
- SameSite=Lax session-cookie construction;
- Origin, Fetch Metadata, trusted-proxy, and trusted-IP-header helpers.
- email/password sign-up and sign-in, persisted sessions, cookie lookup, and
  sign-out on top of the adapter contract.
- JWT/JWE cookie-cache codecs with key-version lookup and session refresh.
- purpose-bound email verification and password-reset tokens.
- rate-limit enforcement backed by atomic secondary-storage increments.
- OAuth authorization state, PKCE, generic HTTPS provider exchange, and
  Google/GitHub provider presets.
- TOTP and one-time backup codes, organization membership, passkey challenge
  replay protection, admin role guards, SSO connection persistence, SCIM user
  persistence/token hashing, and JWT issuance.
- framework-neutral HTTP endpoints, an optional Axum adapter, and a client
  request SDK with reqwest transport and cookie-jar support.
- SQLite relational and secondary-storage adapters plus dialect-neutral
  migration plan generation.

The remaining work is production-hardening rather than missing architecture:
full WebAuthn attestation/assertion cryptography, SAML-specific SSO, full SCIM
protocol pagination/filtering, concrete production database adapters, and a
retry policy. Postgres/MySQL adapters, OAuth ID-token validation, and provider
token encryption are also production-hardening items. The traits are
intentionally small so those features can be added without making the core
depend on a database or web framework.

## Verify

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```
