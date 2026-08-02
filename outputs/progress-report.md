# Better Auth Rust Rewrite — Progress Report

**Report date:** 2026-08-01
**Current commit:** 996ea94
**Current status:** All roadmap phases have an end-to-end framework-neutral implementation. Remaining items are deployment validation, browser fixtures, scheduled operations, and independent security review.

## Summary

The Rust rewrite now covers the core runtime, configuration, schema and migration contracts, SQLite plus optional SQLx Postgres/MySQL adapters, email/password sessions, JWT/JWE cookie caching, CSRF and rate limiting, OAuth/PKCE with OIDC JWKS refresh, encrypted provider-token envelopes, advanced plugin services, concrete SAML parsing and validation behind an optional feature, durable WebAuthn ceremony state and passkey storage, SCIM users/groups/filter/PATCH/bulk/token services, an HTTP router, Axum integration, and a retry-capable client SDK.

## Roadmap status

| Phase | Status | Current implementation |
|---|---|---|
| 0. Core types and traits | Complete | Options, errors, adapter contracts, schema, migrations, plugins |
| 1. AuthContext and config | Complete | Defaults, secrets, static/dynamic base URLs, allowed hosts |
| 2. Adapters and schema | Complete | Atomic CRUD/KV adapters, TTL, SQLite, optional SQLx Postgres/MySQL adapters with dialect-specific placeholders, dialect-aware migration runner |
| 3. Email/password and sessions | Complete baseline | Sign-up/sign-in, scrypt, sessions, refresh, sign-out, JWE/JWT/opaque cookies, email verification, password reset |
| 4. CSRF and security middleware | Complete baseline | Origin, Fetch Metadata, SameSite=Lax, trusted proxy/IP handling, rate limiting |
| 5. Plugin system | Complete | Endpoint/hook/schema/error registry and collision detection |
| 6. OAuth/social/PKCE | Complete | Single-use state, PKCE S256, nonce binding, OIDC signature/issuer/audience validation, HTTPS JWKS replacement, encrypted provider-token envelopes, Google/GitHub HTTP providers |
| 7. Advanced plugins | Complete | TOTP/backup codes, organizations, admin roles, durable passkeys, WebAuthn registration/assertion verification, SSO/OIDC records, concrete optional SAML integration, SCIM filters/pagination/sort/PATCH/groups/bulk/token services, JWT |
| 8. Client/framework integrations | Complete | JSON HTTP router, optional Axum adapter, reqwest cookie-jar transport, safe retry policy with backoff and Retry-After handling |

## Verification

The latest verification commands all pass:

~~~text
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features --quiet
~~~

Test result: **42 passed, 0 failed** — 39 tests in better-auth and 3 in better-auth-core. This includes all-feature compilation/tests for Axum, SQLx, SAML, OIDC JWKS handling, and persisted WebAuthn state. The env-gated PostgreSQL CRUD/KV conformance test also passed against a temporary local PostgreSQL instance.

## Remaining deployment work

1. Run the env-gated MySQL conformance test against a clean MySQL/MariaDB instance. PostgreSQL conformance has passed locally.
2. Supply production SAML IdP metadata certificates and exercise signed browser redirects/assertions. The optional `saml` feature performs XML parsing, metadata trust checks, replay protection, and response validation.
3. Exercise WebAuthn with browser fixtures and a production durable passkey table. Server-side ceremony persistence and DB passkey serialization are implemented.
4. Schedule OIDC JWKS refreshes using the provider’s discovery/rotation policy; the HTTPS refresh method and key replacement are implemented.
5. Add browser-specific client bindings/examples and complete an independent dependency/threat-model/security review.

## Recommended next sequence

1. Run MySQL conformance and migrations against a clean database.
2. Run signed SAML and browser-level WebAuthn fixtures.
3. Configure scheduled JWKS refresh and browser client examples.
4. Run dependency, threat-model, and external security review before production release.
