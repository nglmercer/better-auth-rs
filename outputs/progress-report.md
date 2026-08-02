# Better Auth Rust Rewrite — Progress Report

**Report date:** 2026-08-01
**Baseline commit:** 24dc526
**Current status:** The roadmap has an end-to-end framework-neutral implementation baseline. Remaining work is protocol conformance, provider integration, and live infrastructure testing.

## Summary

The Rust rewrite now covers the core runtime, configuration, schema and migration contracts, SQLite plus optional Postgres/MySQL adapters, email/password sessions, JWT/JWE cookie caching, CSRF and rate limiting, OAuth/PKCE with configurable OIDC ID-token validation, encrypted provider-token envelopes, advanced plugin services, WebAuthn ceremony verification through webauthn-rs, an HTTP router, Axum integration, and a retry-capable client SDK.

## Roadmap status

| Phase | Status | Current implementation |
|---|---|---|
| 0. Core types and traits | Complete | Options, errors, adapter contracts, schema, migrations, plugins |
| 1. AuthContext and config | Complete | Defaults, secrets, static/dynamic base URLs, allowed hosts |
| 2. Adapters and schema | Complete baseline | Atomic CRUD/KV adapters, TTL, SQLite, optional SQLx Postgres/MySQL adapters, dialect-aware migration runner |
| 3. Email/password and sessions | Complete baseline | Sign-up/sign-in, scrypt, sessions, refresh, sign-out, JWE/JWT/opaque cookies, email verification, password reset |
| 4. CSRF and security middleware | Complete baseline | Origin, Fetch Metadata, SameSite=Lax, trusted proxy/IP handling, rate limiting |
| 5. Plugin system | Complete | Endpoint/hook/schema/error registry and collision detection |
| 6. OAuth/social/PKCE | Complete baseline | Single-use state, PKCE S256, nonce binding, configurable OIDC signature/issuer/audience validation, encrypted provider-token envelopes, Google/GitHub HTTP providers |
| 7. Advanced plugins | Complete baseline | TOTP/backup codes, organizations, admin roles, passkeys, WebAuthn registration/assertion verification, SSO/OIDC connection records, SAML validation contract, SCIM filters/pagination/bulk/resource CRUD/tokens, JWT |
| 8. Client/framework integrations | Complete baseline | JSON HTTP router, optional Axum adapter, reqwest cookie-jar transport, safe retry policy with backoff and Retry-After handling |

## Verification

The latest verification commands all pass:

~~~text
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features
~~~

Test result: **35 passed, 0 failed** — 32 tests in better-auth and 3 in better-auth-core. The optional Axum and SQLx features were included in the check and test run.

## Remaining production work

1. SAML still needs a concrete XML parser/canonicalization and certificate/JWKS-backed signature adapter for each deployment. The framework-neutral validator now enforces issuer, audience, ACS recipient, time bounds, request binding, and delegated signature verification.
2. SCIM needs the full RFC 7644 filter grammar, multi-operation PATCH semantics, Groups, and deployment-level bearer-token middleware. The core user resource, allow-listed filters (eq, co, sw, pr), pagination, bulk transaction behavior, and token hashing are implemented.
3. Postgres/MySQL adapters need live integration/conformance tests against both database engines. The optional SQLx implementations and dialect-specific migration execution are present.
4. WebAuthn needs browser ceremony and durable credential-store integration tests. Registration, assertion verification, origin/RP-ID checks, signature checks, and counter updates are delegated to webauthn-rs.
5. OIDC deployments need provider JWKS discovery/rotation wiring; the validator accepts configured RSA/EC keys and enforces signature, issuer, audience, expiry, and nonce checks.
6. Browser-specific client bindings and framework-specific examples remain outside the framework-neutral client and Axum adapter.

## Recommended next sequence

1. Add live Postgres/MySQL conformance tests and run migrations against clean databases.
2. Add a vetted SAML XML/signature integration and browser-level WebAuthn tests.
3. Complete SCIM RFC surfaces and bearer-token middleware.
4. Add OIDC JWKS discovery/rotation and browser client examples.
5. Run dependency, threat-model, and external security review before production release.
