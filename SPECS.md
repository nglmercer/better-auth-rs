# Better Auth for Rust — Product and Technical Specification

**Status:** Proposed target specification, not a claim of implementation or production readiness  
**Source of truth:** [README](README.md), [current status](docs/roadmap-status.md), [parity matrix](docs/parity/MATRIX.md), [upstream pin](docs/parity/UPSTREAM.md)  
**Scope:** Reusable, framework-neutral authentication library for Rust applications. TikTools Cloud is a potential consumer, **not** the library's architecture or product identity.

## 1. Mission and non-goals

Provide a secure, composable, framework- and database-neutral Rust authentication toolkit with optional HTTP/framework adapters and typed client SDKs. Maintain a documented, explicitly version-pinned compatibility surface with TypeScript Better Auth where practical; intentional security improvements take precedence over wire parity.

Non-goals: a TikTools-specific backend, plugin marketplace, user data sync service, hosted identity SaaS, proprietary provider SDK, or automatic claim of full Better Auth parity.

## 2. Existing baseline (verify against code before implementation)

The repo already contains `better-auth-core`, `better-auth`, TypeScript and Kotlin client packages, SQLite/PostgreSQL/MySQL/libSQL adapters, optional Axum routing, email/password, session lifecycle, OAuth/OIDC building blocks, Google/GitHub integrations, OTP/TOTP, WebAuthn, organization/admin/SSO/SCIM components, and test infrastructure. Many features are **partial** and none is declared production validated by the parity matrix. Avoid reimplementing existing services. See the linked status documents for evidence and exact gaps.

## 3. Architecture and package boundaries

- `better-auth-core`: stable configuration types, provider/adapter contracts, schemas, plugin registry and errors. No HTTP framework dependency.
- `better-auth`: authentication services, policy enforcement, credential/session lifecycle, OAuth/OIDC and plugin orchestration.
- Feature-gated adapters: SQLite, PostgreSQL, MySQL, libSQL, Axum. Add Actix only after demand and integration test coverage.
- `packages/better-auth-client`: fetch-based TypeScript client; `packages/better-auth-kotlin`: Kotlin client. Rust HTTP client must use shared contract tests.
- Examples and integration tests demonstrate wiring without introducing a root production server.
- The application owns its business tables, authorization domain, deployment, HTTP route mounting, and OAuth callback handling. The library must not silently create application-specific users.

Dependency direction: core ← runtime ← framework adapters/examples. Feature flags should not force unused databases, TLS implementations, or web frameworks into consumers.

## 4. Authentication requirements

### 4.1 Accounts, sessions and credentials
- Email/password sign-up, sign-in, verified-email flow, reset, password change and account deletion with enumeration-safe responses.
- Configurable strong password hashing, versioned verification and automatic rehash from explicitly approved legacy formats.
- Server-side revocable sessions, list/revoke, idle and absolute expiration, rotation on sensitive events, configurable secure cookie attributes.
- Optional bearer transport, explicit opt-in; never accept bearer/cookie ambiguously without a documented precedence rule.
- Session and provider tokens must be encrypted or hashed as appropriate; secrets never appear in logs.

### 4.2 Social login and identity linking
- Authorization Code + PKCE, unguessable single-use state, strict redirect allowlists, validated OIDC issuer/audience/nonce/signature/expiry and clock skew.
- Google and GitHub flows; other providers through explicit generic OAuth configuration with verified-email trust mapping.
- Existing provider identity linkage takes priority over email matching; auto-link only when ownership of both emails is established.
- No unsafe fallback on JWKS fetch/refresh failure. Cache keys with expiry, proactive refresh and bounded stale-key behavior.
- Desktop flows use system browser and loopback or app link callbacks with application-side verification, never embedded client secrets.

### 4.3 Strong authentication
- TOTP, recovery codes and optional WebAuthn/passkeys with replay prevention and bounded challenges.
- Second-factor challenge must be completed before issuing a normal session.
- Step-up authentication for high-risk account actions; recovery procedures need explicit abuse controls.

### 4.4 Organizations and authorization
- Strict tenant isolation; roles and ownership constraints; no client-provided role escalation.
- Organization/team invitation lifecycle and permission checks; privileged changes must be audited.
- Plugins can register routes only after collision validation and declared authorization/rate-limit policies.

## 5. Persistence and migrations

- Preserve a framework-neutral adapter contract and real conformance suites for SQLite, PostgreSQL, MySQL and libSQL.
- Ensure atomic uniqueness, transaction isolation, concurrency-safe counters and idempotent migration execution.
- Add migration checksums, drift detection, dry-run and upgrade/rollback documentation.
- No silent migrations during normal database connection.
- Backup/restore drills and key rotation must preserve or explicitly invalidate sessions safely.

## 6. HTTP and client contract

- Versioned OpenAPI contract generated/checked against mounted routes.
- Typed requests, documented status codes and stable public error codes with request IDs; never expose internal errors.
- Secure cookies and CSRF checks for browser flows, Origin/Fetch Metadata controls, trusted proxy policy, strict CORS allowlists and body size limits.
- SDK parity checks against the route manifest for Rust/TypeScript/Kotlin.
- Explicit incompatibilities with pinned upstream Better Auth must be documented, not hidden.

## 7. Security and privacy requirements

- Default-deny privileged routes and tenant-scoped queries; validate authorization at HTTP **and service** boundaries.
- Rate-limit by account and trusted source, with resilient atomic shared storage.
- Secret rotation and key versioning; purpose-bound, one-use verification/reset codes.
- No logging of passwords, cookies, OAuth codes/tokens, backup codes or private keys.
- Dependency advisory scanning, license checks, fuzz/property tests for parsers and adversarial flows.
- External independent security review required before calling the library production validated.
- Minimize retained personal data and support account deletion and session invalidation.

## 8. Quality and compatibility gates

- `cargo fmt --all -- --check`; Clippy strict; all-features build/test; MSRV build; security audit and license checks.
- Database tests must execute against live PostgreSQL/MySQL in CI; skipped tests cannot be counted as green evidence.
- Browser E2E for cookies, CSRF, Google OAuth fixtures, passkeys and recovery; deterministic replay/race tests.
- Route inventory vs SDK and pinned upstream inventories: every missing endpoint explicitly deferred or implemented.
- Versioning: semantic versioning for public Rust/TypeScript/Kotlin APIs; breaking contract changes require migration notes.

## 9. Production acceptance criteria

A release is production-validated only when:
1. All P0/P1 security gates in [ROADMAP](ROADMAP.md) have executable evidence.
2. No unresolved high/critical vulnerability or unreviewed privileged endpoint remains.
3. Supported databases pass live conformance and migration-upgrade fixtures.
4. OAuth issuer/JWKS refresh, session revocation, CSRF, passkey and 2FA tests run in CI.
5. Observability, backups, restoration, rate limits and incident/key rotation runbooks are tested.
6. Compatibility claims are scoped to a named upstream version, with documented deviations.
7. Independent security review findings are remediated or explicitly accepted with rationale.

## 10. TikTools Cloud integration boundary

TikTools Cloud may use `better-auth-rs` for identities, Google sign-in, browser/desktop sessions, and publisher membership. The cloud application must separately own plugin uploads, publisher signing-key delegation, static signed registry generation, and user profile synchronization. Authentication does **not** grant package-signing authority. Plugin trust roots and signatures must remain verifiable offline. Do not add marketplace or sync tables to the generic auth library.

## 11. Source-of-truth policy

This file is a forward-looking specification. Update `docs/roadmap-status.md`, `docs/parity/MATRIX.md`, and the upstream pin whenever implementation or compatibility changes. A checked checkbox means validated evidence, never simply code present.
