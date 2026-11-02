# Better Auth for Rust — Incremental Execution Plan

**Base:** `main` at implementation time. **Workflow:** feature branch → tests → draft PR → review → merge.  
Read [SPECS.md](SPECS.md), [ROADMAP.md](ROADMAP.md), [docs/roadmap-status.md](docs/roadmap-status.md), [docs/parity/MATRIX.md](docs/parity/MATRIX.md), and [docs/parity/UPSTREAM.md](docs/parity/UPSTREAM.md) before modifying code.

## Engineering rules

1. Inspect source/tests first; do not reimplement existing behavior. Keep public APIs stable unless a breaking change is approved.
2. Separate bug fixes, API contract changes, security controls and examples into reviewable PRs.
3. Preserve framework neutrality and feature-gated database/framework dependencies.
4. Maintain security-first, fail-closed identity linking, single-use OAuth state, and pre-session 2FA challenges.
5. For each PR, provide scope, touched modules, threat considerations, test commands/results, skipped tests and rollback notes.
6. Update status/parity/deferred documents when behavior changes; distinguish locally validated from CI-validated.
7. No force-push to `main`, secrets in source, or automatic migration at connection time.
8. Prefer test fixtures over network calls to real Google/GitHub or production identities.

## PR sequence

### PR 1 — Baseline inventory and CI reliability
**Branch:** `chore/evidence-and-route-inventory`

- Reconcile route manifests with endpoint inventories and clients; identify 96/128 count drift if any.
- Improve CI diagnostics to expose skip counts and requirements for live DB tests.
- Capture all-features and MSRV status; do not remove coverage to silence CI failures.
- Add concise `docs/test-evidence.md` with environment, commands and known blockers.

**Acceptance:** deterministic route report; verified local checks; CI green or transparently documented external execution blocker.

### PR 2 — Privileged authorization and policy coverage
**Branch:** `test/authorization-and-proxy-boundaries`

- Table-driven tests for every admin/organization/service entry point.
- Add trusted-proxy IP, CSRF/Origin, Fetch Metadata, CORS and permission negative tests.
- Fix vulnerabilities exposed without changing public success shapes gratuitously.
- Ensure path matching and plugin endpoint registration cannot bypass policy.

**Acceptance:** unauthenticated/cross-tenant escalation tests fail closed; request IDs expose no internal secrets.

### PR 3 — OAuth/OIDC/JWKS hardening
**Branch:** `fix/oauth-jwks-lifecycle`

- Implement cached proactive JWKS refresh with key rotation and bounded outage behavior.
- Test Google/GitHub issuer/audience/nonce/sub, replay, PKCE and verified-email linking.
- Add fixtures for invalid key, unknown kid, stale keys, redirect tampering and callback concurrency.
- Document desktop OAuth callback contract for TikTools Cloud consumers.

**Acceptance:** complete negative fixtures; all OAuth state single-use; no unverified auto-linking.

### PR 4 — Session, 2FA and passkey E2E
**Branch:** `test/session-and-webauthn-e2e`

- Test rotation/revocation for password reset and privileged changes.
- Add Playwright/WebAuthn end-to-end fixtures, including replay and failure.
- Verify no full session is issued until 2FA is satisfied.
- Expose missing SDK methods only with contract tests.

**Acceptance:** browser flows pass repeatably; no replay/partial-session bypass.

### PR 5 — Migration integrity and database resilience
**Branch:** `feat/migration-integrity`

- Add checksum/drift detection and dry-run to migration planning.
- Add schema-upgrade fixtures and live Postgres/MySQL concurrency tests.
- Test remote libSQL if credentials are available; mark environment-gated skips explicitly.
- Exercise backup/restore and secondary-store failure handling.

**Acceptance:** repeatable migration plan; data integrity across supported adapters; known failure semantics documented.

### PR 6 — Generated HTTP contract and SDK coverage
**Branch:** `feat/http-sdk-contracts`

- Define source-of-truth route metadata → OpenAPI generation/check.
- Compare method/path/schema/status with Rust, TypeScript and Kotlin SDK methods.
- Keep intentional upstream wire deviations as explicit tests.
- Add package-level examples with ephemeral local server and cookie jar.

**Acceptance:** no undocumented published endpoint or client signature drift.

### PR 7 — Plugin, enterprise auth and auditing
**Branch:** `fix/plugin-and-enterprise-security`

- Enforce plugin path collision checks and explicit route policies.
- Add persistent audit events for privileged changes (without storing secrets).
- Expand SAML signature, SSO metadata, SCIM and organization authorization fixtures.
- Decide deferred endpoints separately and update parity accordingly.

**Acceptance:** privileged/plugin operations are gated and audited; adverse fixtures pass.

### PR 8 — Release engineering and integration example
**Branch:** `docs/release-and-tiktools-example`

- Add a standalone example showing how TikTools Cloud can consume Better Auth for OAuth, sessions and publisher identities.
- Keep TikTools registry publication/signature/sync logic outside this auth repository.
- Verify publish/package versions, docs, feature flags, MSRV and release notes.
- Schedule independent security review and remediate results before claiming production readiness.

**Acceptance:** repeatable release build; examples run; public compatibility statements match evidence.

## Verification matrix

| Area | Minimum verification |
|---|---|
| Rust style/build | `cargo fmt --all -- --check`, `cargo check --workspace --all-features` |
| Rust testing | `cargo test --workspace --all-features`, strict Clippy, MSRV |
| Real persistence | Live PostgreSQL/MySQL tests and migration-upgrade fixtures; explicit skip report |
| Frontend clients | TypeScript type/unit/E2E; Kotlin MockEngine and live HTTP fixtures |
| Security | CSRF, IDOR/tenant isolation, origin spoofing, OAuth state, replay, expired codes, key rotation |
| Browser | Playwright cookie/session and WebAuthn flows |
| Ecosystem | Dep/security/license audit, SBOM/provenance where configured |

## PR definition of done

- [ ] Diff is focused and backward compatibility evaluated.
- [ ] Threat model and sensitive-data handling are reviewed.
- [ ] Tests demonstrate the new feature and failure cases.
- [ ] Relevant databases and feature flags exercised.
- [ ] Skips and blocked CI jobs are called out, not counted as passing.
- [ ] Docs, status, parity and deferred lists updated where applicable.
- [ ] No secrets or test-only insecure defaults leak into production configuration.
- [ ] Release/rollback notes included for schema or API changes.

## Instructions for coding agents

Work through the PR sequence in order unless an active security vulnerability requires reprioritization. Before each change, inspect actual files and tests and cite code paths in the PR. Do not assume this plan is executable specification for missing APIs: derive implementation details from existing traits and current source. Never claim test results without running the tests. Do not implement TikTools Cloud as a feature of the authentication library.
