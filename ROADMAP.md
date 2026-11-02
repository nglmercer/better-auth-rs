# Better Auth for Rust — Delivery Roadmap

**Planning status:** Proposed sequencing as of 2026-11-01. Milestones are **not** claims of completion.  
**Current evidence:** [roadmap-status](docs/roadmap-status.md) · [parity matrix](docs/parity/MATRIX.md) · [deferred endpoints](docs/parity/DEFERRED.md) · [upstream pin](docs/parity/UPSTREAM.md)

The current status tracker reports a substantial working foundation and 96 of 128 pinned core endpoints mounted, with 32 deliberately deferred. Its listed gaps, not a rewrite, determine priorities. Existing CI has been blocked by a GitHub billing issue; local passes alone are not proof CI is green.

## Priority legend

- **P0 — security/release blocker:** required before production use.
- **P1 — compatibility and completeness:** required before stable public claims.
- **P2 — expansion:** optional or demand-driven.

## Milestone 0 — Baseline and reproducible evidence (P0)

- [ ] Reconcile README, status tracker, parity matrix, deferred endpoint inventory and actual source tree.
- [ ] Run local formatter, all-features compile/test, Clippy, browser tests and conformance suites; record exact command, environment and skips.
- [ ] Restore GitHub Actions execution or provide a repeatable externally run CI equivalent; never treat blocked workflows as passing.
- [ ] Generate a route manifest and compare mounted routes, SDK methods and deferred entries.
- [ ] Pin and verify upstream schema including `@better-auth/core`; keep the current version until an explicit parity update.
- [ ] Capture baseline coverage, test times, and login/session latency.

**Exit:** Reproducible baseline report, CI evidence, no undocumented unmounted route.

## Milestone 1 — Security hardening (P0)

- [ ] Add service-boundary authorization tests for privileged/admin/tenant operations.
- [ ] Complete proxy, Origin, Fetch Metadata, CORS and cookie boundary tests.
- [ ] Implement route-specific rate-limit policy and test multi-worker atomic behavior.
- [ ] Schedule OIDC JWKS refresh and test expiry, key rollover, outage and invalid key scenarios.
- [ ] Complete OAuth provider callback/replay/linking negative tests, including unverified email.
- [ ] Validate passkey ceremonies in real browsers; enforce 2FA and step-up gates end-to-end.
- [ ] Add bounded fuzz/property tests, request/error metrics without secret leakage and security runbooks.
- [ ] Obtain independent security review; resolve critical/high findings.

**Exit:** Security threat-model checklist, reproducible adversarial tests, independent review or release remains pre-production.

## Milestone 2 — Storage and operations reliability (P0)

- [ ] Run live PostgreSQL/MySQL conformance continuously, plus SQLite/libSQL matrix.
- [ ] Test remote libSQL and shared-store failure/partition behavior where supported.
- [ ] Add migration checksum/drift/dry-run/upgrade fixtures.
- [ ] Test session invalidation and rotation after account/password/2FA changes.
- [ ] Run encrypted provider token key-rotation and backup/restore drills.
- [ ] Document database migration/incident/secret rotation deployment playbooks.

**Exit:** Backed-up, recoverable deployments with passing real-database CI evidence.

## Milestone 3 — Protocol and SDK correctness (P1)

- [ ] Emit/check OpenAPI with typed errors and status-code mapping.
- [ ] Add route-to-SDK method inventory and contract tests across Rust, TypeScript and Kotlin.
- [ ] Run wire-format differential tests against pinned upstream for supported routes; document deviations.
- [ ] Finish account linking and token refresh/revocation according to reviewed provider policy.
- [ ] Add browser-based cookie flows and desktop OAuth integration example using PKCE.
- [ ] Keep missing endpoints deferred with justification; do not chase numeric parity at expense of security.

**Exit:** Clearly documented, versioned supported API with typed client coverage and compatibility evidence.

## Milestone 4 — Plugin and advanced authentication completeness (P1)

- [ ] Validate plugin route collisions, path params, access policies, hooks and rate limits at registration time.
- [ ] Finish WebAuthn browser/client support, attestation policy and recovery UX examples.
- [ ] Finish organization edge cases, step-up, persistent audit trail and SSO/SCIM fixtures.
- [ ] Provide signed SAML assertions and negative/expired/metadata-rotation fixtures.
- [ ] Decide each deferred upstream feature: implement, explicitly defer, or mark unsupported.

**Exit:** Advanced feature surface is documented by feature-level test evidence, not blanket parity claims.

## Milestone 5 — Stable library release (P1)

- [ ] Audit MSRV/feature combinations and public APIs for accidental breakage.
- [ ] Publish migration guide, examples, versioned API reference and feature matrix.
- [ ] Test crates.io/npm/Kotlin release artifacts and reproducible build provenance.
- [ ] Establish vulnerability disclosure, supported release branches, changelog policy and response ownership.
- [ ] Release only when P0 acceptance criteria are met; otherwise clearly mark experimental.

**Exit:** Versioned, supportable library with documented compatibility boundaries.

## Milestone 6 — Optional ecosystem integrations (P2)

- [ ] Build a standalone TikTools Cloud example using auth services without introducing TikTools dependencies into `better-auth-rs`.
- [ ] Evaluate Actix adapter and additional providers only with consumer-backed demand.
- [ ] Add tracing/telemetry adapters and optional Redis-compatible secondary storage.
- [ ] Review upstream new releases on a separate cadence; pin bumps require updated contracts/tests.

**Exit:** New integrations preserve the core's independent library architecture.

## Release decision rules

- Never label a feature “complete” without tests for its full HTTP + relevant SDK workflow.
- Never label “production ready” until M1 and M2 plus independent review are completed.
- Do not erase intentional security deviations merely to raise parity percentage.
- Prefer small, independently reviewable PRs; each PR updates relevant status and test evidence.
- Keep this file strategic; exact implementation tasks live in [PLAN.md](PLAN.md).
