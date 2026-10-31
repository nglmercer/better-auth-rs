# Release gates

A release is blocked by any gate marked **blocking** that is not passing. The
status column reflects the repository as of this file's last update. It is not a
claim about any published release.

| Gate | Command or evidence | Blocking | Status |
|---|---|---|---|
| Formatting | `cargo fmt --all -- --check` | yes | passing |
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | yes | passing |
| Unit and integration tests | `cargo test --workspace --all-features` | yes | passing |
| Live PostgreSQL | `BETTER_AUTH_TEST_POSTGRES_URL=… cargo test -p better-auth --all-features` | yes | passing locally; CI service container configured, not yet run on GitHub |
| Live MySQL | `BETTER_AUTH_TEST_MYSQL_URL=… cargo test -p better-auth --all-features` | yes | passing locally (8.4); CI service container configured, not yet run on GitHub |
| Connection-kill recovery | `tests/chaos_restart.rs` against a live database | yes | passing locally against one database; two in-process nodes, not separate machines |
| Compatibility fixtures | `crates/better-auth/tests/compat.rs` | yes | passing |
| MSRV build | `cargo +1.89 check --workspace --all-features` | yes | passing locally; CI `msrv` job configured |
| Supply chain | `cargo deny check` | yes | passing with ten accepted advisories (see `docs/supply-chain.md`); acceptance pending |
| SBOM | `tools/supply/sbom.py` | yes | generator present; attach to release artifacts |
| Endpoint inventory | `tools/parity/endpoint_diff.py` against the pinned upstream | yes | regenerated; mounted count is recorded in `docs/parity/ENDPOINTS.md` |
| TypeScript client | `npm run typecheck && npm run test:types && npm test` | yes | passing |
| TypeScript end-to-end | `npm run test:e2e` (Rust web example) | yes | passing |
| Kotlin client | `JAVA_HOME=/usr/lib/jvm/java-21-openjdk ./gradlew jvmTest` | yes | passing |
| Browser end-to-end | Browser automation against the web example | yes | **not run**: the browser extension was not connected |
| Load measurements | `docs/operations/LOAD_TEST.md` | no (recorded) | in-process only; no networked or multi-node run |
| Independent security review | external review | yes | **not started** |
| Multi-node and rolling-deploy tests | separate machines sharing one database | yes | **not started** |

## Stopping rules

A release does not go out while any blocking gate is failing, and a gate marked
**not run** or **not started** counts as failing. Accepted dependency advisories
remain blocking for the `core-stable` milestone until they are removed from
`deny.toml`.
