# Release and compatibility policy

## Versions

Semantic versioning applies from `1.0.0`. Before `1.0.0`, minor versions may
contain breaking changes, and each one must say so in CHANGELOG.md under
**Changed** and, where data is involved, **Compatibility**.

## Compatibility guarantees

These must not change without a major version and a migration note:

- **Password hashes.** Stored hashes keep verifying. Rehash-on-login is allowed
  when the stored parameters are weaker.
- **Signed and encrypted envelopes.** Envelopes signed or encrypted under a key
  version keep verifying while that key version is configured.
- **Core schema.** Tables, columns and indexes in `core_schema()` keep their
  meaning. Column type changes require a migration step.

The golden fixtures in `crates/better-auth/tests/compat/` enforce the first and
third items. Regenerating a fixture is a deliberate, changelogged act.

## Deprecation

A deprecated route, option or function keeps working for at least one minor
version. It is listed under **Deprecated** in CHANGELOG.md with its replacement.

## Supported Rust versions

The minimum supported Rust version is the `rust-version` in the workspace
`Cargo.toml` (currently 1.89). CI checks it in the `msrv` job. Raising it is a
minor-version change at the least, and is listed under **Changed**.

## Releasing

1. Confirm CI is green, including live PostgreSQL and MySQL runs.
2. Run `cargo deny check` and review any new accepted advisory.
3. Generate the SBOM with `tools/supply/sbom.py` and attach it to the release.
4. Regenerate `docs/parity/ENDPOINTS.md` and check the mounted count.
5. Move the Unreleased section of CHANGELOG.md under the new version.
6. Tag the commit `vX.Y.Z`.

Publishing to crates.io is not yet configured. Signing of release artifacts is not
yet configured.
