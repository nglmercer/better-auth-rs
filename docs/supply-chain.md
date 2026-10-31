# Supply-chain policy

Checked by `cargo deny check` in CI. The policy is in [`deny.toml`](../deny.toml).

- **Advisories:** any RustSec advisory fails the check, except the accepted
  exceptions listed below.
- **Licenses:** only the permissive licenses named in `deny.toml` are allowed.
- **Sources:** only crates.io is allowed.
- **Duplicates:** reported as warnings. The dependency tree has legitimate
  duplicates, for example `libsql` and `reqwest`.

## Accepted advisories

Each exception names the parent crate that pins the vulnerable version. None
can be removed by a semver-compatible update. Each one blocks the `core-stable`
milestone in the roadmap until it is removed.

**Acceptance:** the project owner accepted all ten exceptions below on 2026-10-31.
Acceptance does not remove them from the `core-stable` gate.

| Advisory | Crate | Pinned by | Removal condition |
|---|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9 (Marvin timing) | sqlx-mysql | No fixed release. Remove when sqlx drops rsa or rsa ships a fix. |
| RUSTSEC-2026-0387 | crypto-bigint | rsa, saml-rs (bergshamra) | Update saml-rs and sqlx. |
| RUSTSEC-2026-0049, -0098, -0099, -0104, -0382 | rustls-webpki 0.102 | libsql (rustls 0.22 stack) | libsql release on rustls 0.23. |
| RUSTSEC-2026-0346, -0349 | rustls 0.22 | libsql | libsql release on rustls 0.23. |
| RUSTSEC-2026-0258 | h2 0.3 | libsql (hyper 0.14, tonic 0.11) | libsql release on hyper 1. |

The libsql entries affect the optional `libsql` feature, which is used for
remote Turso connections. Deployments that use that feature should weigh the
exposure before they rely on it.

## Software bill of materials

```sh
cargo metadata --format-version 1 --locked | python3 tools/supply/sbom.py > sbom.cdx.json
```

The output is CycloneDX 1.5 JSON, built from the locked dependency graph. It
includes package names, versions, licenses where the package declares them,
and source URLs. It does not include file hashes, because `cargo metadata` does
not provide them.
