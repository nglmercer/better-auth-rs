# In-process load measurements

Measured with `crates/better-auth/examples/load_test.rs` in release mode. The
example drives `AuthRouter::handle` from concurrent tasks, using the in-memory
adapter and storage.

**What these numbers cover:** router logic, password hashing and session lookup.

**What they do not cover:** HTTP parsing, a network hop, a database server,
TLS, or a deployment with several nodes. Those need the multi-node and chaos
tests in roadmap item P5-03, which are not implemented.

## Environment

- CPU: AMD BC-250, 2 logical cores (`nproc` = 2)
- Build: `cargo build --release`, the default scrypt parameters
  (`ln=15, r=8, p=1`)
- Command: `target/release/examples/load_test <concurrency> <requests>`

## Results

| Concurrency | Scenario | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|---|
| 1 | `get-session` | 10.9 µs | 27.5 µs | 32.1 µs | 70,259/s |
| 1 | sign-in, wrong password | 71.2 ms | 73.4 ms | 76.0 ms | 14.0/s |
| 8 | `get-session` | 20.6 µs | 39.2 µs | 78.8 µs | 305,722/s |
| 8 | sign-in, wrong password | 91.7 ms | 111.2 ms | 120.3 ms | 81.6/s |
| 32 | `get-session` | 23.7 µs | 117.5 µs | 243.9 µs | 263,333/s |
| 32 | sign-in, wrong password | 309.4 ms | 421.3 ms | 460.2 ms | 102.5/s |

Every response had the expected status. The run used no rate limiter.

## Reading the numbers

- Sign-in is bound by scrypt. On this machine it saturates near 100 requests
  per second, which is the hashing budget of two cores. Throughput does not rise
  with concurrency beyond the core count.
- Session lookup is cheap. Its cost is the storage read and cookie parsing.
- A password check against an unknown address now spends the same hashing time
  as a check against a real account. Before this change the unknown-address path
  returned in microseconds, and that difference revealed which accounts exist.
  The rows above are for an existing account, whose cost did not change.

## Not yet measured

- A networked server with TLS.
- PostgreSQL or MySQL as the store. The live-database tests check correctness,
  not latency.
- Soak runs longer than a few seconds.
- Recovery after a database restart in the middle of a run.
