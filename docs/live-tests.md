# Live database tests

Some tests run against real database servers. Each one is skipped unless its
environment variable is set, so `cargo test` works without any server.

| Variable | Test | Covers |
|---|---|---|
| `BETTER_AUTH_TEST_POSTGRES_URL` | `database::tests::sqlx_postgres_conformance_when_configured`, `tests/live_database_flow.rs` | Shared adapter contract, atomic counters, sign-up race, two-factor single use under contention |
| `BETTER_AUTH_TEST_MYSQL_URL` | `database::tests::sqlx_mysql_conformance_when_configured`, `tests/live_database_flow.rs` | The same, on MySQL |
| `BETTER_AUTH_TEST_LIBSQL_URL` and `BETTER_AUTH_TEST_LIBSQL_TOKEN` | libSQL conformance | Remote libSQL or Turso (not run in CI without secrets) |

The tests use fresh random emails, so one database can be reused between runs.

## Run locally with Docker

```sh
docker run -d --name ba-postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=better_auth_test -p 127.0.0.1:55432:5432 postgres:16
docker run -d --name ba-mysql -e MYSQL_ROOT_PASSWORD=mysql \
  -e MYSQL_DATABASE=better_auth_test -p 127.0.0.1:33306:3306 mysql:8.4

BETTER_AUTH_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:55432/better_auth_test \
BETTER_AUTH_TEST_MYSQL_URL=mysql://root:mysql@127.0.0.1:33306/better_auth_test \
  cargo test -p better-auth --all-features
```

CI runs the same two servers as service containers in the `verify` job of
`.github/workflows/ci.yml`.

## Notes

- A MySQL database that was migrated by an older build keeps its old column
  types, because migrations use `CREATE TABLE IF NOT EXISTS`. Recreate the test
  database after changing the migration types.
- One MySQL run failed once during development and then passed eight times in a
  row. The cause was not captured. Treat a single failure as a signal to rerun
  with the output saved.
