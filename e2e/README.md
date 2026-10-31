# Browser tests

Playwright tests for the Rust web example, in `crates/better-auth/examples/web-example`.
They drive the page with a real browser and check the session cookie, the forms, the
password reset path, and a cross-site request that must be refused.

## Run

```sh
cd e2e
npm ci
npx playwright install chromium
npx playwright test
```

The Playwright config starts the example with `cargo run`, so a Rust toolchain is needed.
It runs in test mode (`BETTER_AUTH_EXAMPLE_TEST_MODE=1`) on a fixed port, which:

- sets the static base URL that reset links are built from,
- sends email to an in-memory mailbox, and
- serves that mailbox at `/__test/emails` so a test can read a reset token.

Test mode is off by default, so the demo behaves as before when run on its own.
