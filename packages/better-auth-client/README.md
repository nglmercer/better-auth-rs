# `@better-auth/rust-client`

Small TypeScript SDK for the Better Auth Rust HTTP API.

```ts
import { AuthClient } from "@better-auth/rust-client";

const auth = new AuthClient({
  baseURL: "https://example.com/api/auth",
});

await auth.signUp.email({
  email: "user@example.com",
  name: "User",
  password: "a-long-password",
});

const session = await auth.getSession();
await auth.signOut();
```

Typed helpers cover every endpoint exposed by the Rust `AuthRouter`:

```ts
await auth.verifyEmail({ token });
await auth.requestPasswordReset({ email: "user@example.com" });
await auth.resetPassword({ token, new_password: "a-new-password" });
```

Use `auth.request<T>()` for plugin or application-specific endpoints. It
always sends JSON, applies configured default headers, and accepts per-request
headers, credentials, an `AbortSignal`, and an optional idempotency key.

The SDK uses `fetch` and `credentials: "include"`, so browsers keep the
server-issued HttpOnly session cookie. Cross-origin deployments still need
their normal CORS and cookie configuration. Retries are limited to safe HTTP
methods unless an `idempotencyKey` is supplied; retry delays honor both
seconds and HTTP-date `Retry-After` values and stop when the request is
aborted.

## Testing

Install dependencies and run the client tests with:

```sh
npm install
npm run test:types
npm test
npm run test:e2e
```

Vitest tests should mock `fetch` for request and retry behavior. For HTTP
integration tests, `test:e2e` builds the minimal Axum web example in
`crates/better-auth/examples/web-example.rs`. Its browser page covers
registration, login, and password recovery; the E2E suite focuses on the
registration/login cookie flow. The server binds to `127.0.0.1:0`, emits a
readiness line, and is spawned and terminated by the suite. Keep unit tests
mocked for speed, and use E2E for the real HTTP contract.
