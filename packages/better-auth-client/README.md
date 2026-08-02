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

The SDK uses `fetch` and `credentials: "include"`, so browsers keep the
server-issued HttpOnly session cookie. Cross-origin deployments still need
their normal CORS and cookie configuration. Retries are limited to safe HTTP
methods unless an `idempotencyKey` is supplied.
