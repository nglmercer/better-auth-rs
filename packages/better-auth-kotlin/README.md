# Better Auth Kotlin SDK

Kotlin Multiplatform client for the Better Auth Rust HTTP API. It mirrors the
TypeScript client in `packages/better-auth-client` and supports:

- typed email sign-up and sign-in;
- session lookup and sign-out;
- email verification and password reset;
- generic JSON requests for plugin/application endpoints;
- structured HTTP errors;
- safe retries for idempotent requests and idempotency-key protected writes;
- Ktor cookie-based sessions.

## Usage

The SDK accepts a caller-owned Ktor `HttpClient`, allowing Android, JVM, and
iOS applications to choose their own Ktor engine:

```kotlin
val httpClient = HttpClient(CIO) {
    installBetterAuth()
}

val auth = AuthClient("https://example.com/api/auth", httpClient)

val session = auth.signInEmail(
    SignInEmailInput(
        email = "user@example.com",
        password = "a-long-password",
    ),
)

val currentSession = auth.getSession()
auth.signOut()
```

`installBetterAuth()` installs Ktor's in-memory cookie storage. For mobile
applications that must survive process restarts, provide a persistent,
encrypted `CookiesStorage` backed by Android Keystore or iOS Keychain.

The client does not close the injected `HttpClient`; the application owns its
lifecycle and should close it when the application shuts down.

## Tests

Run the unit tests with:

```sh
./gradlew test
```

Tests use Ktor's `MockEngine` for request, response, error, validation, and
retry behavior. Real integration tests should run against the Rust test host
at `crates/better-auth/examples/client-test-server.rs`, just like the
TypeScript client E2E suite.

The Kotlin package currently targets JVM plus shared Kotlin Multiplatform
code. Android and iOS applications select their engine in their own source
sets.
