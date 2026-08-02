package com.betterauth.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.request
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.content.TextContent
import io.ktor.client.request.setBody
import kotlinx.coroutines.delay
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive

@Serializable
public data class SignUpEmailInput(
    val email: String,
    val name: String,
    val password: String,
)

@Serializable
public data class SignInEmailInput(
    val email: String,
    val password: String,
)

@Serializable
public data class AuthUser(
    val id: String,
    val email: String,
    val name: String,
    @SerialName("email_verified") val emailVerified: Boolean,
    val image: String? = null,
)

@Serializable
public data class AuthSession(
    val id: String,
    @SerialName("user_id") val userId: String,
    @SerialName("expires_at") val expiresAt: Long,
)

@Serializable
public data class AuthSessionResponse(
    val user: AuthUser,
    val session: AuthSession,
)

@Serializable
public data class VerifyEmailInput(val token: String)

@Serializable
public data class VerifyEmailResponse(val verified: Boolean)

@Serializable
public data class RequestPasswordResetInput(val email: String)

@Serializable
public data class RequestPasswordResetResponse(val sent: Boolean)

@Serializable
public data class ResetPasswordInput(
    val token: String,
    @SerialName("new_password") val newPassword: String,
)

@Serializable
public data class ResetPasswordResponse(val reset: Boolean)

public data class RetryOptions(
    val maxRetries: Int = 2,
    val baseDelayMillis: Long = 100,
    val maxDelayMillis: Long = 2_000,
) {
    init {
        require(maxRetries >= 0) { "maxRetries must be non-negative" }
        require(baseDelayMillis > 0) { "baseDelayMillis must be positive" }
        require(maxDelayMillis >= baseDelayMillis) {
            "maxDelayMillis must be greater than or equal to baseDelayMillis"
        }
    }
}

public data class AuthRequestOptions(
    val headers: Headers = Headers.Empty,
    val idempotencyKey: String? = null,
)

public class AuthClientException(
    public val status: Int,
    message: String,
    public val code: String? = null,
    public val details: JsonElement? = null,
) : RuntimeException(message)

/**
 * Installs the cookie plugin needed for the server-issued session cookie.
 *
 * The default Ktor cookie storage is in-memory. Native applications that need
 * sessions across process restarts should provide a persistent, encrypted
 * CookiesStorage backed by Android Keystore or iOS Keychain.
 */
public fun io.ktor.client.HttpClientConfig<*>.installBetterAuth() {
    install(HttpCookies)
}

/**
 * Kotlin Multiplatform client for the Better Auth Rust HTTP API.
 *
 * The HttpClient is injected so each platform can select its own Ktor engine.
 * Configure it with installBetterAuth() to keep the session cookie between
 * requests.
 */
public class AuthClient(
    baseUrl: String,
    private val httpClient: HttpClient,
    private val defaultHeaders: Headers = Headers.Empty,
    private val retry: RetryOptions = RetryOptions(),
    @PublishedApi
    internal val json: Json = Json { ignoreUnknownKeys = true },
) {
    private val baseUrl: String

    init {
        val parsed = Url(baseUrl.trimEnd('/'))
        require(parsed.protocol == URLProtocol.HTTP || parsed.protocol == URLProtocol.HTTPS) {
            "baseUrl must use http or https"
        }
        require(parsed.parameters.isEmpty() && parsed.fragment.isEmpty()) {
            "baseUrl must not include a query or fragment"
        }
        this.baseUrl = baseUrl.trimEnd('/')
    }

    public suspend fun signUpEmail(
        input: SignUpEmailInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): AuthSessionResponse = request(
        path = "/sign-up/email",
        method = HttpMethod.Post,
        body = json.encodeToJsonElement(input),
        options = options,
    )

    public suspend fun signInEmail(
        input: SignInEmailInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): AuthSessionResponse = request(
        path = "/sign-in/email",
        method = HttpMethod.Post,
        body = json.encodeToJsonElement(input),
        options = options,
    )

    public suspend fun getSession(
        options: AuthRequestOptions = AuthRequestOptions(),
    ): AuthSessionResponse? = request(
        path = "/get-session",
        method = HttpMethod.Get,
        options = options,
    )

    public suspend fun signOut(options: AuthRequestOptions = AuthRequestOptions()) {
        execute("/sign-out", HttpMethod.Post, null, options)
    }

    public suspend fun verifyEmail(
        input: VerifyEmailInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): VerifyEmailResponse = request(
        path = "/verify-email",
        method = HttpMethod.Post,
        body = json.encodeToJsonElement(input),
        options = options,
    )

    public suspend fun requestPasswordReset(
        input: RequestPasswordResetInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): RequestPasswordResetResponse = request(
        path = "/request-password-reset",
        method = HttpMethod.Post,
        body = json.encodeToJsonElement(input),
        options = options,
    )

    public suspend fun resetPassword(
        input: ResetPasswordInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ResetPasswordResponse = request(
        path = "/reset-password",
        method = HttpMethod.Post,
        body = json.encodeToJsonElement(input),
        options = options,
    )

    /**
     * Calls a plugin or application-specific JSON endpoint.
     *
     * The body is a JsonElement so custom endpoints do not require this SDK
     * to know their request model. Responses are decoded with kotlinx.serialization.
     */
    public suspend inline fun <reified T> request(
        path: String,
        method: HttpMethod = HttpMethod.Get,
        body: JsonElement? = null,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): T {
        val response = execute(path, method, body, options)
        return json.decodeFromString(response.body)
    }

    @PublishedApi
    internal suspend fun execute(
        path: String,
        method: HttpMethod,
        body: JsonElement?,
        options: AuthRequestOptions,
    ): RawResponse {
        require(path.startsWith('/') && !path.startsWith("//")) {
            "client paths must start with '/'"
        }
        val canRetry = method in setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options) ||
            options.idempotencyKey != null
        var attempt = 0

        while (true) {
            val response = httpClient.request("$baseUrl$path") {
                applyRequest(method, body, options)
            }
            val raw = RawResponse(response.status, response.headers, response.bodyAsText())
            if (raw.status.value in 200..299) return raw

            if (!canRetry || !isRetryable(raw.status) || attempt >= retry.maxRetries) {
                throw raw.toException()
            }

            val retryAfter = raw.headers[HttpHeaders.RetryAfter]?.toLongOrNull()
            val exponential = (retry.baseDelayMillis * (1L shl attempt.coerceAtMost(20)))
                .coerceAtMost(retry.maxDelayMillis)
            delay((retryAfter?.times(1_000) ?: exponential).coerceAtMost(retry.maxDelayMillis))
            attempt += 1
        }
    }

    private fun HttpRequestBuilder.applyRequest(
        method: HttpMethod,
        body: JsonElement?,
        options: AuthRequestOptions,
    ) {
        this.method = method
        val headers = HeadersBuilder().apply {
            appendAll(defaultHeaders)
            appendAll(options.headers)
            if (!contains(HttpHeaders.Accept)) {
                append(HttpHeaders.Accept, ContentType.Application.Json.toString())
            }
            options.idempotencyKey?.let { append("Idempotency-Key", it) }
        }
        this.headers.appendAll(headers.build())
        if (body != null) {
            val encodedBody = json.encodeToString(JsonElement.serializer(), body)
            setBody(TextContent(encodedBody, ContentType.Application.Json))
            this.headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        }
    }

    private fun isRetryable(status: HttpStatusCode): Boolean = status.value in setOf(
        408, 425, 429, 500, 502, 503, 504,
    )

    private fun RawResponse.toException(): AuthClientException {
        val error = runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull()
        val message = error?.get("error")?.jsonPrimitive?.contentOrNull
            ?: "request failed with status ${status.value}"
        return AuthClientException(
            status = status.value,
            message = message,
            code = error?.get("code")?.jsonPrimitive?.contentOrNull,
            details = error?.get("details"),
        )
    }

    @PublishedApi
    internal data class RawResponse(
        val status: HttpStatusCode,
        val headers: Headers,
        val body: String,
    )
}
