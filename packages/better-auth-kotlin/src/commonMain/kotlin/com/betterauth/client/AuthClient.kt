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
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

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

/** Session metadata. The session token is never exposed. */
@Serializable
public data class SessionSummary(
    val id: String,
    @SerialName("expires_at") val expiresAt: Long,
    val current: Boolean,
)

@Serializable
public data class ListSessionsResponse(val sessions: List<SessionSummary>)

@Serializable
public data class RevokedCount(val revoked: Int)

@Serializable
public data class LinkedAccount(
    @SerialName("provider_id") val providerId: String,
    @SerialName("account_id") val accountId: String,
)

@Serializable
public data class ListAccountsResponse(val accounts: List<LinkedAccount>)

@Serializable
public data class ChangePasswordResponse(
    val changed: Boolean,
    @SerialName("revoked_sessions") val revokedSessions: Int,
)

@Serializable
public data class UpdateUserResponse(val user: AuthUser)

@Serializable
public data class TwoFactorEnrollment(
    val secret: String,
    @SerialName("totp_uri") val totpUri: String,
    @SerialName("backup_codes") val backupCodes: List<String>,
)

@Serializable
public data class EnabledResponse(val enabled: Boolean)

@Serializable
public data class SentResponse(val sent: Boolean)

@Serializable
public data class ApiKeyView(
    val id: String,
    val name: String,
    val prefix: String,
    val scopes: List<String>,
    @SerialName("expires_at") val expiresAt: Long? = null,
    val revoked: Boolean,
    @SerialName("created_at") val createdAt: Long,
)

@Serializable
public data class ApiKeyCreated(val key: String, @SerialName("api_key") val apiKey: ApiKeyView)

@Serializable
public data class ApiKeyList(@SerialName("api_keys") val apiKeys: List<ApiKeyView>)

@Serializable
public data class DeviceCodeGrant(
    @SerialName("device_code") val deviceCode: String,
    @SerialName("user_code") val userCode: String,
    @SerialName("verification_uri") val verificationUri: String,
    @SerialName("expires_in") val expiresIn: Long,
    val interval: Long,
)

@Serializable
public data class DeviceTokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresIn: Long,
)

/** Outcome of a password sign-in: a session, or a second-factor challenge. */
public sealed interface SignInResult {
    public data class Session(val response: AuthSessionResponse) : SignInResult
    public data class TwoFactorRequired(val challengeToken: String) : SignInResult
}

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
     * Password sign-in that also reports a second-factor challenge. Prefer this
     * over [signInEmail], which cannot decode the challenge response.
     */
    public suspend fun signInEmailOrChallenge(
        input: SignInEmailInput,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): SignInResult {
        val body: JsonObject = request(
            path = "/sign-in/email",
            method = HttpMethod.Post,
            body = json.encodeToJsonElement(input),
            options = options,
        )
        return if (body["two_factor_required"]?.jsonPrimitive?.booleanOrNull == true) {
            SignInResult.TwoFactorRequired(body.getValue("challenge_token").jsonPrimitive.content)
        } else {
            SignInResult.Session(json.decodeFromJsonElement(AuthSessionResponse.serializer(), body))
        }
    }

    public suspend fun twoFactorVerify(
        challengeToken: String,
        code: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): AuthSessionResponse = request(
        path = "/two-factor/verify",
        method = HttpMethod.Post,
        body = buildJsonObject {
            put("challenge_token", challengeToken)
            put("code", code)
        },
        options = options,
    )

    public suspend fun twoFactorEnable(
        password: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): TwoFactorEnrollment = request(
        path = "/two-factor/enable",
        method = HttpMethod.Post,
        body = buildJsonObject { put("password", password) },
        options = options,
    )

    public suspend fun twoFactorConfirm(
        code: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): EnabledResponse = request(
        path = "/two-factor/confirm",
        method = HttpMethod.Post,
        body = buildJsonObject { put("code", code) },
        options = options,
    )

    public suspend fun twoFactorDisable(
        password: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): EnabledResponse = request(
        path = "/two-factor/disable",
        method = HttpMethod.Post,
        body = buildJsonObject { put("password", password) },
        options = options,
    )

    public suspend fun listSessions(
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ListSessionsResponse = request(
        path = "/list-sessions",
        method = HttpMethod.Get,
        options = options,
    )

    public suspend fun revokeSession(
        id: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): RevokedCount = request(
        path = "/revoke-session",
        method = HttpMethod.Post,
        body = buildJsonObject { put("id", id) },
        options = options,
    )

    public suspend fun revokeOtherSessions(
        options: AuthRequestOptions = AuthRequestOptions(),
    ): RevokedCount = request(
        path = "/revoke-other-sessions",
        method = HttpMethod.Post,
        options = options,
    )

    public suspend fun listAccounts(
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ListAccountsResponse = request(
        path = "/list-accounts",
        method = HttpMethod.Get,
        options = options,
    )

    public suspend fun changePassword(
        currentPassword: String,
        newPassword: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ChangePasswordResponse = request(
        path = "/change-password",
        method = HttpMethod.Post,
        body = buildJsonObject {
            put("current_password", currentPassword)
            put("new_password", newPassword)
        },
        options = options,
    )

    public suspend fun updateUser(
        name: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): UpdateUserResponse = request(
        path = "/update-user",
        method = HttpMethod.Post,
        body = buildJsonObject { put("name", name) },
        options = options,
    )

    public suspend fun deleteUser(
        password: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ) {
        execute("/delete-user", HttpMethod.Post, buildJsonObject { put("password", password) }, options)
    }

    public suspend fun magicLinkSend(
        email: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): SentResponse = request(
        path = "/sign-in/magic-link",
        method = HttpMethod.Post,
        body = buildJsonObject { put("email", email) },
        options = options,
    )

    public suspend fun emailOtpSend(
        email: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): SentResponse = request(
        path = "/email-otp/send",
        method = HttpMethod.Post,
        body = buildJsonObject { put("email", email) },
        options = options,
    )

    public suspend fun emailOtpVerify(
        email: String,
        code: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): AuthSessionResponse = request(
        path = "/email-otp/verify",
        method = HttpMethod.Post,
        body = buildJsonObject {
            put("email", email)
            put("code", code)
        },
        options = options,
    )

    public suspend fun apiKeyCreate(
        name: String,
        scopes: List<String>,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ApiKeyCreated = request(
        path = "/api-key/create",
        method = HttpMethod.Post,
        body = buildJsonObject {
            put("name", name)
            put("scopes", kotlinx.serialization.json.JsonArray(scopes.map { kotlinx.serialization.json.JsonPrimitive(it) }))
        },
        options = options,
    )

    public suspend fun apiKeyList(
        options: AuthRequestOptions = AuthRequestOptions(),
    ): ApiKeyList = request(
        path = "/api-key/list",
        method = HttpMethod.Get,
        options = options,
    )

    public suspend fun apiKeyRevoke(
        id: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): RevokedCount = request(
        path = "/api-key/revoke",
        method = HttpMethod.Post,
        body = buildJsonObject { put("id", id) },
        options = options,
    )

    public suspend fun deviceCode(
        clientId: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): DeviceCodeGrant = request(
        path = "/device/code",
        method = HttpMethod.Post,
        body = buildJsonObject { put("client_id", clientId) },
        options = options,
    )

    /**
     * Polls for the device grant. While the user has not decided, the server
     * answers 400 with an RFC 8628 error code such as `authorization_pending`.
     * That arrives as an [AuthClientException]; poll again after the interval.
     */
    public suspend fun deviceToken(
        deviceCode: String,
        clientId: String,
        options: AuthRequestOptions = AuthRequestOptions(),
    ): DeviceTokenResponse = request(
        path = "/device/token",
        method = HttpMethod.Post,
        body = buildJsonObject {
            put("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
            put("device_code", deviceCode)
            put("client_id", clientId)
        },
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
