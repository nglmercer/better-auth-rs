package com.betterauth.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AuthClientTest {
    @Test
    fun signUpSendsTypedJsonAndDecodesSession() = runTest {
        var request: HttpRequestData? = null
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler {
                    request = it
                    respond(
                        content = SESSION_JSON,
                        status = HttpStatusCode.OK,
                        headers = JSON_HEADERS,
                    )
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        val result = client.signUpEmail(
            SignUpEmailInput("user@example.com", "User", "password"),
        )

        assertEquals("user-id", result.user.id)
        assertEquals("/api/auth/sign-up/email", request?.url?.encodedPath)
        assertEquals(HttpMethod.Post, request?.method)
        assertEquals(
            ContentType.Application.Json,
            (request?.body as TextContent).contentType,
        )
    }

    @Test
    fun missingSessionDecodesToNull() = runTest {
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler { respond("null", HttpStatusCode.OK, JSON_HEADERS) }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        assertEquals(null, client.getSession())
    }

    @Test
    fun structuredErrorsAreExposed() = runTest {
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler {
                    respond(
                        content = """{"error":"invalid credentials"}""",
                        status = HttpStatusCode.Unauthorized,
                        headers = JSON_HEADERS,
                    )
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        val error = assertFailsWith<AuthClientException> {
            client.signInEmail(SignInEmailInput("user@example.com", "wrong"))
        }

        assertEquals(401, error.status)
        assertEquals("invalid credentials", error.message)
    }

    @Test
    fun retriesSafeRequestsButNotUnkeyedPosts() = runTest {
        var attempts = 0
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler {
                    attempts += 1
                    if (attempts == 1) {
                        respond("busy", HttpStatusCode.ServiceUnavailable)
                    } else {
                        respond("null", HttpStatusCode.OK, JSON_HEADERS)
                    }
                }
            }
        }
        val client = AuthClient(
            baseUrl = "http://localhost/api/auth",
            httpClient = httpClient,
            retry = RetryOptions(maxRetries = 1, baseDelayMillis = 1, maxDelayMillis = 10),
        )

        assertEquals(null, client.getSession())
        assertEquals(2, attempts)
    }

    @Test
    fun sessionCookieIsReusedForLaterRequests() = runTest {
        var calls = 0
        var receivedCookie: String? = null
        val httpClient = HttpClient(MockEngine) {
            installBetterAuth()
            engine {
                addHandler {
                    calls += 1
                    receivedCookie = it.headers[HttpHeaders.Cookie]
                    if (calls == 1) {
                        respond(
                            content = SESSION_JSON,
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf(ContentType.Application.Json.toString()),
                                HttpHeaders.SetCookie to listOf(
                                    "better-auth.session_token=session-token; Path=/",
                                ),
                            ),
                        )
                    } else {
                        respond("null", HttpStatusCode.OK, JSON_HEADERS)
                    }
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        client.signUpEmail(SignUpEmailInput("user@example.com", "User", "password"))
        client.getSession()

        assertEquals("better-auth.session_token=session-token", receivedCookie)
    }

    @Test
    fun genericRequestsAcceptJsonBodies() = runTest {
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler {
                    respond("""{"ok":true}""", HttpStatusCode.OK, JSON_HEADERS)
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        val result = client.request<GenericResponse>(
            path = "/plugin/example",
            method = HttpMethod.Post,
            body = buildJsonObject { put("enabled", true) },
        )

        assertEquals(true, result.ok)
    }

    @Test
    fun baseUrlAndPathValidationRejectAmbiguousUrls() = runTest {
        val httpClient = HttpClient(MockEngine) {
            engine { addHandler { respond("null") } }
        }

        assertFailsWith<IllegalArgumentException> {
            AuthClient("ftp://localhost/api/auth", httpClient)
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)
        assertFailsWith<IllegalArgumentException> {
            client.request<JsonObjectResponse>("relative")
        }
    }

    @kotlinx.serialization.Serializable
    data class GenericResponse(val ok: Boolean)

    @kotlinx.serialization.Serializable
    data class JsonObjectResponse(val value: String = "")

    private companion object {
        const val SESSION_JSON = """
            {
              "user": {
                "id": "user-id",
                "email": "user@example.com",
                "name": "User",
                "email_verified": false,
                "image": null
              },
              "session": {
                "id": "session-id",
                "user_id": "user-id",
                "expires_at": 2000000000
              }
            }
        """
        val JSON_HEADERS = headersOf(
            HttpHeaders.ContentType,
            ContentType.Application.Json.toString(),
        )
    }

    @Test
    fun twoFactorChallengeIsReportedInsteadOfDecodedAsASession() = runTest {
        var request: HttpRequestData? = null
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler {
                    request = it
                    respond(
                        content = """{"two_factor_required":true,"challenge_token":"challenge-1"}""",
                        status = HttpStatusCode.OK,
                        headers = JSON_HEADERS,
                    )
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        val result = client.signInEmailOrChallenge(SignInEmailInput("user@example.com", "password"))

        assertEquals(SignInResult.TwoFactorRequired("challenge-1"), result)
        assertEquals("/api/auth/sign-in/email", request?.url?.encodedPath)
    }

    @Test
    fun accountRoutesUseServerFieldNames() = runTest {
        val bodies = mutableListOf<Pair<String, String>>()
        val httpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    val body = (request.body as? TextContent)?.text.orEmpty()
                    bodies += request.url.encodedPath to body
                    respond(
                        content = """{"changed":true,"revoked_sessions":2}""",
                        status = HttpStatusCode.OK,
                        headers = JSON_HEADERS,
                    )
                }
            }
        }
        val client = AuthClient("http://localhost/api/auth", httpClient)

        val result = client.changePassword("old-password-1", "new-password-2")

        assertEquals(2, result.revokedSessions)
        assertEquals("/api/auth/change-password", bodies.single().first)
        assertEquals(
            """{"current_password":"old-password-1","new_password":"new-password-2"}""",
            bodies.single().second,
        )
    }
}
