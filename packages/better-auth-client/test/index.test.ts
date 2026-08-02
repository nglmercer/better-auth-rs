import { describe, expect, it, vi } from "vitest";
import { AuthClient, AuthClientError } from "../src/index";

function jsonResponse(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function makeFetch(...responses: Response[]) {
  let index = 0;
  return vi.fn(async (..._args: Parameters<typeof fetch>) => {
    const response = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return response;
  });
}

describe("AuthClient", () => {
  it("supports every typed AuthRouter endpoint", async () => {
    const fetchMock = makeFetch(
      jsonResponse({ verified: true }),
      jsonResponse({ sent: true }),
      jsonResponse({ reset: true }),
      jsonResponse({}),
    );
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth/",
      fetch: fetchMock,
    });

    await expect(client.verifyEmail({ token: "verify-token" })).resolves.toEqual({
      verified: true,
    });
    await expect(
      client.requestPasswordReset({ email: "user@example.com" }),
    ).resolves.toEqual({ sent: true });
    await expect(
      client.resetPassword({ token: "reset-token", new_password: "new-password" }),
    ).resolves.toEqual({ reset: true });
    await expect(client.signOut()).resolves.toBeUndefined();

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "https://example.test/api/auth/verify-email",
      "https://example.test/api/auth/request-password-reset",
      "https://example.test/api/auth/reset-password",
      "https://example.test/api/auth/sign-out",
    ]);
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: "verify-token",
    });
    expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toEqual({
      token: "reset-token",
      new_password: "new-password",
    });
    expect(fetchMock.mock.calls[3]?.[1]?.body).toBeUndefined();
  });

  it("returns null for an empty session", async () => {
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      fetch: makeFetch(jsonResponse(null)),
    });

    await expect(client.getSession()).resolves.toBeNull();
  });

  it("merges default and per-request headers and preserves credentials", async () => {
    const fetchMock = makeFetch(jsonResponse({ ok: true }));
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      headers: { "X-Default": "yes", Accept: "application/default" },
      credentials: "include",
      fetch: fetchMock,
    });

    await client.request("/custom", {
      method: "POST",
      headers: { "X-Request": "yes", Accept: "application/request" },
      credentials: "omit",
      body: { value: 1 },
    });

    const init = fetchMock.mock.calls[0]?.[1];
    const headers = new Headers(init?.headers);
    expect(headers.get("X-Default")).toBe("yes");
    expect(headers.get("X-Request")).toBe("yes");
    expect(headers.get("Accept")).toBe("application/request");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(init?.credentials).toBe("omit");
  });

  it("retries safe requests and honors Retry-After HTTP dates", async () => {
    const fetchMock = makeFetch(
      jsonResponse({ error: "busy" }, 503, {
        "Retry-After": new Date(Date.now() - 1).toUTCString(),
      }),
      jsonResponse({ ok: true }),
    );
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      retry: { maxRetries: 1, baseDelayMs: 1, maxDelayMs: 10 },
      fetch: fetchMock,
    });

    await expect(client.request("/health", { method: "GET" })).resolves.toEqual({
      ok: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry unsafe writes unless an idempotency key is supplied", async () => {
    const fetchMock = makeFetch(jsonResponse({ error: "busy" }, 503));
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      retry: { maxRetries: 1, baseDelayMs: 1, maxDelayMs: 10 },
      fetch: fetchMock,
    });

    await expect(
      client.request("/write", { method: "POST", body: { value: 1 } }),
    ).rejects.toMatchObject({ status: 503 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries an idempotent POST and exposes structured errors", async () => {
    const fetchMock = makeFetch(
      jsonResponse({ error: "busy" }, 503, { "Retry-After": "0" }),
      jsonResponse({ created: true }),
    );
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      retry: { maxRetries: 1, baseDelayMs: 1, maxDelayMs: 10 },
      fetch: fetchMock,
    });

    await expect(
      client.request("/write", {
        method: "POST",
        body: { value: 1 },
        idempotencyKey: "request-1",
      }),
    ).resolves.toEqual({ created: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(
      new Headers(fetchMock.mock.calls[0]?.[1]?.headers).get("Idempotency-Key"),
    ).toBe("request-1");

    const failing = new AuthClient({
      baseURL: "https://example.test/api/auth",
      retry: { maxRetries: 0 },
      fetch: makeFetch(
        jsonResponse({ error: { message: "invalid", code: "INVALID_INPUT" } }, 400),
      ),
    });
    await expect(failing.request("/write", { method: "GET" })).rejects.toEqual(
      expect.objectContaining({
        status: 400,
        code: "INVALID_INPUT",
        message: "invalid",
        details: { error: { message: "invalid", code: "INVALID_INPUT" } },
      }),
    );
  });

  it("stops retry backoff when aborted", async () => {
    const controller = new AbortController();
    const fetchMock = makeFetch(
      jsonResponse({ error: "busy" }, 503, { "Retry-After": "1" }),
    );
    const client = new AuthClient({
      baseURL: "https://example.test/api/auth",
      retry: { maxRetries: 1, baseDelayMs: 1, maxDelayMs: 2_000 },
      fetch: fetchMock,
    });

    const request = client.request("/health", {
      method: "GET",
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const reason = new Error("cancelled");
    controller.abort(reason);
    await expect(request).rejects.toBe(reason);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects invalid or cross-origin URL inputs", () => {
    const fetchMock = makeFetch(jsonResponse({}));
    expect(
      () => new AuthClient({ baseURL: "ftp://example.test", fetch: fetchMock }),
    ).toThrow("baseURL must use http or https");
    expect(
      () => new AuthClient({ baseURL: "https://example.test/api?tenant=1", fetch: fetchMock }),
    ).toThrow("baseURL must not include a query or fragment");

    const client = new AuthClient({
      baseURL: "https://example.test/api",
      fetch: fetchMock,
    });
    expect(() => client.request("//evil.test")).toThrow();
    expect(() => client.request("https://evil.test")).toThrow();
  });

  it("throws AuthClientError for invalid success JSON", async () => {
    const client = new AuthClient({
      baseURL: "https://example.test/api",
      fetch: makeFetch(new Response("not-json", { status: 200 })),
    });

    await expect(client.request("/broken", { method: "GET" })).rejects.toBeInstanceOf(
      AuthClientError,
    );
  });
});
