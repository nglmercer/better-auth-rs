export interface SignUpEmailInput {
  email: string;
  name: string;
  password: string;
}

export interface SignInEmailInput {
  email: string;
  password: string;
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  email_verified: boolean;
  image: string | null;
}

export interface AuthSession {
  id: string;
  user_id: string;
  expires_at: number;
}

export interface AuthSessionResponse {
  user: AuthUser;
  session: AuthSession;
}

export interface VerifyEmailInput {
  token: string;
}

export interface VerifyEmailResponse {
  verified: boolean;
}

export interface RequestPasswordResetInput {
  email: string;
}

export interface RequestPasswordResetResponse {
  sent: boolean;
}

export interface ResetPasswordInput {
  token: string;
  new_password: string;
}

export interface ResetPasswordResponse {
  reset: boolean;
}

export interface TwoFactorChallengeResponse {
  two_factor_required: true;
  challenge_token: string;
}

/** Password sign-in succeeds with a session, or with a second-factor challenge. */
export type SignInEmailResponse = AuthSessionResponse | TwoFactorChallengeResponse;

export function isTwoFactorChallenge(
  response: SignInEmailResponse,
): response is TwoFactorChallengeResponse {
  return "two_factor_required" in response && response.two_factor_required === true;
}

export interface AdminUser {
  id: string;
  email: string;
  name: string;
  role: string | null;
  email_verified: boolean;
}

export interface SessionSummary {
  id: string;
  expires_at: number;
  current: boolean;
}

export interface LinkedAccount {
  provider_id: string;
  account_id: string;
}

/** A passkey as the signed-in user sees it. The credential itself never leaves the server. */
export interface PasskeyView {
  id: string;
  name: string | null;
  credential_id: string;
}

/**
 * WebAuthn options as the server sends them (base64url fields). Browsers need
 * binary buffers, so convert them before calling `navigator.credentials`.
 */
export type PasskeyOptions = Record<string, unknown>;

export interface TwoFactorEnrollment {
  secret: string;
  totp_uri: string;
  backup_codes: string[];
}

export interface RetryOptions {
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

export interface AuthClientOptions {
  /** Auth server URL, including its API base path when configured. */
  baseURL: string | URL;
  /** Inject a fetch implementation for tests, workers, or custom runtimes. */
  fetch?: typeof globalThis.fetch;
  /** Headers applied to every request; per-request headers take precedence. */
  headers?: HeadersInit;
  /** Browser clients should keep this as `include` for session cookies. */
  credentials?: RequestCredentials;
  retry?: RetryOptions;
}

export interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  /** Retries a POST only when the server can safely deduplicate it. */
  idempotencyKey?: string;
}

export class AuthClientError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: unknown;

  constructor(message: string, status: number, code?: string, details?: unknown) {
    super(message);
    this.name = "AuthClientError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

export class AuthClient {
  readonly signUp = {
    email: (input: SignUpEmailInput) =>
      this.request<AuthSessionResponse>("/sign-up/email", {
        method: "POST",
        body: input,
      }),
  };

  readonly signIn = {
    email: (input: SignInEmailInput) =>
      this.request<SignInEmailResponse>("/sign-in/email", {
        method: "POST",
        body: input,
      }),
  };

  readonly magicLink = {
    send: (input: { email: string }) =>
      this.request<{ sent: true }>("/sign-in/magic-link", {
        method: "POST",
        body: input,
      }),
  };

  readonly emailOtp = {
    send: (input: { email: string }) =>
      this.request<{ sent: true }>("/email-otp/send", {
        method: "POST",
        body: input,
      }),
    verify: (input: { email: string; code: string }) =>
      this.request<AuthSessionResponse>("/email-otp/verify", {
        method: "POST",
        body: input,
      }),
  };

  readonly admin = {
    listUsers: (options: { limit?: number; offset?: number } = {}) => {
      const query = new URLSearchParams();
      if (options.limit !== undefined) query.set("limit", String(options.limit));
      if (options.offset !== undefined) query.set("offset", String(options.offset));
      const suffix = query.size > 0 ? `?${query.toString()}` : "";
      return this.request<{ users: AdminUser[] }>(`/admin/list-users${suffix}`, {
        method: "GET",
      });
    },
    setRole: (input: { userId: string; role: string }) =>
      this.request<{ updated: true }>("/admin/set-role", {
        method: "POST",
        body: { user_id: input.userId, role: input.role },
      }),
    revokeSessions: (input: { userId: string }) =>
      this.request<{ revoked: number }>("/admin/revoke-sessions", {
        method: "POST",
        body: { user_id: input.userId },
      }),
  };

  /** Passkey ceremonies. The browser runs WebAuthn between the two steps of each pair. */
  readonly passkey = {
    registerOptions: () =>
      this.request<{ transaction_id: string; options: PasskeyOptions }>(
        "/passkey/generate-register-options",
        { method: "POST", body: {} },
      ),
    register: (input: { transactionId: string; response: unknown; name?: string }) =>
      this.request<{ passkey: PasskeyView }>("/passkey/verify-registration", {
        method: "POST",
        body: {
          transaction_id: input.transactionId,
          response: input.response,
          name: input.name,
        },
      }),
    signInOptions: () =>
      this.request<{ transaction_id: string; options: PasskeyOptions }>(
        "/passkey/generate-authenticate-options",
        { method: "POST", body: {} },
      ),
    signIn: (input: { transactionId: string; response: unknown }) =>
      this.request<SignInEmailResponse>("/passkey/verify-authentication", {
        method: "POST",
        body: { transaction_id: input.transactionId, response: input.response },
      }),
    list: () =>
      this.request<{ passkeys: PasskeyView[] }>("/passkey/list-user-passkeys", {
        method: "GET",
      }),
    rename: (input: { id: string; name: string }) =>
      this.request<{ updated: boolean }>("/passkey/update-passkey", {
        method: "POST",
        body: input,
      }),
    delete: (input: { id: string }) =>
      this.request<{ deleted: boolean }>("/passkey/delete-passkey", {
        method: "POST",
        body: input,
      }),
  };

  readonly twoFactor = {
    enable: (input: { password: string }) =>
      this.request<TwoFactorEnrollment>("/two-factor/enable", {
        method: "POST",
        body: input,
      }),
    confirm: (input: { code: string }) =>
      this.request<{ enabled: true }>("/two-factor/confirm", {
        method: "POST",
        body: input,
      }),
    disable: (input: { password: string }) =>
      this.request<{ enabled: false }>("/two-factor/disable", {
        method: "POST",
        body: input,
      }),
    verify: (input: { challengeToken: string; code: string }) =>
      this.request<AuthSessionResponse>("/two-factor/verify", {
        method: "POST",
        body: { challenge_token: input.challengeToken, code: input.code },
      }),
  };

  private readonly baseURL: URL;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly defaultHeaders: Headers;
  private readonly credentials: RequestCredentials;
  private readonly retry: Required<RetryOptions>;

  constructor(options: AuthClientOptions) {
    const baseURL = new URL(options.baseURL);
    if (baseURL.protocol !== "http:" && baseURL.protocol !== "https:") {
      throw new TypeError("baseURL must use http or https");
    }
    if (baseURL.search || baseURL.hash) {
      throw new TypeError("baseURL must not include a query or fragment");
    }
    this.baseURL = new URL(baseURL.toString().replace(/\/+$/, ""));
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new TypeError("a fetch implementation is required");
    }
    this.fetchImpl = options.fetch ?? fetchImpl.bind(globalThis);
    this.defaultHeaders = new Headers(options.headers);
    this.credentials = options.credentials ?? "include";
    this.retry = {
      maxRetries: options.retry?.maxRetries ?? 2,
      baseDelayMs: options.retry?.baseDelayMs ?? 100,
      maxDelayMs: options.retry?.maxDelayMs ?? 2000,
    };
    if (
      !Number.isInteger(this.retry.maxRetries) ||
      this.retry.maxRetries < 0 ||
      !Number.isFinite(this.retry.baseDelayMs) ||
      this.retry.baseDelayMs <= 0 ||
      !Number.isFinite(this.retry.maxDelayMs) ||
      this.retry.maxDelayMs < this.retry.baseDelayMs
    ) {
      throw new TypeError("invalid retry options");
    }
  }

  getSession(): Promise<AuthSessionResponse | null> {
    return this.request<AuthSessionResponse | null>("/get-session", {
      method: "GET",
    });
  }

  async signOut(): Promise<void> {
    await this.request<unknown>("/sign-out", { method: "POST" });
  }

  listSessions(): Promise<{ sessions: SessionSummary[] }> {
    return this.request<{ sessions: SessionSummary[] }>("/list-sessions", {
      method: "GET",
    });
  }

  revokeSession(id: string): Promise<{ revoked: number }> {
    return this.request<{ revoked: number }>("/revoke-session", {
      method: "POST",
      body: { id },
    });
  }

  revokeOtherSessions(): Promise<{ revoked: number }> {
    return this.request<{ revoked: number }>("/revoke-other-sessions", {
      method: "POST",
    });
  }

  async revokeSessions(): Promise<void> {
    await this.request<unknown>("/revoke-sessions", { method: "POST" });
  }

  listAccounts(): Promise<{ accounts: LinkedAccount[] }> {
    return this.request<{ accounts: LinkedAccount[] }>("/list-accounts", {
      method: "GET",
    });
  }

  changePassword(input: {
    currentPassword: string;
    newPassword: string;
  }): Promise<{ changed: true; revoked_sessions: number }> {
    return this.request<{ changed: true; revoked_sessions: number }>("/change-password", {
      method: "POST",
      body: { current_password: input.currentPassword, new_password: input.newPassword },
    });
  }

  updateUser(input: { name: string }): Promise<{ user: AuthUser }> {
    return this.request<{ user: AuthUser }>("/update-user", {
      method: "POST",
      body: input,
    });
  }

  async deleteUser(input: { password: string }): Promise<void> {
    await this.request<unknown>("/delete-user", { method: "POST", body: input });
  }

  sendVerificationEmail(): Promise<{ sent: true }> {
    return this.request<{ sent: true }>("/send-verification-email", {
      method: "POST",
    });
  }

  verifyEmail(input: VerifyEmailInput): Promise<VerifyEmailResponse> {
    return this.request<VerifyEmailResponse>("/verify-email", {
      method: "POST",
      body: input,
    });
  }

  requestPasswordReset(
    input: RequestPasswordResetInput,
  ): Promise<RequestPasswordResetResponse> {
    return this.request<RequestPasswordResetResponse>("/request-password-reset", {
      method: "POST",
      body: input,
    });
  }

  resetPassword(input: ResetPasswordInput): Promise<ResetPasswordResponse> {
    return this.request<ResetPasswordResponse>("/reset-password", {
      method: "POST",
      body: input,
    });
  }

  request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const {
      body: bodyValue,
      headers: requestHeaders,
      idempotencyKey,
      ...requestOptions
    } = options;
    const method = (options.method ?? "GET").toUpperCase();
    const headers = new Headers(this.defaultHeaders);
    new Headers(requestHeaders).forEach((value, key) => headers.set(key, value));
    if (!headers.has("Accept")) headers.set("Accept", "application/json");
    if (idempotencyKey) {
      headers.set("Idempotency-Key", idempotencyKey);
    }
    const body = bodyValue === undefined ? undefined : JSON.stringify(bodyValue);
    if (body !== undefined && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const requestInit: RequestInit = {
      ...requestOptions,
      method,
      headers,
      body,
      credentials: requestOptions.credentials ?? this.credentials,
    };

    const retrySafe = ["GET", "HEAD", "OPTIONS"].includes(method) || Boolean(idempotencyKey);
    return this.execute<T>(this.url(path), requestInit, retrySafe);
  }

  private url(path: string): string {
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TypeError("client paths must start with '/'");
    }
    return new URL(path.slice(1), `${this.baseURL.toString()}/`).toString();
  }

  private async execute<T>(url: string, init: RequestInit, retrySafe: boolean): Promise<T> {
    let attempt = 0;
    while (true) {
      let response: Response;
      try {
        response = await this.fetchImpl(url, init);
      } catch (error) {
        if (init.signal?.aborted || !retrySafe || attempt >= this.retry.maxRetries) {
          throw error;
        }
        await delay(this.backoff(attempt), init.signal ?? undefined);
        attempt += 1;
        continue;
      }

      if (response.ok) {
        return parseResponse<T>(response);
      }
      if (!retrySafe || !RETRYABLE_STATUSES.has(response.status) || attempt >= this.retry.maxRetries) {
        throw await toClientError(response);
      }
      try {
        await response.body?.cancel();
      } catch {
        // The retry should proceed even if the failed response cannot be cancelled.
      }
      const retryAfter = parseRetryAfter(response.headers.get("Retry-After"));
      await delay(
        Math.min(retryAfter ?? this.backoff(attempt), this.retry.maxDelayMs),
        init.signal ?? undefined,
      );
      attempt += 1;
    }
  }

  private backoff(attempt: number): number {
    return Math.min(this.retry.baseDelayMs * 2 ** attempt, this.retry.maxDelayMs);
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  if (!text) {
    return undefined as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new AuthClientError("Auth server returned invalid JSON", response.status);
  }
}

async function toClientError(response: Response): Promise<AuthClientError> {
  let details: unknown;
  try {
    details = await response.clone().json();
  } catch {
    details = undefined;
  }
  const object = isRecord(details) ? details : undefined;
  const error = object && isRecord(object.error) ? object.error : object;
  const message =
    (typeof object?.error === "string" && object.error) ||
    (error && typeof error.message === "string" && error.message) ||
    `Auth request failed (${response.status})`;
  const code = error && typeof error.code === "string" ? error.code : undefined;
  return new AuthClientError(message, response.status, code, details);
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - Date.now()) : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(signal.reason ?? new Error("The operation was aborted"));
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      reject(signal?.reason ?? new Error("The operation was aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
