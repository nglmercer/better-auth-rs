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
      this.request<AuthSessionResponse>("/sign-in/email", {
        method: "POST",
        body: input,
      }),
  };

  private readonly baseURL: URL;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly credentials: RequestCredentials;
  private readonly retry: Required<RetryOptions>;

  constructor(options: AuthClientOptions) {
    const baseURL = new URL(options.baseURL);
    if (baseURL.protocol !== "http:" && baseURL.protocol !== "https:") {
      throw new TypeError("baseURL must use http or https");
    }
    this.baseURL = new URL(baseURL.toString().replace(/\/+$/, ""));
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.credentials = options.credentials ?? "include";
    this.retry = {
      maxRetries: options.retry?.maxRetries ?? 2,
      baseDelayMs: options.retry?.baseDelayMs ?? 100,
      maxDelayMs: options.retry?.maxDelayMs ?? 2000,
    };
    if (
      this.retry.maxRetries < 0 ||
      this.retry.baseDelayMs <= 0 ||
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

  signOut(): Promise<void> {
    return this.request<void>("/sign-out", { method: "POST", body: {} });
  }

  request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const method = (options.method ?? "GET").toUpperCase();
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (options.idempotencyKey) {
      headers.set("Idempotency-Key", options.idempotencyKey);
    }
    const body = options.body === undefined ? undefined : JSON.stringify(options.body);
    if (body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    const requestInit: RequestInit = {
      ...options,
      method,
      headers,
      body,
      credentials: options.credentials ?? this.credentials,
    };
    delete (requestInit as RequestInit & { idempotencyKey?: unknown }).idempotencyKey;

    const retrySafe = ["GET", "HEAD", "OPTIONS"].includes(method) || Boolean(options.idempotencyKey);
    return this.execute<T>(this.url(path), requestInit, retrySafe);
  }

  private url(path: string): string {
    if (!path.startsWith("/")) {
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
        if (!retrySafe || attempt >= this.retry.maxRetries) {
          throw error;
        }
        await delay(this.backoff(attempt));
        attempt += 1;
        continue;
      }

      if (response.ok) {
        return parseResponse<T>(response);
      }
      if (!retrySafe || !RETRYABLE_STATUSES.has(response.status) || attempt >= this.retry.maxRetries) {
        throw await toClientError(response);
      }
      const retryAfter = parseRetryAfter(response.headers.get("Retry-After"));
      await delay(Math.min(retryAfter ?? this.backoff(attempt), this.retry.maxDelayMs));
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
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
