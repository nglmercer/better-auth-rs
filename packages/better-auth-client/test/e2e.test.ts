import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuthClient, isTwoFactorChallenge } from "../src/index";

const packageDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(packageDirectory, "../../..");

let server: ChildProcess | undefined;
let authBaseURL = "";

function startServer(): Promise<string> {
  const binary =
    process.env.BETTER_AUTH_E2E_BIN ??
    join(
      repositoryRoot,
      "target",
      "debug",
      "examples",
      `web-example${process.platform === "win32" ? ".exe" : ""}`,
    );
  const child = spawn(binary, [], {
      cwd: repositoryRoot,
      env: { ...process.env, CARGO_TERM_COLOR: "never" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  server = child;

  return new Promise((resolveReady, reject) => {
    let output = "";
    let settled = false;
    const timeout = setTimeout(() => {
      finish(new Error(`Timed out waiting for test server. Output:\n${output}`));
    }, 180_000);

    const finish = (error?: Error, readyURL?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) reject(error);
      else resolveReady(readyURL!);
    };

    const onOutput = (chunk: Buffer) => {
      output += chunk.toString();
      const match = output.match(/READY\s+(http:\/\/127\.0\.0\.1:\d+\/api\/auth)/);
      if (match) finish(undefined, match[1]);
    };

    child.stdout?.on("data", onOutput);
    child.stderr?.on("data", onOutput);
    child.once("error", (error) => finish(error));
    child.once("exit", (code, signal) => {
      finish(new Error(`Test server exited before readiness: code=${code}, signal=${signal}\n${output}`));
    });
  });
}

function stopServer() {
  if (!server?.pid) return;
  if (process.platform === "win32") {
    server.kill();
  } else {
    try {
      process.kill(-server.pid, "SIGTERM");
    } catch {
      server.kill("SIGTERM");
    }
  }
  server = undefined;
}

function cookieFetch() {
  let cookie = "";
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    if (cookie) headers.set("cookie", cookie);
    const response = await fetch(input, { ...init, headers });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) cookie = setCookie.split(";", 1)[0] ?? "";
    return response;
  };
}

describe("AuthClient against the Rust web example", () => {
  beforeAll(async () => {
    authBaseURL = await startServer();
  });

  afterAll(() => {
    stopServer();
  });

  it("performs a real registration and login flow", async () => {
    const fetchWithCookies = cookieFetch();
    const client = new AuthClient({
      baseURL: authBaseURL,
      fetch: fetchWithCookies,
      retry: { maxRetries: 0 },
    });
    const email = `e2e-${Date.now()}@example.com`;
    const password = "correct horse battery staple";

    const signedUp = await client.signUp.email({
      email,
      name: "E2E User",
      password,
    });
    expect(signedUp.user.email).toBe(email);
    expect(signedUp.session.user_id).toBe(signedUp.user.id);

    const signedIn = await client.signIn.email({ email, password });
    // The account has no second factor, so sign-in returns a session.
    if (isTwoFactorChallenge(signedIn)) throw new Error("unexpected challenge");
    expect(signedIn.user.id).toBe(signedUp.user.id);
    expect(signedIn.session.user_id).toBe(signedUp.user.id);
  });
});
