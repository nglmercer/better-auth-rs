import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "a fresh passphrase for the reset";

/** An address no other test uses, since all tests share one server. */
function uniqueEmail(label: string): string {
  const random = Math.random().toString(36).slice(2, 10);
  return `${label}-${Date.now()}-${random}@example.com`;
}

/** The origin the server expects on state-changing requests. */
function origin(page: Page): string {
  return new URL(page.url() || "http://127.0.0.1:4173").origin;
}

async function createAccountOverApi(request: APIRequestContext, baseURL: string, email: string) {
  const response = await request.post("/api/auth/sign-up/email", {
    headers: { Origin: baseURL, "Content-Type": "application/json" },
    data: { name: "Test Person", email, password: PASSWORD },
  });
  expect(response.status()).toBe(200);
}

/** The most recent reset token mailed to `email`, read from the test mailbox. */
async function resetTokenFor(request: APIRequestContext, email: string): Promise<string> {
  const response = await request.get("/__test/emails");
  const messages = (await response.json()) as { to: string; text: string }[];
  const message = [...messages].reverse().find((candidate) => candidate.to === email);
  expect(message, `a reset email was sent to ${email}`).toBeDefined();
  const match = /token=([0-9a-zA-Z]+)/.exec(message!.text);
  expect(match, "the reset email contains a token").not.toBeNull();
  return match![1];
}

async function signInWithForm(page: Page, email: string, password: string) {
  await page.goto("/");
  await page.locator("#login input[name=email]").fill(email);
  await page.locator("#login input[name=password]").fill(password);
  await page.locator("#login button[type=submit]").click();
}

test("a visitor creates an account in the browser and is signed in", async ({ page, context }) => {
  const email = uniqueEmail("signup");
  await page.goto("/");
  await page.locator("button[data-view=register]").click();
  await page.locator("#register input[name=name]").fill("Ada Test");
  await page.locator("#register input[name=email]").fill(email);
  await page.locator("#register input[name=password]").fill(PASSWORD);
  await page.locator("#register button[type=submit]").click();

  await expect(page.locator(".auth-card > .result .result-title")).toHaveText("Request succeeded");
  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "better-auth.session_token");
  expect(session, "the session cookie is set").toBeDefined();
  // The page script cannot read the session cookie, and it is sent only to this site.
  expect(session!.httpOnly).toBe(true);
  expect(session!.sameSite).toBe("Lax");
  expect(await page.evaluate(() => document.cookie)).not.toContain("better-auth.session_token");

  const session_response = await page.request.get("/api/auth/get-session");
  expect((await session_response.json()).user.email).toBe(email);
});

test("a wrong password is rejected and creates no session", async ({ page, request, context }) => {
  const email = uniqueEmail("wrong-password");
  await createAccountOverApi(request, "http://127.0.0.1:4173", email);

  await signInWithForm(page, email, "not the password at all");
  await expect(page.locator(".auth-card > .result .result-title")).toHaveText("Request was rejected");
  const cookies = await context.cookies();
  expect(cookies.find((cookie) => cookie.name === "better-auth.session_token")).toBeUndefined();
});

test("an existing account signs in with the right password", async ({ page, request }) => {
  const email = uniqueEmail("sign-in");
  await createAccountOverApi(request, "http://127.0.0.1:4173", email);

  await signInWithForm(page, email, PASSWORD);
  await expect(page.locator(".auth-card > .result .result-title")).toHaveText("Request succeeded");
  const session_response = await page.request.get("/api/auth/get-session");
  expect((await session_response.json()).user.email).toBe(email);
});

test("password recovery through the dialog sets a new password", async ({ page, request }) => {
  const email = uniqueEmail("recovery");
  await createAccountOverApi(request, "http://127.0.0.1:4173", email);

  await page.goto("/");
  await page.locator("[data-open-recovery]").click();
  await page.locator("#request-recovery input[name=email]").fill(email);
  await page.locator("#request-recovery button[type=submit]").click();

  // The dialog moves to the token step once the request is accepted.
  await expect(page.locator("#verify-recovery")).toBeVisible();
  const token = await resetTokenFor(request, email);
  await page.locator("#verify-recovery input[name=token]").fill(token);
  await page.locator("#verify-recovery button[type=submit]").click();

  await expect(page.locator("#reset-password")).toBeVisible();
  await page.locator("#reset-password input[name=new_password]").fill(NEW_PASSWORD);
  await page.locator("#reset-password input[name=confirm_password]").fill(NEW_PASSWORD);
  await page.locator("#reset-password button[type=submit]").click();
  await expect(page.locator("#recovery-modal .result .result-title")).toHaveText("Password updated");

  // The new password works, and the old one no longer does.
  const newPassword = await request.post("/api/auth/sign-in/email", {
    headers: { Origin: "http://127.0.0.1:4173", "Content-Type": "application/json" },
    data: { email, password: NEW_PASSWORD },
  });
  expect(newPassword.status()).toBe(200);
  const oldPassword = await request.post("/api/auth/sign-in/email", {
    headers: { Origin: "http://127.0.0.1:4173", "Content-Type": "application/json" },
    data: { email, password: PASSWORD },
  });
  expect(oldPassword.status()).toBe(401);
});

test("a reset token cannot be used twice", async ({ page, request }) => {
  const email = uniqueEmail("token-reuse");
  await createAccountOverApi(request, "http://127.0.0.1:4173", email);
  await page.goto("/");
  await page.locator("[data-open-recovery]").click();
  await page.locator("#request-recovery input[name=email]").fill(email);
  await page.locator("#request-recovery button[type=submit]").click();
  await expect(page.locator("#verify-recovery")).toBeVisible();
  const token = await resetTokenFor(request, email);

  const first = await request.post("/api/auth/reset-password", {
    headers: { Origin: "http://127.0.0.1:4173", "Content-Type": "application/json" },
    data: { token, new_password: NEW_PASSWORD },
  });
  expect(first.status()).toBe(200);
  expect((await first.json()).reset).toBe(true);
  const second = await request.post("/api/auth/reset-password", {
    headers: { Origin: "http://127.0.0.1:4173", "Content-Type": "application/json" },
    data: { token, new_password: "yet another passphrase here" },
  });
  // The same token is answered like an unknown one: 200 with reset false, so the reply
  // does not reveal whether a token was ever valid.
  expect(second.status()).toBe(200);
  expect((await second.json()).reset).toBe(false);
});

test("requests from another site are refused even with a valid session", async ({ page, request }) => {
  const email = uniqueEmail("csrf");
  await createAccountOverApi(request, "http://127.0.0.1:4173", email);
  await signInWithForm(page, email, PASSWORD);
  await expect(page.locator(".auth-card > .result .result-title")).toHaveText("Request succeeded");

  // A page on another site can send the browser's cookies, but not its origin check.
  const cookieHeader = (await page.context().cookies())
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
  const forged = await request.post("/api/auth/sign-out", {
    headers: { Origin: "https://evil.example", Cookie: cookieHeader },
  });
  expect(forged.status()).toBe(403);
  // The legitimate session is still there.
  const still = await page.request.get("/api/auth/get-session");
  expect((await still.json()).user.email).toBe(email);
});

test("the form shows a server rejection without leaving the page", async ({ page }) => {
  await page.goto("/");
  await page.locator("#login input[name=email]").fill("nobody-here@example.com");
  await page.locator("#login input[name=password]").fill(PASSWORD);
  await page.locator("#login button[type=submit]").click();
  await expect(page.locator(".auth-card > .result .result-title")).toHaveText("Request was rejected");
  expect(origin(page)).toBe("http://127.0.0.1:4173");
});
