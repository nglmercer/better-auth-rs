import { defineConfig, devices } from "@playwright/test";

// A fixed port, because the server builds reset links from it and the browser must
// reach the same address.
const port = 4173;

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  // One server with one in-memory store, so tests run one after another. Each test
  // uses its own email address, so they do not depend on each other.
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // The example is built on demand by cargo. Test mode fixes the port, uses a
    // static base URL and captures email at /__test/emails.
    command: "cargo run -q -p better-auth --example web-example",
    cwd: "..",
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
    env: {
      BETTER_AUTH_EXAMPLE_TEST_MODE: "1",
      BETTER_AUTH_EXAMPLE_PORT: String(port),
    },
  },
});
