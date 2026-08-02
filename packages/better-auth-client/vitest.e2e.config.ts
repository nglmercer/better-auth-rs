import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/e2e.test.ts"],
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
