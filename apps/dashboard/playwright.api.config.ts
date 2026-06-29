import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4174";

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results-api",
  projects: [
    { name: "api-desktop", use: { viewport: { height: 768, width: 1366 } } },
  ],
  reporter: "list",
  testDir: "e2e",
  testMatch: /api-mode\.spec\.ts/,
  use: {
    baseURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "pnpm dev --host 127.0.0.1 --port 4174",
    reuseExistingServer: false,
    timeout: 30_000,
    url: baseURL,
  },
});
