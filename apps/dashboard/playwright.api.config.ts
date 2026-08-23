import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4174";

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results-api",
  projects: [
    {
      name: "api-desktop-1280",
      use: { viewport: { height: 720, width: 1280 } },
    },
    {
      name: "api-desktop-1366",
      use: { viewport: { height: 768, width: 1366 } },
    },
    {
      name: "api-desktop-1440",
      use: { viewport: { height: 900, width: 1440 } },
    },
    {
      name: "api-desktop-1920",
      use: { viewport: { height: 1080, width: 1920 } },
    },
  ],
  reporter: "list",
  testDir: "e2e",
  testMatch: /api-mode\.spec\.ts/,
  workers: 1,
  use: {
    baseURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "VITE_EVIDENCE_POLL_INTERVAL_MS=2000 pnpm dev --host 127.0.0.1 --port 4174",
    reuseExistingServer: false,
    timeout: 30_000,
    url: baseURL,
  },
});
