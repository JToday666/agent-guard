import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4173";

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results",
  projects: [
    { name: "desktop", use: { viewport: { height: 768, width: 1366 } } },
    { name: "tablet", use: { viewport: { height: 1024, width: 768 } } },
    { name: "mobile", use: { viewport: { height: 844, width: 390 } } },
  ],
  reporter: "list",
  testDir: "e2e",
  use: {
    baseURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "pnpm dev:mock --host 127.0.0.1 --port 4173",
    reuseExistingServer: false,
    timeout: 30_000,
    url: baseURL,
  },
});
