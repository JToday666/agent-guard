import { defineConfig } from "@playwright/test";

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results-roadmap",
  projects: [
    {
      name: "roadmap-artifact-chromium",
      use: {
        browserName: "chromium",
        viewport: { height: 900, width: 1440 },
      },
    },
  ],
  reporter: "list",
  testDir: "e2e",
  testMatch: /roadmap-artifact\.spec\.ts/,
  timeout: 30_000,
  use: {
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  workers: 1,
});
