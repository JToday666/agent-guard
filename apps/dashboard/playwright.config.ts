import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4173";

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results",
  projects: [
    {
      name: "desktop-functional",
      testIgnore: /(api-mode|desktop-matrix|tablet-matrix)\.spec\.ts/,
      use: { viewport: { height: 768, width: 1366 } },
    },
    {
      name: "desktop-1280",
      testMatch: /desktop-matrix\.spec\.ts/,
      use: { viewport: { height: 720, width: 1280 } },
    },
    {
      name: "desktop-1366",
      testMatch: /desktop-matrix\.spec\.ts/,
      use: { viewport: { height: 768, width: 1366 } },
    },
    {
      name: "desktop-1440",
      testMatch: /desktop-matrix\.spec\.ts/,
      use: { viewport: { height: 900, width: 1440 } },
    },
    {
      name: "desktop-1920",
      testMatch: /desktop-matrix\.spec\.ts/,
      use: { viewport: { height: 1080, width: 1920 } },
    },
    {
      name: "tablet-768",
      testMatch: /tablet-matrix\.spec\.ts/,
      use: { viewport: { height: 1024, width: 768 } },
    },
    {
      name: "tablet-820",
      testMatch: /tablet-matrix\.spec\.ts/,
      use: { viewport: { height: 1180, width: 820 } },
    },
    {
      name: "tablet-1024",
      testMatch: /tablet-matrix\.spec\.ts/,
      use: { viewport: { height: 768, width: 1024 } },
    },
    {
      name: "tablet-1180",
      testMatch: /tablet-matrix\.spec\.ts/,
      use: { viewport: { height: 820, width: 1180 } },
    },
    {
      name: "tablet-1199",
      testMatch: /tablet-matrix\.spec\.ts/,
      use: { viewport: { height: 900, width: 1199 } },
    },
  ],
  reporter: "list",
  testDir: "e2e",
  testIgnore: /api-mode\.spec\.ts/,
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
