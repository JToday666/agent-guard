import { defineConfig } from "@playwright/test";

const liveBaseURL = "http://127.0.0.1:4175";
const rollbackBaseURL = "http://127.0.0.1:4176";
const guardApiURL = "http://127.0.0.1:4188";
const requestedStorageBackend = process.env.AGENTGUARD_S1_STORAGE_BACKEND ?? "memory";
if (requestedStorageBackend !== "memory" && requestedStorageBackend !== "postgres") {
  throw new Error("AGENTGUARD_S1_STORAGE_BACKEND must be memory or postgres");
}
const storageBackend = requestedStorageBackend;

export default defineConfig({
  expect: { timeout: 10_000 },
  fullyParallel: false,
  outputDir: `test-results-s1-live-${storageBackend}`,
  projects: [
    {
      name: `s1-live-${storageBackend}-chromium`,
      use: { viewport: { height: 900, width: 1440 } },
    },
  ],
  reporter: "list",
  testDir: "e2e",
  testMatch: /s1-live\.spec\.ts/,
  timeout: 60_000,
  workers: 1,
  use: {
    baseURL: liveBaseURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: [
    {
      command: [
        "uv run --directory ../.. --group bench",
        "python -m tests.support.runtime_safety_harness serve",
        `--storage-backend ${storageBackend}`,
        "--host 127.0.0.1 --port 4188 --reset-postgres",
      ].join(" "),
      reuseExistingServer: false,
      timeout: 60_000,
      url: `${guardApiURL}/health`,
    },
    {
      command: [
        `VITE_BACKEND_TARGET=${guardApiURL}`,
        "VITE_RUNTIME_SUPERVISION_S1_ENABLED=true",
        "pnpm dev --host 127.0.0.1 --port 4175",
      ].join(" "),
      reuseExistingServer: false,
      timeout: 30_000,
      url: liveBaseURL,
    },
    {
      command: [
        `VITE_BACKEND_TARGET=${guardApiURL}`,
        "VITE_RUNTIME_SUPERVISION_S1_ENABLED=false",
        "pnpm dev --host 127.0.0.1 --port 4176",
      ].join(" "),
      reuseExistingServer: false,
      timeout: 30_000,
      url: rollbackBaseURL,
    },
  ],
});
