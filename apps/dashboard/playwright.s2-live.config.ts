import { defineConfig } from "@playwright/test";

const dashboardURL = "http://127.0.0.1:4177";
const guardApiURL = "http://127.0.0.1:4198";
const storage = process.env.AGENTGUARD_S2_STORAGE_BACKEND ?? "memory";
if (!new Set(["memory", "postgres"]).has(storage)) {
  throw new Error("AGENTGUARD_S2_STORAGE_BACKEND must be memory or postgres");
}

export default defineConfig({
  fullyParallel: false,
  outputDir: `test-results-s2-live-${storage}`,
  reporter: "list",
  testDir: "e2e",
  testMatch: /s2-live\.spec\.ts/,
  timeout: 60_000,
  workers: 1,
  use: {
    baseURL: dashboardURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: [
        "uv run --directory ../.. --group bench",
        "python -m tests.support.runtime_supervision_s2_harness serve",
        `--storage-backend ${storage}`,
        "--host 127.0.0.1 --port 4198 --reset-postgres",
      ].join(" "),
      timeout: 120_000,
      url: `${guardApiURL}/health`,
    },
    {
      command: `VITE_BACKEND_TARGET=${guardApiURL} ./node_modules/.bin/vite --host 127.0.0.1 --port 4177`,
      timeout: 30_000,
      url: dashboardURL,
    },
  ],
});
