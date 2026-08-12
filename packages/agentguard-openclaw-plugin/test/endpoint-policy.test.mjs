import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  GuardApiClient,
  validateGuardApiBaseUrl as validatePluginEndpoint,
} from "../dist/guard-api-client.js";
import { validateGuardApiBaseUrl as validateScriptEndpoint } from "../../../scripts/guard-api-endpoint.mjs";

const fixture = JSON.parse(
  fs.readFileSync(
    fileURLToPath(
      new URL(
        "../../../tests/fixtures/guard_api_endpoint_policy.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
);

test("plugin and repository scripts share the Guard API endpoint policy", () => {
  for (const entry of fixture.allowed) {
    assert.equal(validatePluginEndpoint(entry.input), entry.normalized);
    assert.equal(validateScriptEndpoint(entry.input), entry.normalized);
  }
  for (const value of fixture.rejected) {
    assert.throws(() => validatePluginEndpoint(value));
    assert.throws(() => validateScriptEndpoint(value));
  }
});

test("GuardApiClient rejects unsafe targets before fetch or token exposure", () => {
  let fetchCalls = 0;

  assert.throws(
    () =>
      new GuardApiClient({
        config: {
          guardApiBaseUrl: "http://user@attacker.example",
          adapterToken: "adapter-secret",
          requestTimeoutMs: 1000,
          approvalPollIntervalMs: 10,
          approvalTimeoutMs: 10,
        },
        fetchImpl: async () => {
          fetchCalls += 1;
          return new Response("{}");
        },
      }),
    (error) => {
      assert.equal(String(error.message).includes("adapter-secret"), false);
      assert.equal(String(error.message).includes("attacker.example"), false);
      return true;
    },
  );
  assert.equal(fetchCalls, 0);
});

test("GuardApiClient forbids redirects and never issues a second request", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.example",
      adapterToken: "adapter-secret",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
    },
    fetchImpl: async (url, init) => {
      requests.push({ url: String(url), init });
      return new Response("", {
        status: 307,
        headers: { location: "https://attacker.example/collect" },
      });
    },
  });

  await assert.rejects(() => client.evaluate({ event_id: "evt_redirect" }));

  assert.equal(requests.length, 1);
  assert.equal(requests[0].init.redirect, "error");
  assert.equal(requests[0].init.headers.Authorization, "Bearer adapter-secret");
});
