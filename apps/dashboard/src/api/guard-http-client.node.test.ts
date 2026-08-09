import assert from "node:assert/strict";
import test from "node:test";

import { requestConditionalJson } from "./guard-http-client.ts";

test("sends If-None-Match and preserves data on a 304 response", async () => {
  const originalFetch = globalThis.fetch;
  let requestEtag: string | null = null;
  globalThis.fetch = async (_input, init) => {
    requestEtag = new Headers(init?.headers).get("if-none-match");
    return new Response(null, {
      status: 304,
      headers: { ETag: '"trace-v1"' },
    });
  };

  try {
    const result = await requestConditionalJson<{ trace_id: string }>(
      "/traces/trace-1",
      '"trace-v1"',
    );
    assert.equal(requestEtag, '"trace-v1"');
    assert.deepEqual(result, { status: "not_modified", etag: '"trace-v1"' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("returns the response validator with a modified JSON document", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ trace_id: "trace-2" }), {
      status: 200,
      headers: { "Content-Type": "application/json", ETag: '"trace-v2"' },
    });

  try {
    const result = await requestConditionalJson<{ trace_id: string }>("/traces/trace-2");
    assert.deepEqual(result, {
      status: "modified",
      etag: '"trace-v2"',
      value: { trace_id: "trace-2" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("does not reuse a request validator when a modified response omits ETag", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ trace_id: "trace-3" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  try {
    const result = await requestConditionalJson<{ trace_id: string }>(
      "/traces/trace-3",
      '"trace-v2"',
    );
    assert.deepEqual(result, {
      status: "modified",
      etag: null,
      value: { trace_id: "trace-3" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
