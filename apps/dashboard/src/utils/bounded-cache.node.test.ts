import assert from "node:assert/strict";
import test from "node:test";

import {
  getFreshCacheValue,
  removeCacheValue,
  setBoundedCacheValue,
  unwrapTimedCache,
} from "./bounded-cache.ts";

test("bounded cache returns fresh values and rejects expired values", () => {
  const cache = setBoundedCacheValue({}, "trace-1", { id: 1 }, 3, 1_000);

  assert.deepEqual(getFreshCacheValue(cache, "trace-1", 500, 1_500), {
    id: 1,
  });
  assert.equal(getFreshCacheValue(cache, "trace-1", 500, 1_501), undefined);
});

test("bounded cache evicts the least recently accessed entry", () => {
  let cache = setBoundedCacheValue({}, "trace-1", { id: 1 }, 2, 1_000);
  cache = setBoundedCacheValue(cache, "trace-2", { id: 2 }, 2, 1_100);
  getFreshCacheValue(cache, "trace-1", 1_000, 1_200);
  cache = setBoundedCacheValue(cache, "trace-3", { id: 3 }, 2, 1_300);

  assert.deepEqual(Object.keys(cache).sort(), ["trace-1", "trace-3"]);
  assert.deepEqual(unwrapTimedCache(cache), {
    "trace-1": { id: 1 },
    "trace-3": { id: 3 },
  });
});

test("bounded cache removes an invalidated entry without mutating the source", () => {
  const cache = setBoundedCacheValue({}, "trace-1", { id: 1 }, 2, 1_000);
  const next = removeCacheValue(cache, "trace-1");

  assert.deepEqual(Object.keys(next), []);
  assert.deepEqual(Object.keys(cache), ["trace-1"]);
});
