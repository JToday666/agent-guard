export interface TimedCacheEntry<T> {
  accessedAt: number;
  cachedAt: number;
  value: T;
}

export type TimedCache<T> = Record<string, TimedCacheEntry<T>>;

export function getFreshCacheValue<T>(
  cache: TimedCache<T>,
  key: string,
  ttlMs: number,
  now = Date.now(),
): T | undefined {
  const entry = cache[key];
  if (!entry || now - entry.cachedAt > ttlMs) return undefined;
  entry.accessedAt = now;
  return entry.value;
}

export function getCachedValue<T>(cache: TimedCache<T>, key: string): T | undefined {
  return cache[key]?.value;
}

export function setBoundedCacheValue<T>(
  cache: TimedCache<T>,
  key: string,
  value: T,
  maxEntries: number,
  now = Date.now(),
): TimedCache<T> {
  const next: TimedCache<T> = {
    ...cache,
    [key]: { accessedAt: now, cachedAt: now, value },
  };
  const keys = Object.keys(next);
  if (keys.length <= maxEntries) return next;

  const evictionKey = keys
    .filter((candidate) => candidate !== key)
    .sort((left, right) => next[left]!.accessedAt - next[right]!.accessedAt)[0];
  if (evictionKey) delete next[evictionKey];
  return next;
}

export function removeCacheValue<T>(cache: TimedCache<T>, key: string): TimedCache<T> {
  if (!cache[key]) return cache;
  const next = { ...cache };
  delete next[key];
  return next;
}

export function unwrapTimedCache<T>(cache: TimedCache<T>): Record<string, T> {
  return Object.fromEntries(Object.entries(cache).map(([key, entry]) => [key, entry.value]));
}
