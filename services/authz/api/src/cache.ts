const MAX_ENTRIES = 10_000;

/**
 * Memoizes `fn` for `ttlMs`, keeping only results `keep` accepts, so a miss (unknown
 * application, no bindings, no active model) is always looked up again. A `ttlMs` of 0 disables it.
 */
export function ttlCached<A extends string[], V>(
  fn: (...args: A) => Promise<V>,
  ttlMs: number,
  keep: (value: V) => boolean,
): (...args: A) => Promise<V> {
  if (ttlMs === 0) return fn;
  const entries = new Map<string, { value: V; expires: number }>();
  return async (...args) => {
    const key = JSON.stringify(args);
    const hit = entries.get(key);
    if (hit && hit.expires > Date.now()) return hit.value;
    const value = await fn(...args);
    if (keep(value)) {
      entries.delete(key);
      entries.set(key, { value, expires: Date.now() + ttlMs });
      // Map iterates in insertion order, so the first key is the oldest.
      if (entries.size > MAX_ENTRIES) {
        entries.delete(entries.keys().next().value as string);
      }
    }
    return value;
  };
}
