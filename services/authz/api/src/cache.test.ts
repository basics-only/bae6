import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { ttlCached } from "./cache.js";

const counting = (value: string | null) => {
  let calls = 0;
  return {
    fn: async (_key: string) => {
      calls++;
      return value;
    },
    calls: () => calls,
  };
};

test("serves a kept result from memory within the ttl", async () => {
  const source = counting("store-1");
  const lookup = ttlCached(source.fn, 5000, (v) => v !== null);
  await lookup("crm-prod");
  await lookup("crm-prod");
  assert.equal(source.calls(), 1);
});

test("looks a miss up again every time so a new binding applies at once", async () => {
  const source = counting(null);
  const lookup = ttlCached(source.fn, 5000, (v) => v !== null);
  await lookup("crm-prod");
  await lookup("crm-prod");
  assert.equal(source.calls(), 2);
});

test("looks a result up again once the ttl has passed", async () => {
  mock.timers.enable({ apis: ["Date"], now: 0 });
  try {
    const source = counting("store-1");
    const lookup = ttlCached(source.fn, 5000, (v) => v !== null);
    await lookup("crm-prod");
    mock.timers.tick(5001);
    await lookup("crm-prod");
    assert.equal(source.calls(), 2);
  } finally {
    mock.timers.reset();
  }
});

test("keeps separate results per argument list", async () => {
  const source = counting("store-1");
  const lookup = ttlCached(source.fn, 5000, (v) => v !== null);
  await lookup("crm-prod");
  await lookup("crm-dev");
  assert.equal(source.calls(), 2);
});

test("does not cache at all when the ttl is 0", async () => {
  const source = counting("store-1");
  const lookup = ttlCached(source.fn, 0, (v) => v !== null);
  await lookup("crm-prod");
  await lookup("crm-prod");
  assert.equal(source.calls(), 2);
});
