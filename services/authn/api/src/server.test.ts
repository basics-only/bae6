import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createAuthnApi } from "./server.js";

let pingFails = false;
const server = createAuthnApi({
  ping: async () => {
    if (pingFails) throw new Error("db down");
  },
  requestTimeoutMs: 5000,
});
let base: string;
before(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => server.close());

test("liveness never checks the database", async () => {
  pingFails = true;
  try {
    const res = await fetch(`${base}/health/live`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  } finally {
    pingFails = false;
  }
});

test("readiness fails while the database is unreachable", async () => {
  assert.equal((await fetch(`${base}/health/ready`)).status, 200);
  pingFails = true;
  try {
    const res = await fetch(`${base}/health/ready`);
    assert.equal(res.status, 503);
    assert.equal((await res.json()).code, "unavailable");
  } finally {
    pingFails = false;
  }
});

test("an unknown path is a 404 envelope that echoes a valid request ID", async () => {
  const res = await fetch(`${base}/v1/anything`, {
    headers: { "x-request-id": "abc-123" },
  });
  assert.equal(res.status, 404);
  assert.equal(res.headers.get("x-request-id"), "abc-123");
  assert.deepEqual(await res.json(), {
    code: "not_found",
    message: "Not found.",
    requestId: "abc-123",
  });
});

test("a malformed request ID is replaced, not echoed", async () => {
  const res = await fetch(`${base}/health/live`, {
    headers: { "x-request-id": "bad idé" },
  });
  assert.match(res.headers.get("x-request-id") ?? "", /^req_[0-9a-f-]{36}$/);
});

test("readiness fails once draining starts", async () => {
  const draining = createAuthnApi({
    ping: async () => {},
    requestTimeoutMs: 5000,
  });
  await new Promise<void>((r) => draining.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(draining.address() as AddressInfo).port}`;
  try {
    assert.equal((await fetch(`${url}/health/ready`)).status, 200);
    draining.drain();
    assert.equal((await fetch(`${url}/health/ready`)).status, 503);
  } finally {
    draining.closeAllConnections();
    draining.close();
  }
});
