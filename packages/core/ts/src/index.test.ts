import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type ClientOptions,
  Transport,
  type TransportErrors,
} from "./index.js";

class ApiError extends Error {
  constructor(readonly status: number) {
    super(`api ${status}`);
  }
}
class NetError extends Error {}

const errors: TransportErrors = {
  timeout: () => new NetError("timeout"),
  unreachable: (name) => new NetError(`unreachable ${name}`),
  tooLarge: () => new NetError("too large"),
  api: (status) => new ApiError(status),
};

const reply = (status: number, body = "{}") =>
  new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });

function transport(
  fetchImpl: typeof fetch,
  extra: Partial<ClientOptions> = {},
) {
  return new Transport(
    {
      baseUrl: "http://svc.test/",
      credentials: "tok",
      fetch: fetchImpl,
      ...extra,
    },
    { timeoutMs: 1000, errors },
  );
}

test("sends requests through the injected fetch with bearer credentials", async () => {
  let seen: { url: string; auth: string } | undefined;
  const t = transport(async (url, init) => {
    seen = {
      url: String(url),
      auth: new Headers(init?.headers).get("authorization") ?? "",
    };
    return reply(200);
  });
  await t.raw("GET", "/v1/x");
  assert.deepEqual(seen, { url: "http://svc.test/v1/x", auth: "Bearer tok" });
});

test("calls a credentials function before every attempt", async () => {
  let n = 0;
  const auths: string[] = [];
  const t = transport(
    async (_url, init) => {
      auths.push(new Headers(init?.headers).get("authorization") ?? "");
      return auths.length === 1 ? reply(503) : reply(200);
    },
    { credentials: async () => `tok${++n}` },
  );
  await t.raw("GET", "/v1/x");
  assert.deepEqual(auths, ["Bearer tok1", "Bearer tok2"]);
});

test("onRequest can add headers and onResponse sees each attempt", async () => {
  const sent: (string | null)[] = [];
  const seen: [number, number][] = [];
  const t = transport(
    async (_url, init) => {
      sent.push(new Headers(init?.headers).get("x-trace"));
      return sent.length === 1 ? reply(502) : reply(200);
    },
    {
      onRequest: (r) => {
        r.headers["x-trace"] = `a${r.attempt}`;
      },
      onResponse: (r) => {
        seen.push([r.attempt, r.status]);
      },
    },
  );
  await t.raw("GET", "/v1/x");
  assert.deepEqual(sent, ["a1", "a2"]);
  assert.deepEqual(seen, [
    [1, 502],
    [2, 200],
  ]);
});

test("maxRetries 0 disables retries of idempotent requests", async () => {
  let calls = 0;
  const t = transport(
    async () => {
      calls++;
      return reply(503);
    },
    { maxRetries: 0 },
  );
  await assert.rejects(t.raw("GET", "/v1/x"), ApiError);
  assert.equal(calls, 1);
});

test("maxRetries bounds the attempts", async () => {
  let calls = 0;
  const t = transport(
    async () => {
      calls++;
      return reply(503);
    },
    { maxRetries: 1 },
  );
  await assert.rejects(t.raw("GET", "/v1/x"), ApiError);
  assert.equal(calls, 2);
});

test("rejects a maxRetries outside the supported range", () => {
  assert.throws(() => transport(fetch, { maxRetries: 6 }), RangeError);
  assert.throws(() => transport(fetch, { maxRetries: -1 }), RangeError);
});

test("does not retry a POST without an idempotency key", async () => {
  let calls = 0;
  const t = transport(async () => {
    calls++;
    return reply(503);
  });
  await assert.rejects(t.raw("POST", "/v1/x", { body: {} }), ApiError);
  assert.equal(calls, 1);
});

test("retries a dropped connection on an idempotent request", async () => {
  let calls = 0;
  const t = transport(async () => {
    if (++calls === 1) throw new TypeError("fetch failed");
    return reply(200);
  });
  await t.raw("GET", "/v1/x");
  assert.equal(calls, 2);
});

test("a failing hook or credentials function is raised once and not retried", async () => {
  let calls = 0;
  const hook = transport(
    async () => {
      calls++;
      return reply(200);
    },
    {
      onRequest: () => {
        throw new Error("hook failed");
      },
    },
  );
  await assert.rejects(hook.raw("GET", "/v1/x"), /hook failed/);
  const creds = transport(
    async () => {
      calls++;
      return reply(200);
    },
    {
      credentials: () => {
        throw new Error("no token");
      },
    },
  );
  await assert.rejects(creds.raw("GET", "/v1/x"), /no token/);
  assert.equal(calls, 0);
});

test("rejects empty credentials", async () => {
  assert.throws(() => transport(fetch, { credentials: "" }), TypeError);
  const t = transport(fetch, { credentials: () => "" });
  await assert.rejects(t.raw("GET", "/v1/x"), TypeError);
});

test("the error from a failed connection does not carry the token", async () => {
  const t = transport(
    async () => {
      throw new TypeError("bad header value Bearer tok");
    },
    { maxRetries: 0 },
  );
  const err = await t.raw("GET", "/v1/x").catch((e: Error) => e);
  assert.doesNotMatch(`${err} ${(err as Error).message}`, /tok/);
});
