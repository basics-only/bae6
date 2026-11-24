import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, test } from "node:test";
import { fastifyHook, nodeMiddleware, tenantGuard } from "./middleware.js";

let authzServer: Server;
let baseUrl: string;
let answer: { status: number; body: unknown };
let exchanges: string[];
let checked: { authorization: string | undefined; body: unknown }[];
let exchangeFails: { status?: number } | undefined;

before(async () => {
  authzServer = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
    });
    req.on("end", () => {
      checked.push({
        authorization: req.headers.authorization,
        body: JSON.parse(raw),
      });
      res.writeHead(answer.status, { "content-type": "application/json" });
      res.end(JSON.stringify(answer.body));
    });
  });
  await new Promise<void>((r) => authzServer.listen(0, "127.0.0.1", r));
  baseUrl = `http://127.0.0.1:${(authzServer.address() as AddressInfo).port}`;
});

after(() => {
  authzServer.close();
});

beforeEach(() => {
  answer = { status: 200, body: { allowed: true } };
  exchanges = [];
  checked = [];
  exchangeFails = undefined;
});

const guard = () =>
  tenantGuard({
    authz: {
      baseUrl,
      application: "app",
      credentials: "unused",
    } as never,
    async exchange(subjectToken) {
      exchanges.push(subjectToken);
      if (exchangeFails) throw Object.assign(new Error("x"), exchangeFails);
      return { accessToken: `authz-for-${subjectToken}`, expiresIn: 300 };
    },
  });

const resource = { resourceType: "model", resourceId: "gpt" };

test("an allowed check passes and authz sees the exchanged token and the resource", async () => {
  assert.deepEqual(await guard()("Bearer t1", resource), { allowed: true });
  assert.deepEqual(checked, [
    { authorization: "Bearer authz-for-t1", body: resource },
  ]);
});

test("a denied check is 403", async () => {
  answer = { status: 200, body: { allowed: false } };
  const verdict = await guard()("Bearer t1", resource);
  assert.equal(verdict.allowed, false);
  assert.equal(!verdict.allowed && verdict.status, 403);
});

test("a missing or malformed bearer is 401 without contacting anyone", async () => {
  for (const header of [undefined, "", "Basic abc", "Bearer ", "Bearer a b"]) {
    const verdict = await guard()(header, resource);
    assert.equal(!verdict.allowed && verdict.status, 401);
  }
  assert.deepEqual(exchanges, []);
  assert.deepEqual(checked, []);
});

test("a request that maps to no resource is denied", async () => {
  const verdict = await guard()("Bearer t1", undefined);
  assert.equal(!verdict.allowed && verdict.status, 403);
  assert.deepEqual(exchanges, []);
});

test("a refused subject token is 401 and an unreachable authn is 503", async () => {
  exchangeFails = { status: 400 };
  let verdict = await guard()("Bearer t1", resource);
  assert.equal(!verdict.allowed && verdict.status, 401);
  exchangeFails = {};
  verdict = await guard()("Bearer t1", resource);
  assert.equal(!verdict.allowed && verdict.status, 503);
  assert.deepEqual(checked, []);
});

test("authz errors deny: 5xx is 503 and 403 is 403, never an allow", async () => {
  answer = { status: 503, body: { code: "authorization_unavailable" } };
  let verdict = await guard()("Bearer t1", resource);
  assert.equal(!verdict.allowed && verdict.status, 503);
  answer = { status: 403, body: { code: "forbidden" } };
  verdict = await guard()("Bearer t1", resource);
  assert.equal(!verdict.allowed && verdict.status, 403);
  answer = { status: 200, body: { allowed: "yes" } };
  verdict = await guard()("Bearer t1", resource);
  assert.equal(verdict.allowed, false);
});

test("the exchanged token is reused for the same subject token", async () => {
  const g = guard();
  await g("Bearer t1", resource);
  await g("Bearer t1", resource);
  await g("Bearer t2", resource);
  assert.deepEqual(exchanges, ["t1", "t2"]);
});

test("node middleware calls next on allow and answers 403 JSON on deny", async () => {
  const g = guard();
  const middleware = nodeMiddleware(g, () => resource);
  const app = createServer((req, res) =>
    middleware(req, res, (err) => {
      res.writeHead(err ? 500 : 200).end("handled");
    }),
  );
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  try {
    let res = await fetch(url, { headers: { authorization: "Bearer t1" } });
    assert.equal(res.status, 200);
    answer = { status: 200, body: { allowed: false } };
    res = await fetch(url, { headers: { authorization: "Bearer t9" } });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).code, "forbidden");
    res = await fetch(url);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("www-authenticate"), "Bearer");
  } finally {
    app.close();
  }
});

test("a resourceOf that throws never reaches the handler", async () => {
  const middleware = nodeMiddleware(guard(), () => {
    throw new Error("boom");
  });
  let nextError: unknown;
  await middleware(
    { headers: { authorization: "Bearer t1" } } as never,
    {} as never,
    (err) => {
      nextError = err;
    },
  );
  assert.equal((nextError as Error).message, "boom");
});

test("fastify hook returns on allow and replies with the denial otherwise", async () => {
  const sent: unknown[] = [];
  const reply = {
    code(status: number) {
      sent.push(status);
      return reply;
    },
    header() {
      return reply;
    },
    send(body: unknown) {
      sent.push(body);
    },
  };
  const hook = fastifyHook(guard(), () => resource);
  await hook({ headers: { authorization: "Bearer t1" } }, reply);
  assert.deepEqual(sent, []);
  answer = { status: 200, body: { allowed: false } };
  await hook({ headers: { authorization: "Bearer t2" } }, reply);
  assert.equal(sent[0], 403);
});
