import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type { Principal } from "../auth/index.js";
import { HttpError } from "../http.js";
import { createApp } from "../server.js";
import { tenantRoutes } from "./routes.js";

const ALICE = `prn_${"a".repeat(32)}`;
const tenantAdmin: Principal = {
  subject: `user:prn_${"b".repeat(32)}`,
  organization: "acme",
  scopes: ["tenant"],
  applications: [],
};
const workload: Principal = { ...tenantAdmin, scopes: ["check"] };
let who: Principal = tenantAdmin;
let calls: unknown[][] = [];
let server: ReturnType<typeof createApp>;
let base: string;

before(async () => {
  server = createApp({
    authenticate: async () => who,
    readiness: async () => [],
    log: () => {},
    routes: tenantRoutes((organization) => ({
      placePrincipal: async (...args: unknown[]) => {
        calls.push([organization, ...args.slice(0, 3)]);
        if (args[2] === "gone")
          throw new HttpError(404, "not_found", "Unknown unit.");
        return undefined as never;
      },
      placeResource: async (...args: unknown[]) => {
        calls.push([organization, ...args.slice(0, 4)]);
        return "42";
      },
      check: async (subject: string, type: string, id: string) => {
        calls.push([organization, subject, type, id]);
        if (id === "down")
          throw new HttpError(503, "authorization_unavailable", "Down.");
        return id === "yes";
      },
    })),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const put = (body: unknown, id = ALICE) =>
  fetch(`${base}/v1/tenant/principals/${id}/unit`, {
    method: "PUT",
    headers: { authorization: "Bearer x", "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

test("a tenant principal places a principal in its own tenant as itself", async () => {
  calls = [];
  who = tenantAdmin;
  const res = await put({ principalType: "user", unit: "finance" });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    principalId: ALICE,
    principalType: "user",
    unit: "finance",
  });
  assert.deepEqual(calls, [
    ["acme", tenantAdmin.subject, `user:${ALICE}`, "finance"],
  ]);
});

test("placement refuses callers without the tenant scope, bad requests and unknown units", async () => {
  calls = [];
  who = workload;
  assert.equal(
    (await put({ principalType: "user", unit: "finance" })).status,
    403,
  );
  who = tenantAdmin;
  for (const body of [
    { unit: "finance" },
    { principalType: "group", unit: "finance" },
    { principalType: "user" },
    "[1]",
    "{",
    { principalType: "user", unit: "x".repeat(2000) },
  ])
    assert.equal((await put(body)).status, 400);
  assert.equal(
    (await put({ principalType: "user", unit: "gone" })).status,
    404,
  );
  const get = await fetch(`${base}/v1/tenant/principals/${ALICE}/unit`, {
    headers: { authorization: "Bearer x" },
  });
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "PUT");
  assert.equal(calls.filter((c) => c[3] !== "gone").length, 0);
});

const check = (body: unknown) =>
  fetch(`${base}/v1/tenant/check`, {
    method: "POST",
    headers: { authorization: "Bearer x", "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

test("a check answers for the token principal in its own tenant and never from the body", async () => {
  calls = [];
  who = tenantAdmin;
  const allowed = await check({
    resourceType: "model",
    resourceId: "yes",
    subject: "user:other",
  });
  assert.deepEqual(await allowed.json(), { allowed: true });
  const denied = await check({ resourceType: "model", resourceId: "no" });
  assert.deepEqual(await denied.json(), { allowed: false });
  assert.deepEqual(calls, [
    ["acme", tenantAdmin.subject, "model", "yes"],
    ["acme", tenantAdmin.subject, "model", "no"],
  ]);
});

test("a check refuses missing scope, bad requests and wrong methods, and reports an outage as 503", async () => {
  who = workload;
  assert.equal(
    (await check({ resourceType: "model", resourceId: "yes" })).status,
    403,
  );
  who = tenantAdmin;
  for (const body of [
    { resourceType: "model" },
    { resourceId: "yes" },
    "[1]",
    "{",
  ])
    assert.equal((await check(body)).status, 400);
  const down = await check({ resourceType: "model", resourceId: "down" });
  assert.equal(down.status, 503);
  assert.equal((await down.json()).code, "authorization_unavailable");
  const get = await fetch(`${base}/v1/tenant/check`, {
    headers: { authorization: "Bearer x" },
  });
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
});

const extAuthz = (resource: string | undefined, path = "", method = "GET") =>
  fetch(`${base}/v1/tenant/ext-authz${path}`, {
    method,
    headers: {
      authorization: "Bearer x",
      ...(resource === undefined ? {} : { "bae6-resource": resource }),
    },
  });

test("ext-authz answers an empty 200 for an allow on any method and path under it, and denies otherwise", async () => {
  calls = [];
  who = tenantAdmin;
  const allowed = await extAuthz("model:yes", "/v1/chat/completions", "POST");
  assert.equal(allowed.status, 200);
  assert.equal(await allowed.text(), "");
  assert.equal((await extAuthz("model:no")).status, 403);
  assert.equal((await extAuthz("model:down")).status, 503);
  assert.deepEqual(calls[0], ["acme", tenantAdmin.subject, "model", "yes"]);
});

test("ext-authz refuses a missing or malformed resource header and a principal without the tenant scope", async () => {
  who = tenantAdmin;
  for (const header of [
    undefined,
    "",
    "model",
    "model:",
    ":yes",
    "a:b:c",
    "model: x",
  ])
    assert.equal((await extAuthz(header)).status, 400);
  who = workload;
  assert.equal((await extAuthz("model:yes")).status, 403);
});

test("resource placement uses the authenticated tenant and actor", async () => {
  calls = [];
  const input = { resourceType: "model", resourceId: "llm", unit: "finance" };
  const register = () =>
    fetch(`${base}/v1/tenant/resources/unit`, {
      method: "PUT",
      headers: {
        authorization: "Bearer x",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        ...input,
        organization: "other",
        actor: "user:other",
      }),
    });
  who = workload;
  assert.equal((await register()).status, 403);
  who = tenantAdmin;
  const result = await register();
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), { ...input, auditEventId: "42" });
  assert.deepEqual(calls, [
    ["acme", tenantAdmin.subject, "model", "llm", "finance"],
  ]);
});
