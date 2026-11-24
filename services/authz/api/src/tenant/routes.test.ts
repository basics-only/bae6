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
