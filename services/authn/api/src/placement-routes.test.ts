import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import { createPlacementRoutes } from "./placement-routes.js";
import { createAuthnApi } from "./server.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ALICE = `prn_${"a".repeat(32)}`;
const GLOBEX_USER = `prn_${"b".repeat(32)}`;
const SECRET = "p".repeat(40);
let db: pg.Pool;
let close: () => Promise<void>;
let server: ReturnType<typeof createAuthnApi>;
let base: string;

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_plc",
  ));
  await db.query(
    `INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'acme', 'user'), ($2, 'globex', 'user')`,
    [ALICE, GLOBEX_USER],
  );
  server = createAuthnApi({
    ping: async () => {},
    requestTimeoutMs: 5000,
    routes: createPlacementRoutes({
      db,
      clientSecret: async (client) =>
        ({ placement: SECRET, other: "o".repeat(40) })[client],
    }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (skip) return;
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await close();
});

const put = (
  principalId: string,
  body: unknown,
  headers: Record<string, string> = {
    authorization: `Bearer ${SECRET}`,
    "content-type": "application/json",
  },
) =>
  fetch(`${base}/admin/principals/${principalId}/org-path`, {
    method: "PUT",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

const orgPath = async (id: string) =>
  (await db.query("SELECT org_path FROM principals WHERE id = $1", [id]))
    .rows[0].org_path;

test(
  "the placement client moves a principal and the new path is stored",
  { skip },
  async () => {
    const res = await put(ALICE, {
      tenantId: "acme",
      principalType: "user",
      orgPath: ["acme", "finance"],
    });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      principalId: ALICE,
      tenantId: "acme",
      orgPath: ["acme", "finance"],
    });
    assert.deepEqual(await orgPath(ALICE), ["acme", "finance"]);
  },
);

test(
  "placement refuses callers without the placement client secret",
  { skip },
  async () => {
    const body = {
      tenantId: "acme",
      principalType: "user",
      orgPath: ["acme", "legal"],
    };
    const json = { "content-type": "application/json" };
    for (const headers of [
      json,
      { ...json, authorization: `Bearer ${"o".repeat(40)}` },
      { ...json, authorization: "Bearer wrong" },
    ]) {
      const res = await put(ALICE, body, headers);
      assert.equal(res.status, 401);
      assert.equal(res.headers.get("www-authenticate"), "Bearer");
    }
    assert.deepEqual(await orgPath(ALICE), ["acme", "finance"]);
  },
);

test(
  "placement refuses a unit outside the tenant, a principal of another tenant and malformed requests",
  { skip },
  async () => {
    const refused = async (res: Response, status: number, code: string) => {
      assert.equal(res.status, status);
      assert.equal((await res.json()).code, code);
    };
    await refused(
      await put(ALICE, {
        tenantId: "acme",
        principalType: "user",
        orgPath: ["globex", "finance"],
      }),
      400,
      "invalid_request",
    );
    await refused(
      await put(ALICE, {
        tenantId: "globex",
        principalType: "user",
        orgPath: ["globex", "x"],
      }),
      404,
      "unknown_principal",
    );
    await refused(
      await put(GLOBEX_USER, {
        tenantId: "acme",
        principalType: "user",
        orgPath: ["acme", "x"],
      }),
      404,
      "unknown_principal",
    );
    await refused(
      await put(ALICE, { tenantId: "acme", principalType: "user" }),
      400,
      "invalid_request",
    );
    await refused(
      await put(ALICE, { tenantId: "acme", orgPath: ["acme", "x"] }),
      400,
      "invalid_request",
    );
    await refused(
      await put(ALICE, {
        tenantId: "acme",
        principalType: "service",
        orgPath: ["acme", "x"],
      }),
      400,
      "invalid_request",
    );
    await refused(await put(ALICE, "[1]"), 400, "invalid_request");
    await refused(await put(ALICE, "{"), 400, "invalid_request");
    await refused(
      await put(ALICE, "tenantId=acme", {
        authorization: `Bearer ${SECRET}`,
        "content-type": "text/plain",
      }),
      400,
      "invalid_request",
    );
    await refused(
      await put(ALICE, {
        tenantId: "acme",
        principalType: "user",
        orgPath: ["acme", "x".repeat(5000)],
      }),
      400,
      "invalid_request",
    );
    assert.deepEqual(await orgPath(ALICE), ["acme", "finance"]);
    const get = await fetch(`${base}/admin/principals/${ALICE}/org-path`);
    assert.equal(get.status, 405);
    assert.equal(get.headers.get("allow"), "PUT");
  },
);
