import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Authz, AuthzApiError } from "./index.js";

const ALICE = `prn_${"a".repeat(32)}`;

test("placePrincipal puts the unit for the principal and rejects an unusable answer", async () => {
  const seen: string[] = [];
  let answer: unknown = { unit: "finance" };
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    seen.push(`${req.method} ${req.url} ${body}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(answer));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const authz = new Authz({
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    credentials: "t",
    application: "crm",
  });
  try {
    const input = {
      principalId: ALICE,
      principalType: "user",
      unit: "finance",
    } as const;
    await authz.placePrincipal(input);
    assert.deepEqual(seen, [
      `PUT /v1/tenant/principals/${ALICE}/unit {"principalType":"user","unit":"finance"}`,
    ]);
    answer = {};
    await assert.rejects(authz.placePrincipal(input), AuthzApiError);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
