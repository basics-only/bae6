import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Authz, AuthzApiError } from "./index.js";

test("tenantCheck posts the resource and raises instead of denying quietly", async () => {
  const seen: string[] = [];
  let reply: [number, unknown] = [200, { allowed: true }];
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    seen.push(`${req.method} ${req.url} ${body}`);
    res.writeHead(reply[0], { "content-type": "application/json" });
    res.end(JSON.stringify(reply[1]));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const authz = new Authz({
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    credentials: "t",
    application: "crm",
  });
  const input = { resourceType: "model", resourceId: "llm" };
  try {
    assert.equal(await authz.tenantCheck(input), true);
    assert.deepEqual(seen, [
      'POST /v1/tenant/check {"resourceType":"model","resourceId":"llm"}',
    ]);
    reply = [200, { allowed: false }];
    assert.equal(await authz.tenantCheck(input), false);
    reply = [200, { allowed: "yes" }];
    await assert.rejects(authz.tenantCheck(input), AuthzApiError);
    reply = [
      503,
      { code: "authorization_unavailable", message: "x", requestId: "r" },
    ];
    await assert.rejects(authz.tenantCheck(input), { status: 503 });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
