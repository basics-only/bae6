import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Authz, AuthzApiError } from "./index.js";
import { executionContextOf, fastifyHook, tenantGuard } from "./middleware.js";

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

test("placeTenantResource sends the placement and returns its audit ID", async () => {
  const input = { resourceType: "model", resourceId: "llm", unit: "finance" };
  const authz = new Authz({
    baseUrl: "https://authz.example",
    credentials: "t",
    application: "crm",
    fetch: async (url, init) => {
      assert.equal(
        String(url),
        "https://authz.example/v1/tenant/resources/unit",
      );
      assert.equal(init?.method, "PUT");
      assert.deepEqual(JSON.parse(String(init?.body)), input);
      return Response.json({ ...input, auditEventId: "42" });
    },
  });
  assert.equal(await authz.placeTenantResource(input), "42");
});

test("tenant middleware exposes verified context only for a successful check", async () => {
  const resource = { resourceType: "model", resourceId: "llm" };
  const context = {
    tenantId: "acme",
    orgPath: ["acme"],
    principalId: `prn_${"a".repeat(32)}`,
    principalType: "user",
    actorId: `prn_${"a".repeat(32)}`,
    requestId: "signed-request",
  };
  let response: unknown = {
    allowed: true,
    executionContext: { ...context, unexpected: "dropped" },
  };
  const guard = tenantGuard({
    includeExecutionContext: true,
    authz: {
      baseUrl: "https://authz.example",
      application: "crm",
      fetch: async (_url, init) => {
        assert.deepEqual(JSON.parse(String(init?.body)), {
          ...resource,
          includeExecutionContext: true,
        });
        return Response.json(response);
      },
    },
    async exchange() {
      return { accessToken: "t", expiresIn: 300 };
    },
  });
  const request = {
    headers: { authorization: "Bearer caller", "x-request-id": "forged" },
  };
  let status: number | undefined;
  const reply = {
    code(code: number) {
      status = code;
      return this;
    },
    header() {
      return this;
    },
    send() {},
  };
  const hook = fastifyHook(guard, () => resource);
  await hook(request, reply);
  assert.deepEqual(executionContextOf(request), context);
  response = { allowed: false };
  await hook(request, reply);
  assert.equal(status, 403);
  assert.equal(executionContextOf(request), undefined);
  for (const bad of [
    { allowed: true },
    {
      allowed: true,
      executionContext: { ...context, delegationId: `dlg_${"c".repeat(32)}` },
    },
  ]) {
    response = bad;
    status = undefined;
    await hook(request, reply);
    assert.equal(status, 503);
    assert.equal(executionContextOf(request), undefined);
  }
});
