import assert from "node:assert/strict";
import { test } from "node:test";

const url = {
  oidc: "http://127.0.0.1:8085",
  agent: "http://127.0.0.1:8087",
  eval: "http://127.0.0.1:8088",
  mcp: "http://127.0.0.1:8084",
  gateway: "http://127.0.0.1:8089",
};

async function token(sub, aud, scope) {
  const res = await fetch(`${url.oidc}/token`, {
    method: "POST",
    body: JSON.stringify({ sub, aud, scope }),
  });
  assert.equal(res.status, 200);
  return (await res.json()).access_token;
}

async function call(base, method, path, { jwt, body } = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return {
    status: res.status,
    body: text.startsWith("{") ? JSON.parse(text) : text,
  };
}

async function finished(base, path, jwt) {
  let run;
  for (const deadline = Date.now() + 60_000; run?.status !== "finished"; ) {
    assert.ok(
      Date.now() < deadline,
      `run did not finish: ${JSON.stringify(run)}`,
    );
    await new Promise((r) => setTimeout(r, 500));
    run = (await call(base, "GET", path, { jwt })).body;
  }
  return run;
}

test("an agent run is queued, answered by the model and readable afterwards", async () => {
  const jwt = await token(
    "research-agent",
    "bae6-ai-agents",
    "agent-runs:write agent-runs:read",
  );
  const created = await call(url.agent, "POST", "/v1/agent-runs", {
    jwt,
    body: { task: "summarize the handbook", model: "chat-mock" },
  });
  assert.equal(created.status, 202, JSON.stringify(created.body));
  const run = await finished(
    url.agent,
    `/v1/agent-runs/${created.body.id}`,
    jwt,
  );
  assert.equal(run.stop, "final");
  assert.match(run.text, /mock reply to: .*summarize the handbook/);
  assert.ok(run.tokens > 0);
});

test("agent runs refuse a missing scope and a wrong audience", async () => {
  const readOnly = await token("viewer", "bae6-ai-agents", "agent-runs:read");
  const body = { task: "x", model: "chat-mock" };
  assert.equal(
    (await call(url.agent, "POST", "/v1/agent-runs", { jwt: readOnly, body }))
      .status,
    403,
  );
  const other = await token("viewer", "bae6-ai-evals", "agent-runs:write");
  assert.equal(
    (await call(url.agent, "POST", "/v1/agent-runs", { jwt: other, body }))
      .status,
    401,
  );
  assert.equal(
    (await call(url.agent, "POST", "/v1/agent-runs", { body })).status,
    401,
  );
});

test("an eval run scores every case and reports the mean", async () => {
  const jwt = await token(
    "evaluator",
    "bae6-ai-evals",
    "eval-runs:write eval-runs:read",
  );
  const created = await call(url.eval, "POST", "/v1/eval-runs", {
    jwt,
    body: {
      name: "smoke",
      datasetVersion: "v1",
      model: "chat-mock",
      scorers: ["contains"],
      cases: [
        { id: "a", input: "alpha", expected: "mock reply to: alpha" },
        { id: "b", input: "beta", expected: "no such text" },
      ],
    },
  });
  assert.equal(created.status, 202, JSON.stringify(created.body));
  const run = await finished(url.eval, `/v1/eval-runs/${created.body.id}`, jwt);
  const byId = Object.fromEntries(run.report.cases.map((c) => [c.id, c]));
  assert.equal(byId.a.scores.contains, 1);
  assert.equal(byId.b.scores.contains, 0);
  assert.equal(run.report.mean.contains, 0.5);
  assert.equal(run.report.failures, 0);
});

test("a tool call goes through the gateway to an approved server and not to a revoked one", async () => {
  const publish = await token(
    "research-agent",
    "bae6-context-mcp",
    "mcp:publish",
  );
  const approve = await token("reviewer", "bae6-context-mcp", "mcp:approve");
  const id = `echo-${Date.now().toString(36)}`;
  const created = await call(url.mcp, "POST", "/v1/servers", {
    jwt: publish,
    body: {
      id,
      team: "research",
      name: "Echo",
      version: {
        version: "1.0.0",
        endpoint: "http://mock-mcp:8080/mcp",
        protocolVersion: "2025-06-18",
        transport: "streamable-http",
        authentication: { method: "none" },
        tools: [{ name: "echo" }],
      },
    },
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal(
    (
      await call(url.mcp, "POST", `/v1/servers/${id}/approve`, {
        jwt: approve,
        body: { version: "1.0.0" },
      })
    ).status,
    200,
  );

  const invoke = await token(
    "research-agent",
    "bae6-context-mcp-gateway",
    "mcp:invoke",
  );
  const path = `/v1/servers/${id}/tools/call`;
  const body = { tool: "echo", arguments: { q: "hi" } };
  const ok = await call(url.gateway, "POST", path, { jwt: invoke, body });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.match(JSON.stringify(ok.body), /echo: \{\\"q\\":\\"hi\\"\}/);

  assert.equal((await call(url.gateway, "POST", path, { body })).status, 401);
  await call(url.mcp, "POST", `/v1/servers/${id}/revoke`, {
    jwt: approve,
    body: {},
  });
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(
    (await call(url.gateway, "POST", path, { jwt: invoke, body })).status,
    404,
  );
});
