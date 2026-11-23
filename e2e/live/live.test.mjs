import assert from "node:assert/strict";
import { test } from "node:test";

const url = {
  oidc: "http://127.0.0.1:8085",
  otherOidc: "http://127.0.0.1:8086",
  ai: "http://127.0.0.1:8081",
  data: "http://127.0.0.1:8082",
};

async function token(sub, aud, scope, issuer = url.oidc) {
  const res = await fetch(`${issuer}/token`, {
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
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  return {
    status: res.status,
    body: text.startsWith("{") ? JSON.parse(text) : text,
  };
}

const read = (key, jwt) =>
  call(url.data, "GET", `/v1/sources/docs/objects/content?key=${key}`, {
    jwt,
  });

test("real Bedrock answers through the gateway and the call is metered", async () => {
  const ai = await token("live", "bae6-ai", "ai:invoke ai:usage:read");
  const spentBefore = Number(
    (await call(url.ai, "GET", "/v1/budgets", { jwt: ai })).body.spent,
  );
  const answer = await call(url.ai, "POST", "/v1/chat/completions", {
    jwt: ai,
    body: {
      model: "chat-live",
      messages: [{ role: "user", content: "Reply with the word ok." }],
    },
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.ok(answer.body.choices[0].message.content.length > 0);
  assert.ok(answer.body.usage.completion_tokens > 0);
  const budget = await call(url.ai, "GET", "/v1/budgets", { jwt: ai });
  assert.ok(Number(budget.body.spent) > spentBefore);
});

test("data-api reads a real S3 object inside the source prefix only", async () => {
  const data = await token("live", "bae6-context-data", "data:read");
  const object = await read("example/handbook.txt", data);
  assert.equal(object.status, 200);
  assert.match(String(object.body), /ten business days/);

  const outside = await read("other/private.txt", data);
  assert.notEqual(outside.status, 200);
  assert.doesNotMatch(JSON.stringify(outside.body), /Not part of/);
});

test("another organization cannot read the real bucket", async () => {
  const other = await token(
    "live",
    "bae6-context-data",
    "data:read",
    url.otherOidc,
  );
  assert.equal((await read("example/handbook.txt", other)).status, 404);
});
