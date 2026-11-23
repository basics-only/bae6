import assert from "node:assert/strict";
import { test } from "node:test";
import { ORGS, orgIssuer } from "../orgs/orgs.mjs";

const url = {
  oidc: "http://127.0.0.1:8085",
  ai: "http://127.0.0.1:8081",
  data: "http://127.0.0.1:8082",
};

async function token(org, aud, scope) {
  const res = await fetch(`${orgIssuer(url.oidc, org)}/token`, {
    method: "POST",
    body: JSON.stringify({ sub: "agent", aud, scope }),
  });
  assert.equal(res.status, 200);
  return (await res.json()).access_token;
}

async function call(base, method, path, jwt, body) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${jwt}`,
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

const read = (key, jwt) =>
  call(url.data, "GET", `/v1/sources/docs/objects/content?key=${key}`, jwt);

test("each of the 20 organizations reads only its own documents", async () => {
  await Promise.all(
    ORGS.map(async (org, i) => {
      const jwt = await token(org, "bae6-context-data", "data:read");
      const own = await read(`${org}/handbook.txt`, jwt);
      assert.equal(own.status, 200, org);
      assert.equal(own.body, `Handbook of ${org}.`);

      const neighbour = ORGS[(i + 1) % ORGS.length];
      const other = await read(`${neighbour}/handbook.txt`, jwt);
      assert.notEqual(other.status, 200, `${org} read ${neighbour}`);
      assert.doesNotMatch(JSON.stringify(other.body), /Handbook of/);
      assert.notEqual(
        (await read("example/handbook.txt", jwt)).status,
        200,
        `${org} read example`,
      );
    }),
  );
});

test("model spend is metered to the calling organization only", async () => {
  const [spender, bystander] = ORGS;
  const jwt = {
    spender: await token(spender, "bae6-ai", "ai:invoke ai:usage:read"),
    bystander: await token(bystander, "bae6-ai", "ai:usage:read"),
  };
  const spent = async (who) =>
    Number((await call(url.ai, "GET", "/v1/budgets", jwt[who])).body.spent);
  const before = {
    spender: await spent("spender"),
    bystander: await spent("bystander"),
  };

  const answer = await call(
    url.ai,
    "POST",
    "/v1/chat/completions",
    jwt.spender,
    {
      model: "chat-mock",
      messages: [{ role: "user", content: "hello" }],
    },
  );
  assert.equal(answer.status, 200);

  assert.ok((await spent("spender")) > before.spender);
  assert.equal(await spent("bystander"), before.bystander);
});

test("an issuer no service is configured for is refused", async () => {
  const jwt = await token("acme-unknown", "bae6-context-data", "data:read");
  assert.equal((await read("acme-unknown/handbook.txt", jwt)).status, 401);
});
