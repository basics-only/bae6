import assert from "node:assert/strict";
import { test } from "node:test";
import { ORGS, orgIssuer } from "../orgs/orgs.mjs";

const url = {
  oidc: "http://127.0.0.1:8085",
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

test("an issuer no service is configured for is refused", async () => {
  const jwt = await token("acme-unknown", "bae6-context-data", "data:read");
  assert.equal((await read("acme-unknown/handbook.txt", jwt)).status, 401);
});
