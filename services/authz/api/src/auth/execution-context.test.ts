import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { bae6Authenticator } from "./bae6.js";

test("execution context comes from the verified bearer token", async (t) => {
  const issuer = "https://authn.example";
  const principalId = `prn_${"a".repeat(32)}`;
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1" };
  t.mock.method(globalThis, "fetch", async () =>
    Response.json({ keys: [jwk] }),
  );
  const authenticate = bae6Authenticator({
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    audience: "bae6-authz",
    organization: "acme",
  });
  const bearer = async (claims: Record<string, unknown>, key = privateKey) =>
    `Bearer ${await new SignJWT({
      tenant_id: "acme",
      principal_type: "user",
      org_path: ["acme", "finance"],
      txn: "signed-request",
      cost_center_id: "finance",
      ...claims,
    })
      .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "bae6+jwt" })
      .setIssuer(issuer)
      .setAudience("bae6-authz")
      .setSubject(principalId)
      .setExpirationTime("5m")
      .sign(key)}`;

  assert.deepEqual((await authenticate(await bearer({})))?.executionContext, {
    tenantId: "acme",
    orgPath: ["acme", "finance"],
    principalId,
    principalType: "user",
    actorId: principalId,
    costCenterId: "finance",
  });
  for (const claims of [
    { org_path: ["other"] },
    { org_path: undefined },
    { cost_center_id: [] },
  ])
    assert.equal(await authenticate(await bearer(claims)), null);
  assert.equal(
    await authenticate(
      await bearer({}, (await generateKeyPair("ES256")).privateKey),
    ),
    null,
  );
});
