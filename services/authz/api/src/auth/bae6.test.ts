import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { bae6Authenticator, firstOf } from "./bae6.js";
import type { Authenticator } from "./principal.js";

const ISSUER = "https://authn.bae6.test";
const ALICE = `prn_${"a".repeat(32)}`;
let server: Server;
let authenticate: Authenticator;
let privateKey: CryptoKey;
let otherKey: CryptoKey;

before(async () => {
  const pair = await generateKeyPair("ES256");
  privateKey = pair.privateKey;
  otherKey = (await generateKeyPair("ES256")).privateKey;
  const jwk: JWK = {
    ...(await exportJWK(pair.publicKey)),
    kid: "k1",
    alg: "ES256",
  };
  server = createServer((_, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  authenticate = bae6Authenticator({
    issuer: ISSUER,
    jwksUri: `http://127.0.0.1:${port}/jwks`,
    audience: "bae6-authz",
  });
});

after(() => {
  server.close();
});

const sign = (
  claims: Record<string, unknown> = {},
  over: { typ?: string; aud?: string; iss?: string; key?: CryptoKey } = {},
) =>
  new SignJWT({
    tenant_id: "acme",
    principal_type: "user",
    ...claims,
  })
    .setProtectedHeader({
      alg: "ES256",
      kid: "k1",
      typ: over.typ ?? "bae6+jwt",
    })
    .setIssuer(over.iss ?? ISSUER)
    .setAudience(over.aud ?? "bae6-authz")
    .setSubject(ALICE)
    .setExpirationTime("5m")
    .sign(over.key ?? privateKey);

const bearer = async (...args: Parameters<typeof sign>) =>
  `Bearer ${await sign(...args)}`;

test("a bae6 token becomes a tenant principal named by its type and id", async () => {
  assert.deepEqual(await authenticate(await bearer()), {
    subject: `user:${ALICE}`,
    organization: "acme",
    scopes: ["tenant"],
    applications: [],
    issuer: ISSUER,
  });
});

test("tokens that are forged, mistyped, for another audience, delegated or malformed are refused", async () => {
  for (const authorization of [
    undefined,
    "Bearer not-a-jwt",
    await bearer({}, { key: otherKey }),
    await bearer({}, { typ: "JWT" }),
    await bearer({}, { aud: "bae6-ai" }),
    await bearer({}, { iss: "https://evil.test" }),
    await bearer({ tenant_id: "Bad Tenant" }),
    await bearer({ principal_type: "root" }),
    await bearer({ tenant_id: undefined }),
    await bearer({ act: { sub: "prn_agent" } }),
    await bearer({ delegation_id: "dlg_x" }),
  ])
    assert.equal(await authenticate(authorization), null);
});

test("the second authenticator is consulted only when the first refuses", async () => {
  const fallback: Authenticator = async () => ({
    subject: "other",
    organization: "acme",
    scopes: [],
    applications: [],
  });
  const both = firstOf(authenticate, fallback);
  assert.equal((await both(await bearer()))?.subject, `user:${ALICE}`);
  assert.equal((await both("Bearer x"))?.subject, "other");
});
