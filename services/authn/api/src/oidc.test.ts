import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createIdp, type MockIdpConfig } from "@bae6/mock-oidc/idp.mjs";
import {
  decodeJwt,
  decodeProtectedHeader,
  generateKeyPair,
  SignJWT,
} from "jose";
import { OidcError, OidcProvider, type ProviderConnection } from "./oidc.js";

const require = createRequire(import.meta.url);
const config: MockIdpConfig = JSON.parse(
  readFileSync(require.resolve("@bae6/mock-oidc/providers.json"), "utf8"),
);
const ACME = "11111111-1111-4111-8111-111111111111";
const client = config.clients[0] as MockIdpConfig["clients"][number];
let server: Server;
let base: string;
// Stands in for an on-path attacker: rewrites the ID token in the next token response.
let rewriteIdToken: ((idToken: string) => Promise<string>) | undefined;
let tokenEndpointFails = false;

before(async () => {
  let idp: Awaited<ReturnType<typeof createIdp>>;
  server = createServer(async (req, res) => {
    if (req.url?.endsWith("/token.oauth2") && tokenEndpointFails) {
      res.writeHead(503).end();
      return;
    }
    const rewrite = rewriteIdToken;
    if (req.url?.endsWith("/token.oauth2") && rewrite) {
      rewriteIdToken = undefined;
      const end = res.end.bind(res);
      res.end = ((chunk: string) => {
        const body = JSON.parse(chunk);
        void rewrite(body.id_token).then((t) =>
          end(JSON.stringify({ ...body, id_token: t })),
        );
        return res;
      }) as typeof res.end;
    }
    if (!(await idp.handle(req, res, new URL(req.url ?? "/", "http://mock")))) {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  idp = await createIdp({ baseUrl: base, config });
});
after(() => {
  server.closeAllConnections();
  return new Promise<void>((r) => server.close(() => r()));
});

const issuers = {
  entra: () => `${base}/entra/${ACME}/v2.0`,
  okta: () => `${base}/okta/oauth2/aus1bae6default`,
  ping: () => `${base}/ping/acme`,
};
const connection = (kind: keyof typeof issuers): ProviderConnection => ({
  issuer: issuers[kind](),
  clientId: client.id,
  clientSecret: client.secret,
  redirectUri: `http://localhost:8092/auth/callback/${kind}`,
});

async function browse(url: URL) {
  const res = await fetch(url, { redirect: "manual" });
  const location = res.headers.get("location");
  assert.ok(location, `expected a redirect, got ${res.status}`);
  return new URL(location).searchParams;
}

async function signIn(kind: keyof typeof issuers, loginHint?: string) {
  const provider = await OidcProvider.discover(connection(kind), {
    allowHttp: true,
  });
  const { url, pending } = await provider.beginLogin(
    loginHint ? { loginHint } : {},
  );
  return provider.completeLogin(await browse(url), pending);
}

test("a sign-in at each provider yields the ID token's issuer and subject", async () => {
  for (const kind of ["entra", "okta", "ping"] as const) {
    const { identity } = await signIn(kind);
    assert.equal(identity.issuer, issuers[kind](), kind);
    assert.ok(identity.subject, kind);
  }
  const ping = await signIn("ping");
  assert.equal(ping.identity.subject, "dave");
  assert.equal(ping.identity.claims.employeeId, "E1001");
});

test("identity comes from the ID token, never the access token", async () => {
  const { identity, providerAccessToken } = await signIn("okta");
  assert.equal(identity.subject, "00u1carol0000000000");
  assert.equal(decodeJwt(providerAccessToken).sub, "carol@acme.example");
});

test("Entra identities carry tid and oid from the ID token", async () => {
  const { identity } = await signIn("entra", "alice@acme.example");
  assert.equal(identity.claims.tid, ACME);
  assert.equal(identity.claims.oid, "a1a1a1a1-0000-4000-8000-000000000001");
});

test("a callback with another login's state, nonce or verifier is refused", async () => {
  const provider = await OidcProvider.discover(connection("ping"), {
    allowHttp: true,
  });
  for (const field of ["state", "nonce", "codeVerifier"] as const) {
    const { url, pending } = await provider.beginLogin();
    const query = await browse(url);
    const other = (await provider.beginLogin()).pending;
    await assert.rejects(
      provider.completeLogin(query, { ...pending, [field]: other[field] }),
      (e: unknown) => e instanceof OidcError && e.code === "invalid_callback",
      field,
    );
  }
});

test("a provider's error redirect is provider_denied", async () => {
  const provider = await OidcProvider.discover(connection("okta"), {
    allowHttp: true,
  });
  const { url, pending } = await provider.beginLogin({
    loginHint: "mallory@acme.example",
  });
  await assert.rejects(
    provider.completeLogin(await browse(url), pending),
    (e: unknown) => e instanceof OidcError && e.code === "provider_denied",
  );
});

test("discovery fails when the issuer is not exactly the configured one", async () => {
  await assert.rejects(
    OidcProvider.discover(
      { ...connection("ping"), issuer: `${issuers.ping()}/` },
      { allowHttp: true },
    ),
    (e: unknown) => e instanceof OidcError && e.code === "discovery_failed",
  );
});

test("plain http to a provider is refused unless allowed", async () => {
  await assert.rejects(
    OidcProvider.discover(connection("ping")),
    (e: unknown) => e instanceof OidcError && e.code === "discovery_failed",
  );
});

test("a rotated signing key is picked up once the cached JWKS is past its 60 s refetch cooldown", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const provider = await OidcProvider.discover(connection("okta"), {
    allowHttp: true,
  });
  const signIn = async () => {
    const { url, pending } = await provider.beginLogin();
    return provider.completeLogin(await browse(url), pending);
  };
  await signIn();
  assert.ok(
    (await fetch(`${issuers.okta()}/_mock/rotate`, { method: "POST" })).ok,
  );
  await assert.rejects(
    signIn(),
    (e: unknown) => e instanceof OidcError && e.code === "invalid_callback",
    "inside the cooldown an unknown kid does not trigger a refetch",
  );
  t.mock.timers.tick(61_000);
  const { identity } = await signIn();
  assert.equal(identity.subject, "00u1carol0000000000");
});

test("an ID token signed by a key the provider never published is refused", async () => {
  const provider = await OidcProvider.discover(connection("ping"), {
    allowHttp: true,
  });
  const { url, pending } = await provider.beginLogin();
  const { privateKey } = await generateKeyPair("RS256");
  rewriteIdToken = async (real) =>
    new SignJWT({ ...decodeJwt(real), sub: "attacker" })
      .setProtectedHeader(decodeProtectedHeader(real) as { alg: string })
      .sign(privateKey);
  await assert.rejects(
    provider.completeLogin(await browse(url), pending),
    (e: unknown) => e instanceof OidcError && e.code === "invalid_callback",
  );
});

test("a provider outage is provider_unavailable, not a bad callback", async () => {
  const provider = await OidcProvider.discover(connection("ping"), {
    allowHttp: true,
  });
  const { url, pending } = await provider.beginLogin();
  const query = await browse(url);
  tokenEndpointFails = true;
  try {
    await assert.rejects(
      provider.completeLogin(query, pending),
      (e: unknown) =>
        e instanceof OidcError && e.code === "provider_unavailable",
    );
  } finally {
    tokenEndpointFails = false;
  }
});

test("a wrong client secret is provider_misconfigured", async () => {
  const provider = await OidcProvider.discover(
    { ...connection("ping"), clientSecret: "not-the-secret" },
    { allowHttp: true },
  );
  const { url, pending } = await provider.beginLogin();
  await assert.rejects(
    provider.completeLogin(await browse(url), pending),
    (e: unknown) =>
      e instanceof OidcError && e.code === "provider_misconfigured",
  );
});

test("openid is always requested, even when a connection lists other scopes", async () => {
  const provider = await OidcProvider.discover(
    { ...connection("ping"), scopes: ["profile"] },
    { allowHttp: true },
  );
  const { url } = await provider.beginLogin();
  assert.deepEqual(url.searchParams.get("scope")?.split(" ").sort(), [
    "openid",
    "profile",
  ]);
});

test("an oversized or control-character login hint is refused before redirecting", async () => {
  const provider = await OidcProvider.discover(connection("ping"), {
    allowHttp: true,
  });
  for (const loginHint of ["a".repeat(257), "dave\r\nx"]) {
    await assert.rejects(
      provider.beginLogin({ loginHint }),
      (e: unknown) => e instanceof OidcError && e.code === "invalid_request",
    );
  }
});
