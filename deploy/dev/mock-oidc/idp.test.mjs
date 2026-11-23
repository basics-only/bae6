import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { after, before, test } from "node:test";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { createIdp, GRAPH_AUDIENCE, validateConfig } from "./idp.mjs";

const config = JSON.parse(
  readFileSync(new URL("./providers.json", import.meta.url), "utf8"),
);
const ACME = "11111111-1111-4111-8111-111111111111";
const GLOBEX = "22222222-2222-4222-8222-222222222222";
const client = config.clients[0];
const basic = `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`;
const other = { ...client, id: "other-app", secret: "dev only other" };
config.clients.push(other);
// RFC 6749 2.3.1: Basic credentials are form-encoded first, so a space travels as `+`.
const otherBasic = `Basic ${Buffer.from("other-app:dev+only+other").toString("base64")}`;
let base;
let server;

before(async () => {
  let idp;
  server = createServer(async (req, res) => {
    if (!(await idp.handle(req, res, new URL(req.url, "http://mock")))) {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
  idp = await createIdp({ baseUrl: base, config });
});
after(() => server.close());

const discoveryPath = {
  entra: (id) => `/entra/${id}/v2.0`,
  okta: (id) => `/okta/oauth2/${id}`,
  ping: (id) => `/ping/${id}`,
};
const meta = async (kind, id) =>
  (
    await fetch(
      `${base}${discoveryPath[kind](id)}/.well-known/openid-configuration`,
    )
  ).json();

async function authorize(kind, id, overrides = {}) {
  const d = await meta(kind, id);
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({
    response_type: "code",
    client_id: client.id,
    redirect_uri: `http://localhost:8092/auth/callback/${kind}`,
    scope: "openid profile",
    state: "st-1",
    nonce: "n-1",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    ...overrides,
  });
  for (const [k, v] of Object.entries(overrides))
    if (v === undefined) q.delete(k);
  const res = await fetch(`${d.authorization_endpoint}?${q}`, {
    redirect: "manual",
  });
  return {
    d,
    res,
    verifier,
    location:
      res.headers.get("location") && new URL(res.headers.get("location")),
  };
}

const exchange = (d, form, auth = basic) =>
  fetch(d.token_endpoint, {
    method: "POST",
    headers: {
      authorization: auth,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(form),
  });

async function login(kind, id, overrides) {
  const { d, verifier, location } = await authorize(kind, id, overrides);
  const res = await exchange(d, {
    grant_type: "authorization_code",
    code: location.searchParams.get("code"),
    redirect_uri: `http://localhost:8092/auth/callback/${kind}`,
    code_verifier: verifier,
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  const keys = createRemoteJWKSet(new URL(d.jwks_uri));
  const { payload } = await jwtVerify(body.id_token, keys, {
    issuer: d.issuer,
    audience: client.id,
  });
  return { d, body, id: payload, access: decodeJwt(body.access_token) };
}

test("Entra ID tokens carry tid and oid, with a pairwise sub distinct from oid", async () => {
  const { id, d } = await login("entra", ACME, {
    login_hint: "alice@acme.example",
  });
  assert.equal(d.issuer, `${base}/entra/${ACME}/v2.0`);
  assert.equal(id.tid, ACME);
  assert.equal(id.oid, "a1a1a1a1-0000-4000-8000-000000000001");
  assert.notEqual(id.sub, id.oid);
  assert.equal(id.nonce, "n-1");
  assert.deepEqual(id.groups.length, 2);
});

test("Entra access tokens from sign-in are for Graph, not for the app", async () => {
  const { access } = await login("entra", ACME, {
    login_hint: "alice@acme.example",
  });
  assert.equal(access.aud, GRAPH_AUDIENCE);
});

test("Entra replaces groups with a Graph pointer past the overage limit, and Graph returns them", async () => {
  const { id, d } = await login("entra", ACME, {
    login_hint: "bob@acme.example",
  });
  assert.equal(id.groups, undefined);
  assert.deepEqual(id._claim_names, { groups: "src1" });
  const graphToken = (
    await (
      await exchange(d, {
        grant_type: "client_credentials",
        scope: `${GRAPH_AUDIENCE}/.default`,
      })
    ).json()
  ).access_token;
  const res = await fetch(
    `${base}/entra/graph/v1.0/users/${id.oid}/getMemberObjects`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${graphToken}` },
      body: JSON.stringify({ securityEnabledOnly: false }),
    },
  );
  assert.equal(res.status, 200);
  assert.equal((await res.json()).value.length, 6);
});

test("Graph will not show one Entra tenant's users to another tenant's token", async () => {
  const d = await meta("entra", GLOBEX);
  const other = (
    await (
      await exchange(d, {
        grant_type: "client_credentials",
        scope: `${GRAPH_AUDIENCE}/.default`,
      })
    ).json()
  ).access_token;
  const res = await fetch(
    `${base}/entra/graph/v1.0/users/b2b2b2b2-0000-4000-8000-000000000002/getMemberObjects`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${other}` },
    },
  );
  assert.equal(res.status, 404);
  const anon = await fetch(
    `${base}/entra/graph/v1.0/users/b2b2b2b2-0000-4000-8000-000000000002/getMemberObjects`,
    {
      method: "POST",
    },
  );
  assert.equal(anon.status, 401);
});

test("each Entra tenant is its own issuer with its own keys", async () => {
  const acme = await meta("entra", ACME);
  const globex = await meta("entra", GLOBEX);
  assert.notEqual(acme.issuer, globex.issuer);
  const { body } = await login("entra", GLOBEX);
  await assert.rejects(
    jwtVerify(body.id_token, createRemoteJWKSet(new URL(acme.jwks_uri))),
  );
});

test("an Okta custom authorization server issues access tokens whose sub is the login, not the user ID", async () => {
  const { id, access, d } = await login("okta", "aus1bae6default");
  assert.equal(d.issuer, `${base}/okta/oauth2/aus1bae6default`);
  assert.equal(id.sub, "00u1carol0000000000");
  assert.equal(access.aud, "api://bae6");
  assert.equal(access.sub, "carol@acme.example");
  assert.equal(access.uid, id.sub);
  assert.deepEqual(access.scp, ["openid", "profile"]);
});

test("Ping ID tokens carry the configured custom claims", async () => {
  const { id, access, d } = await login("ping", "acme");
  assert.ok(
    new URL(d.authorization_endpoint).pathname.endsWith(
      "/as/authorization.oauth2",
    ),
  );
  assert.equal(id.employeeId, "E1001");
  assert.deepEqual(id.memberOf, ["CN=Finance,OU=Groups,DC=acme,DC=example"]);
  assert.equal(access.aud, "bae6");
});

test("a code works once, only with its verifier and redirect URI", async () => {
  const kind = "ping";
  const redirect_uri = "http://localhost:8092/auth/callback/ping";
  const a = await authorize(kind, "acme");
  const code = a.location.searchParams.get("code");
  assert.equal(a.location.searchParams.get("state"), "st-1");
  const wrongVerifier = await exchange(a.d, {
    grant_type: "authorization_code",
    code,
    redirect_uri,
    code_verifier: "x".repeat(43),
  });
  assert.equal(wrongVerifier.status, 400);
  const replay = await exchange(a.d, {
    grant_type: "authorization_code",
    code,
    redirect_uri,
    code_verifier: a.verifier,
  });
  assert.equal(replay.status, 400, "a failed attempt still burns the code");
  const b = await authorize(kind, "acme");
  const wrongRedirect = await exchange(b.d, {
    grant_type: "authorization_code",
    code: b.location.searchParams.get("code"),
    redirect_uri: "http://localhost:8092/auth/callback/okta",
    code_verifier: b.verifier,
  });
  assert.equal(wrongRedirect.status, 400);
});

test("a code from one realm is refused at another realm's token endpoint", async () => {
  const a = await authorize("entra", ACME);
  const globex = await meta("entra", GLOBEX);
  const res = await exchange(globex, {
    grant_type: "authorization_code",
    code: a.location.searchParams.get("code"),
    redirect_uri: "http://localhost:8092/auth/callback/entra",
    code_verifier: a.verifier,
  });
  assert.equal(res.status, 400);
});

test("an unregistered redirect URI gets an error page, never a redirect", async () => {
  const { res } = await authorize("okta", "aus1bae6default", {
    redirect_uri: "https://evil.example/cb",
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("location"), null);
});

test("authorize refuses requests without PKCE, state or openid", async () => {
  for (const o of [
    { code_challenge: undefined },
    { code_challenge_method: "plain" },
    { state: undefined },
    { scope: "profile" },
  ]) {
    const { location } = await authorize("okta", "aus1bae6default", o);
    assert.equal(
      location.searchParams.get("error"),
      "invalid_request",
      JSON.stringify(o),
    );
  }
});

test("an unknown login is denied", async () => {
  const { location } = await authorize("okta", "aus1bae6default", {
    login_hint: "mallory@acme.example",
  });
  assert.equal(location.searchParams.get("error"), "access_denied");
  assert.equal(location.searchParams.get("code"), null);
});

test("a wrong client secret is invalid_client", async () => {
  const d = await meta("okta", "aus1bae6default");
  const res = await exchange(
    d,
    { grant_type: "client_credentials" },
    `Basic ${Buffer.from(`${client.id}:wrong-secret`).toString("base64")}`,
  );
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, "invalid_client");
});

test("after a rotation both keys are published; after a second the oldest is gone", async () => {
  const d = await meta("okta", "aus1bae6default");
  const { body } = await login("okta", "aus1bae6default");
  const rotate = () =>
    fetch(`${base}/okta/oauth2/aus1bae6default/_mock/rotate`, {
      method: "POST",
    }).then((r) => r.json());
  const verify = () =>
    jwtVerify(
      body.id_token,
      createRemoteJWKSet(new URL(d.jwks_uri), {
        cacheMaxAge: 0,
        cooldownDuration: 0,
      }),
    );
  const first = await rotate();
  assert.equal(first.published.length, 2);
  await verify();
  const fresh = await login("okta", "aus1bae6default");
  assert.equal(
    fresh.body.id_token.split(".")[0],
    Buffer.from(
      JSON.stringify({ alg: "RS256", kid: first.kid, typ: "JWT" }),
    ).toString("base64url"),
  );
  await rotate();
  await assert.rejects(verify());
});

test("user claims cannot override what the mock sets", () => {
  const bad = structuredClone(config);
  bad.realms[3].users[0].claims.aud = "someone-else";
  assert.throws(() => validateConfig(bad), /claim aud is set by the mock/);
});

test("a user without a claims object is rejected at load, not at sign-in", () => {
  const bad = structuredClone(config);
  delete bad.realms[3].users[0].claims;
  assert.throws(() => validateConfig(bad), /claims must be an object/);
});

test("Entra gives the same user a different sub at each client; others do not", async () => {
  const subAt = async (kind, id, as, auth) => {
    const a = await authorize(kind, id, { client_id: as });
    const res = await exchange(
      a.d,
      {
        grant_type: "authorization_code",
        code: a.location.searchParams.get("code"),
        redirect_uri: `http://localhost:8092/auth/callback/${kind}`,
        code_verifier: a.verifier,
      },
      auth,
    );
    assert.equal(res.status, 200);
    return decodeJwt((await res.json()).id_token).sub;
  };
  assert.notEqual(
    await subAt("entra", ACME, client.id, basic),
    await subAt("entra", ACME, other.id, otherBasic),
  );
  assert.equal(
    await subAt("ping", "acme", client.id, basic),
    await subAt("ping", "acme", other.id, otherBasic),
  );
});
