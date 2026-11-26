import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import { SESSION_TOKEN_TYPE, WORKLOAD_TOKEN_TYPE } from "./exchange.js";
import { localSigner, type Signer, syncKeys } from "./keys.js";
import { setPrincipalOrgPath } from "./principals.js";
import { createAuthnApi } from "./server.js";
import { createSession, revokeSession } from "./sessions.js";
import { createTokenRoutes } from "./token-routes.js";
import { verifyToken } from "./tokens.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ISSUER = "https://authn.bae6.test";
const ALICE = `prn_${"a".repeat(32)}`;
const WORKER = `prn_${"e".repeat(32)}`;
const PING = "https://ping.example/acme";
const GATEWAY_SECRET = "g".repeat(40);
const CONSOLE_SECRET = "c".repeat(40);
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT = "urn:ietf:params:oauth:token-type:jwt";
let db: pg.Pool;
let close: () => Promise<void>;
let server: ReturnType<typeof createAuthnApi>;
let base: string;

const p256 = () =>
  localSigner(
    generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString(),
  );
const keyA = p256();
const keyB = p256();
const signers = new Map<string, Signer>([[keyA.kid, keyA]]);
const idpKey = await generateKeyPair("ES256");
const strangerKey = await generateKeyPair("ES256");
const idpKeys = createLocalJWKSet({
  keys: [{ ...(await exportJWK(idpKey.publicKey)), alg: "ES256" }],
});
let providerDown = false;

const providerToken = (
  claims: { iss?: string; sub?: string; aud?: string; exp?: number } = {},
  key = idpKey.privateKey,
) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer(claims.iss ?? PING)
    .setSubject(claims.sub ?? "embed-worker")
    .setAudience(claims.aud ?? "c")
    .setIssuedAt()
    .setExpirationTime(claims.exp ?? Math.floor(Date.now() / 1000) + 600)
    .sign(key);

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_tokr",
  ));
  await db.query(
    `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
     VALUES ('acme', 'ping', 'pingfederate', 'https://ping.example/acme', 'c', 's')`,
  );
  await db.query(
    `INSERT INTO principals (id, tenant_id, type, owner_application_id, org_path)
     VALUES ($1, 'acme', 'user', null, '{acme,finance}'),
            ($2, 'acme', 'service', 'demo', '{acme,platform}')`,
    [ALICE, WORKER],
  );
  await db.query(
    `INSERT INTO external_identities
       (id, tenant_id, principal_id, provider_connection_id, issuer, subject, last_verified_at)
     VALUES ($1, 'acme', $3, 'ping', $5, 'alice', now()),
            ($2, 'acme', $4, 'ping', $5, 'embed-worker', now())`,
    [`xid_${"1".repeat(32)}`, `xid_${"2".repeat(32)}`, ALICE, WORKER, PING],
  );
  server = createAuthnApi({
    ping: async () => {},
    requestTimeoutMs: 5000,
    routes: createTokenRoutes({
      db,
      signers,
      issuer: ISSUER,
      audiences: new Set(["gateway", "data-api"]),
      reexchangeTargets: new Map([["gateway", new Set(["data-api"])]]),
      sessionClients: ["console"],
      clientSecret: async (client) =>
        ({ gateway: GATEWAY_SECRET, console: CONSOLE_SECRET })[client],
      workloadKeys: async () => {
        if (providerDown) throw new TypeError("fetch failed");
        return idpKeys;
      },
    }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (skip) return;
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await close();
});

const session = async () =>
  (
    await createSession(db, {
      tenantId: "acme",
      principalId: ALICE,
      connectionId: "ping",
      ttlSeconds: 3600,
    })
  ).cookie;

const post = (
  fields: Record<string, string>,
  headers: Record<string, string> = {},
) =>
  fetch(`${base}/auth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams({ grant_type: EXCHANGE, ...fields }),
  });

const fromSession = (
  cookie: string,
  audience = "gateway",
  secret = CONSOLE_SECRET,
) =>
  post(
    {
      subject_token: cookie,
      subject_token_type: SESSION_TOKEN_TYPE,
      audience,
    },
    { "x-request-id": "req-42", authorization: `Bearer ${secret}` },
  );

const oauthError = async (res: Response, status: number, error: string) => {
  assert.equal(res.status, status);
  assert.deepEqual(await res.json(), { error });
};

test(
  "a fresh install activates its first key and publishes it with a bounded cache lifetime",
  { skip },
  async () => {
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
    });
    const res = await fetch(`${base}/.well-known/jwks.json`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "public, max-age=300");
    const { keys } = await res.json();
    assert.deepEqual(
      keys.map((k: Record<string, unknown>) => [k.kid, k.alg, "d" in k]),
      [[keyA.kid, "ES256", false]],
    );
  },
);

test(
  "a session becomes a bae6 token for an allowed audience",
  { skip },
  async () => {
    const res = await fromSession(await session());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    const body = await res.json();
    assert.equal(body.token_type, "Bearer");
    assert.ok(body.expires_in > 0 && body.expires_in <= 300);
    const claims = await verifyToken(db, body.access_token, {
      issuer: ISSUER,
      audience: "gateway",
    });
    assert.equal(claims.sub, ALICE);
    assert.equal(claims.txn, "req-42");
    assert.equal(claims.principal_type, "user");
    assert.equal(claims.application_id, "console");
    assert.deepEqual(claims.org_path, ["acme", "finance"]);
    assert.match(claims.session_id ?? "", /^ses_/);
  },
);

test(
  "a principal moved to another org unit gets the new org_path on its next session exchange",
  { skip },
  async () => {
    const cookie = await session();
    const claimsOf = async (res: Response) =>
      verifyToken(db, (await res.json()).access_token, {
        issuer: ISSUER,
        audience: "gateway",
      });
    const before = await claimsOf(await fromSession(cookie));
    const move = (orgPath: string[]) =>
      setPrincipalOrgPath(db, {
        tenantId: "acme",
        principalId: ALICE,
        principalType: "user",
        orgPath,
        actor: "authz",
      });
    await move(["acme", "legal"]);
    try {
      assert.deepEqual(before.org_path, ["acme", "finance"]);
      assert.deepEqual((await claimsOf(await fromSession(cookie))).org_path, [
        "acme",
        "legal",
      ]);
    } finally {
      await move(["acme", "finance"]);
    }
  },
);

test(
  "session exchange refuses revoked sessions, unknown audiences, actors and malformed requests",
  { skip },
  async () => {
    const cookie = await session();
    await oauthError(await fromSession(cookie, "evil"), 400, "invalid_target");
    await oauthError(
      await post(
        {
          subject_token: cookie,
          subject_token_type: SESSION_TOKEN_TYPE,
          audience: "gateway",
          actor_token: "x",
          actor_token_type: JWT,
        },
        { authorization: `Bearer ${CONSOLE_SECRET}` },
      ),
      400,
      "invalid_request",
    );
    for (const secret of [GATEWAY_SECRET, "x".repeat(40)])
      await oauthError(
        await fromSession(cookie, "gateway", secret),
        401,
        "invalid_client",
      );
    await oauthError(
      await fromSession(`${cookie.split(".")[0]}.${"A".repeat(43)}`),
      400,
      "invalid_request",
    );
    const json = await fetch(`${base}/auth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    await oauthError(json, 400, "invalid_request");
    await oauthError(
      await post({ subject_token: "x".repeat(21_000) }),
      400,
      "invalid_request",
    );
    await revokeSession(db, cookie.split(".")[0] as string);
    await oauthError(await fromSession(cookie), 400, "invalid_request");
  },
);

test(
  "re-exchange requires the secret of the service the subject token was issued to",
  { skip },
  async () => {
    const forGateway = (await (await fromSession(await session())).json())
      .access_token;
    const forDataApi = (
      await (await fromSession(await session(), "data-api")).json()
    ).access_token;
    const reExchange = (token: string, headers: Record<string, string>) =>
      post(
        { subject_token: token, subject_token_type: JWT, audience: "data-api" },
        headers,
      );

    const missing = await reExchange(forGateway, {});
    assert.equal(missing.headers.get("www-authenticate"), "Bearer");
    await oauthError(missing, 401, "invalid_client");
    await oauthError(
      await reExchange(forGateway, {
        authorization: `Bearer ${"x".repeat(40)}`,
      }),
      401,
      "invalid_client",
    );
    await oauthError(
      await reExchange(forDataApi, {
        authorization: `Bearer ${GATEWAY_SECRET}`,
      }),
      401,
      "invalid_client",
    );
    await oauthError(
      await reExchange("not-a-jwt", {
        authorization: `Bearer ${GATEWAY_SECRET}`,
      }),
      400,
      "invalid_request",
    );

    const ok = await reExchange(forGateway, {
      authorization: `Bearer ${GATEWAY_SECRET}`,
    });
    assert.equal(ok.status, 200);
    const claims = await verifyToken(db, (await ok.json()).access_token, {
      issuer: ISSUER,
      audience: "data-api",
    });
    assert.equal(claims.sub, ALICE);

    await db.query(
      "UPDATE provider_connections SET status = 'disabled' WHERE id = 'ping'",
    );
    try {
      await oauthError(
        await reExchange(forGateway, {
          authorization: `Bearer ${GATEWAY_SECRET}`,
        }),
        400,
        "invalid_request",
      );
    } finally {
      await db.query(
        "UPDATE provider_connections SET status = 'active' WHERE id = 'ping'",
      );
    }
  },
);

const fromWorkload = async (
  token: string | Promise<string>,
  audience = "gateway",
) =>
  post(
    {
      subject_token: await token,
      subject_token_type: WORKLOAD_TOKEN_TYPE,
      audience,
    },
    { "x-request-id": "req-43" },
  );

test(
  "a workload's provider token becomes a service token naming its application",
  { skip },
  async () => {
    const exp = Math.floor(Date.now() / 1000) + 120;
    const res = await fromWorkload(providerToken({ exp }));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.expires_in > 0 && body.expires_in <= 120);
    const claims = await verifyToken(db, body.access_token, {
      issuer: ISSUER,
      audience: "gateway",
    });
    assert.equal(claims.sub, WORKER);
    assert.equal(claims.principal_type, "service");
    assert.equal(claims.tenant_id, "acme");
    assert.equal(claims.application_id, "demo");
    assert.equal(claims.txn, "req-43");
    assert.deepEqual(claims.org_path, ["acme", "platform"]);
    assert.equal(claims.session_id, undefined);
  },
);

test(
  "workload exchange refuses users, strangers, other audiences, forged or expired tokens and disabled services",
  { skip },
  async () => {
    const now = Math.floor(Date.now() / 1000);
    for (const token of [
      providerToken({ sub: "alice" }),
      providerToken({ sub: "nobody" }),
      providerToken({ aud: "gateway" }),
      providerToken({}, strangerKey.privateKey),
      providerToken({ exp: now - 120 }),
      "not-a-jwt",
    ])
      await oauthError(await fromWorkload(token), 400, "invalid_request");
    await oauthError(
      await fromWorkload(providerToken(), "evil"),
      400,
      "invalid_target",
    );
    await db.query("UPDATE principals SET status = 'disabled' WHERE id = $1", [
      WORKER,
    ]);
    try {
      await oauthError(
        await fromWorkload(providerToken()),
        400,
        "invalid_request",
      );
    } finally {
      await db.query("UPDATE principals SET status = 'active' WHERE id = $1", [
        WORKER,
      ]);
    }
  },
);

test(
  "workload exchange refuses a disabled connection, an identity from another issuer and a subject two tenants claim",
  { skip },
  async () => {
    const drifter = "https://elsewhere.example/acme";
    await db.query(
      `INSERT INTO external_identities
         (id, tenant_id, principal_id, provider_connection_id, issuer, subject, last_verified_at)
       VALUES ($1, 'acme', $2, 'ping', $3, 'drifter', now())`,
      [`xid_${"3".repeat(32)}`, WORKER, drifter],
    );
    await oauthError(
      await fromWorkload(providerToken({ iss: drifter, sub: "drifter" })),
      400,
      "invalid_request",
    );

    await db.query(
      "UPDATE provider_connections SET status = 'disabled' WHERE id = 'ping'",
    );
    try {
      await oauthError(
        await fromWorkload(providerToken()),
        400,
        "invalid_request",
      );
    } finally {
      await db.query(
        "UPDATE provider_connections SET status = 'active' WHERE id = 'ping'",
      );
    }

    const twin = `prn_${"f".repeat(32)}`;
    await db.query(
      `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
       VALUES ('globex', 'ping', 'pingfederate', $1, 'c', 's')`,
      [PING],
    );
    await db.query(
      `INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'globex', 'service')`,
      [twin],
    );
    await db.query(
      `INSERT INTO external_identities
         (id, tenant_id, principal_id, provider_connection_id, issuer, subject, last_verified_at)
       VALUES ($1, 'globex', $2, 'ping', $3, 'embed-worker', now())`,
      [`xid_${"4".repeat(32)}`, twin, PING],
    );
    try {
      await oauthError(
        await fromWorkload(providerToken()),
        400,
        "invalid_request",
      );
    } finally {
      await db.query(
        "DELETE FROM external_identities WHERE tenant_id = 'globex'",
      );
      await db.query("DELETE FROM principals WHERE tenant_id = 'globex'");
      await db.query(
        "DELETE FROM provider_connections WHERE tenant_id = 'globex'",
      );
    }
    assert.equal((await fromWorkload(providerToken())).status, 200);
  },
);

test(
  "workload exchange answers 503 when the provider's keys cannot be fetched",
  { skip },
  async () => {
    providerDown = true;
    try {
      const res = await fromWorkload(providerToken());
      assert.equal(res.status, 503);
    } finally {
      providerDown = false;
    }
  },
);

test(
  "a new key is published as next and signs only once named active after the overlap",
  { skip },
  async () => {
    signers.set(keyB.kid, keyB);
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
      [keyB.kid]: "next",
    });
    await db.query(
      "UPDATE signing_keys SET created_at = now() - interval '1 hour' WHERE kid = $1",
      [keyB.kid],
    );
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
      [keyB.kid]: "next",
    });
    assert.deepEqual(await syncKeys(db, signers, keyB.kid), {
      [keyA.kid]: "retired",
      [keyB.kid]: "active",
    });
    const { keys } = await (
      await fetch(`${base}/.well-known/jwks.json`)
    ).json();
    assert.deepEqual(
      keys.map((k: { kid: string }) => k.kid),
      [keyB.kid, keyA.kid],
    );
  },
);
