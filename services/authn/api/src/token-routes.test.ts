import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import { SESSION_TOKEN_TYPE } from "./exchange.js";
import { localSigner, type Signer, syncKeys } from "./keys.js";
import { createAuthnApi } from "./server.js";
import { createSession, revokeSession } from "./sessions.js";
import { createTokenRoutes } from "./token-routes.js";
import { verifyToken } from "./tokens.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ISSUER = "https://authn.bae6.test";
const ALICE = `prn_${"a".repeat(32)}`;
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
    `INSERT INTO principals (id, tenant_id, type, org_path)
     VALUES ($1, 'acme', 'user', '{acme,finance}')`,
    [ALICE],
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
    assert.deepEqual(claims.org_path, ["acme", "finance"]);
    assert.match(claims.session_id ?? "", /^ses_/);
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
