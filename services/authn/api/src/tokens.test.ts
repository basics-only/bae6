import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { after, before, test } from "node:test";
import { calculateJwkThumbprint, SignJWT } from "jose";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import {
  exchangeToken,
  OAuthError,
  parseExchangeRequest,
  parseTokenTargets,
} from "./exchange.js";
import {
  KeyError,
  localSigner,
  promoteNextKey,
  publishedKeys,
  registerKey,
  type Signer,
} from "./keys.js";
import {
  type MintInput,
  mintToken,
  TOKEN_TYPE,
  verifyToken,
} from "./tokens.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ISSUER = "https://authn.bae6.test";
const ALICE = `prn_${"a".repeat(32)}`;
const AGENT = `prn_${"b".repeat(32)}`;
const LEAVER = `prn_${"c".repeat(32)}`;
const LIVE_SESSION = `ses_${"1".repeat(32)}`;
const REVOKED_SESSION = `ses_${"2".repeat(32)}`;
let db: pg.Pool;
let close: () => Promise<void>;

const pem = (spec: "P-256" | "P-384" | "ed25519" | "rsa"): string => {
  const { privateKey } =
    spec === "ed25519"
      ? generateKeyPairSync("ed25519")
      : spec === "rsa"
        ? generateKeyPairSync("rsa", { modulusLength: 2048 })
        : generateKeyPairSync("ec", { namedCurve: spec });
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
};

const parts = (token: string) => {
  const [h = "", p = "", s = ""] = token.split(".");
  return [h, p, s] as const;
};
const headerOf = (token: string) =>
  JSON.parse(Buffer.from(parts(token)[0], "base64url").toString());

const keyA = localSigner(pem("P-256"));
const keyB = localSigner(pem("ed25519"));
const signers = new Map<string, Signer>([
  [keyA.kid, keyA],
  [keyB.kid, keyB],
]);

const backdate = (kid: string, column: "created_at" | "retired_at") =>
  db.query(
    `UPDATE signing_keys SET ${column} = now() - interval '1 hour' WHERE kid = $1`,
    [kid],
  );

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_tok",
  ));
  await db.query(
    `INSERT INTO principals (id, tenant_id, type, owner_application_id, org_path)
     VALUES ($1, 'acme', 'user', null, '{acme,finance}'),
            ($2, 'acme', 'agent', 'helper', null),
            ($3, 'acme', 'user', null, null)`,
    [ALICE, AGENT, LEAVER],
  );
  await db.query(
    `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
     VALUES ('acme', 'ping', 'pingfederate', 'https://ping.example/acme', 'c', 's')`,
  );
  await db.query(
    `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash, provider_connection_id, expires_at, revoked_at)
     VALUES ($1, 'acme', $3, $4, $4, 'ping', now() + interval '1 hour', null),
            ($2, 'acme', $3, $4, $4, 'ping', now() + interval '1 hour', now())`,
    [LIVE_SESSION, REVOKED_SESSION, ALICE, Buffer.alloc(32)],
  );
  await registerKey(db, keyA);
  await backdate(keyA.kid, "created_at");
  await promoteNextKey(db, signers);
});

after(async () => {
  if (!skip) await close?.();
});

const base: MintInput = {
  aud: "gateway",
  sub: ALICE,
  txn: "req-1",
  tenant_id: "acme",
  org_path: ["acme", "finance"],
  principal_type: "user",
};
const mint = (input: Partial<MintInput> = {}) =>
  mintToken(db, signers, ISSUER, { ...base, ...input });

const rejects = (p: Promise<unknown>) =>
  assert.rejects(p, { message: /token|claim|lifetime|audiences/ });

const forge = (
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
) => {
  const now = Math.floor(Date.now() / 1000);
  const body = {
    ...base,
    iss: ISSUER,
    iat: now,
    exp: now + 60,
    jti: "abcdefghijklmnopqr",
    ...claims,
  };
  const signingInput = `${Buffer.from(JSON.stringify({ alg: keyA.alg, kid: keyA.kid, typ: TOKEN_TYPE, ...header })).toString("base64url")}.${Buffer.from(JSON.stringify(body)).toString("base64url")}`;
  return keyA
    .sign(Buffer.from(signingInput))
    .then((sig) => `${signingInput}.${Buffer.from(sig).toString("base64url")}`);
};

test("the key ID is the RFC 7638 thumbprint and only P-256 or Ed25519 keys sign", async () => {
  assert.equal(keyA.kid, await calculateJwkThumbprint(keyA.publicJwk));
  assert.equal(keyB.kid, await calculateJwkThumbprint(keyB.publicJwk));
  assert.equal("d" in keyA.publicJwk, false);
  assert.throws(() => localSigner(pem("rsa")), KeyError);
  assert.throws(() => localSigner(pem("P-384")), KeyError);
});

test(
  "a minted token verifies for its one audience and lasts at most five minutes",
  { skip },
  async () => {
    const { token, expiresIn } = await mint();
    assert.ok(expiresIn <= 300 && expiresIn > 290);
    assert.deepEqual(headerOf(token), {
      alg: "ES256",
      kid: keyA.kid,
      typ: TOKEN_TYPE,
    });
    const claims = await verifyToken(db, token, {
      issuer: ISSUER,
      audience: "gateway",
    });
    assert.equal(claims.sub, ALICE);
    assert.equal(claims.exp - claims.iat, expiresIn);
    await rejects(
      verifyToken(db, token, { issuer: ISSUER, audience: "data-api" }),
    );
    await rejects(
      verifyToken(db, token, {
        issuer: "https://other.test",
        audience: "gateway",
      }),
    );
  },
);

test("minting refuses claims outside the contract", { skip }, async () => {
  for (const bad of [
    { sub: "alice" },
    { org_path: ["globex"] },
    { org_path: [] },
    { delegation_id: `dlg_${"0".repeat(32)}` },
    { act: { sub: ALICE, extra: 1 } as never },
    { surprise: true } as never,
  ])
    await assert.rejects(mint(bad), { message: /invalid claim/ });
  await assert.rejects(mint({ notAfter: Math.floor(Date.now() / 1000) }), {
    message: /expired/,
  });
});

test(
  "a stored org path is a flat list of slugs rooted at the tenant",
  { skip },
  async () => {
    for (const path of [
      "{acme,NULL,x}",
      "{{acme},{x}}",
      "{globex}",
      "{acme,Bad}",
      '{acme,"fin,ops"}',
      "{NULL,acme}",
      "{}",
    ])
      await assert.rejects(
        db.query("UPDATE principals SET org_path = $1 WHERE id = $2", [
          path,
          ALICE,
        ]),
        { code: /^23/ },
      );
  },
);

test(
  "forged, tampered and out-of-contract tokens are refused",
  { skip },
  async () => {
    const opts = { issuer: ISSUER, audience: "gateway" };
    const { token } = await mint();
    const [h, p, s] = parts(token);
    const tampered = JSON.parse(Buffer.from(p, "base64url").toString());
    tampered.sub = LEAVER;
    await rejects(
      verifyToken(
        db,
        `${h}.${Buffer.from(JSON.stringify(tampered)).toString("base64url")}.${s}`,
        opts,
      ),
    );

    const stranger = localSigner(pem("P-256"));
    const strangerInput = `${Buffer.from(JSON.stringify({ alg: "ES256", kid: keyA.kid, typ: TOKEN_TYPE })).toString("base64url")}.${p}`;
    const strangerSig = Buffer.from(
      await stranger.sign(Buffer.from(strangerInput)),
    ).toString("base64url");
    await rejects(verifyToken(db, `${strangerInput}.${strangerSig}`, opts));

    const hs = await new SignJWT({ ...base })
      .setProtectedHeader({ alg: "HS256", kid: keyA.kid, typ: TOKEN_TYPE })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime("1m")
      .setJti("abcdefghijklmnopqr")
      .sign(new TextEncoder().encode(JSON.stringify(keyA.publicJwk)));
    await rejects(verifyToken(db, hs, opts));
    await rejects(
      verifyToken(
        db,
        `${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.`,
        opts,
      ),
    );

    const now = Math.floor(Date.now() / 1000);
    for (const [claims, header] of [
      [{ exp: now + 600 }, {}],
      [{ iat: now - 400, exp: now - 100 }, {}],
      [{ aud: ["gateway", "data-api"] }, {}],
      [{ scope: "admin" }, {}],
      [{ org_path: ["globex"] }, {}],
      [{}, { typ: "JWT" }],
      [{}, { kid: "unknown-kid" }],
    ] as const)
      await rejects(verifyToken(db, await forge(claims, header), opts));
    assert.ok(await verifyToken(db, await forge({}), opts));
  },
);

const deps = () => ({
  db,
  signers,
  issuer: ISSUER,
  audiences: new Set(["gateway", "data-api"]),
  reexchangeTargets: new Map([["gateway", new Set(["data-api"])]]),
});

const form = (fields: Record<string, string>) =>
  parseExchangeRequest(
    new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
      audience: "data-api",
      ...fields,
    }),
  );

const oauthError = (p: Promise<unknown> | (() => unknown), error: string) =>
  typeof p === "function"
    ? assert.throws(
        p,
        (e: unknown) => e instanceof OAuthError && e.error === error,
      )
    : assert.rejects(
        p,
        (e: unknown) => e instanceof OAuthError && e.error === error,
      );

test("exchange requests outside RFC 8693 or the contract are refused", () => {
  const grant = "urn:ietf:params:oauth:grant-type:token-exchange";
  const jwt = "urn:ietf:params:oauth:token-type:jwt";
  oauthError(
    () => parseExchangeRequest(new URLSearchParams({ grant_type: "password" })),
    "unsupported_grant_type",
  );
  oauthError(
    () => parseExchangeRequest(new URLSearchParams()),
    "invalid_request",
  );
  oauthError(
    () =>
      parseExchangeRequest(
        new URLSearchParams([
          ["grant_type", grant],
          ["subject_token", "a"],
          ["subject_token", "b"],
          ["subject_token_type", jwt],
          ["audience", "x"],
        ]),
      ),
    "invalid_request",
  );
  for (const extra of [
    { client_secret: "x" },
    { actor_token: "x" },
    { actor_token_type: jwt },
    { delegation_id: `dlg_${"0".repeat(32)}` },
    { requested_token_type: "urn:ietf:params:oauth:token-type:saml2" },
    { subject_token: "x".repeat(8193) },
    { subject_token_type: "urn:ietf:params:oauth:token-type:id_token" },
  ])
    oauthError(() => form({ subject_token: "t", ...extra }), "invalid_request");
  assert.equal(form({ subject_token: "t" }).audience, "data-api");
});

test("re-exchange targets accept only other known audiences, each caller once", () => {
  const audiences = new Set(["gateway", "data-api", "embed-api"]);
  assert.deepEqual(
    parseTokenTargets(
      " gateway = data-api | embed-api , data-api=embed-api",
      audiences,
    ),
    new Map([
      ["gateway", new Set(["data-api", "embed-api"])],
      ["data-api", new Set(["embed-api"])],
    ]),
  );
  assert.deepEqual(parseTokenTargets("", audiences), new Map());
  for (const bad of [
    "gateway",
    "gateway=",
    "gateway=data-api|",
    "gateway=gateway",
    "gateway=evil",
    "evil=data-api",
    "gateway=data-api=embed-api",
    "gateway=data-api,gateway=embed-api",
  ])
    assert.throws(
      () => parseTokenTargets(bad, audiences),
      /TOKEN_TARGETS/,
      bad,
    );
});

test(
  "re-exchange moves a token to a new audience without widening it",
  { skip },
  async () => {
    const subject = await mint({
      act: { sub: AGENT },
      session_id: LIVE_SESSION,
      notAfter: Math.floor(Date.now() / 1000) + 120,
    });
    const out = await exchangeToken(
      deps(),
      { audience: "gateway" },
      form({ subject_token: subject.token }),
    );
    assert.equal(out.token_type, "Bearer");
    assert.ok(out.expires_in <= subject.expiresIn);
    const before = await verifyToken(db, subject.token, {
      issuer: ISSUER,
      audience: "gateway",
    });
    const after = await verifyToken(db, out.access_token, {
      issuer: ISSUER,
      audience: "data-api",
    });
    for (const claim of [
      "sub",
      "txn",
      "tenant_id",
      "org_path",
      "principal_type",
      "act",
      "session_id",
    ] as const)
      assert.deepEqual(after[claim], before[claim]);
    assert.ok(after.exp <= before.exp);
    assert.notEqual(after.jti, before.jti);
  },
);

test(
  "re-exchange binds the subject token to the calling service and the audience allowlist",
  { skip },
  async () => {
    const { token } = await mint();
    await oauthError(
      exchangeToken(
        deps(),
        { audience: "data-api" },
        form({ subject_token: token }),
      ),
      "invalid_request",
    );
    await oauthError(
      exchangeToken(
        deps(),
        { audience: "gateway" },
        form({ subject_token: token, audience: "evil" }),
      ),
      "invalid_target",
    );
    await oauthError(
      exchangeToken(
        deps(),
        { audience: "gateway" },
        form({ subject_token: token, audience: "gateway" }),
      ),
      "invalid_target",
    );
    await oauthError(
      exchangeToken(
        { ...deps(), reexchangeTargets: new Map() },
        { audience: "gateway" },
        form({ subject_token: token }),
      ),
      "invalid_target",
    );
    oauthError(
      () =>
        form({
          subject_token: token,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        }),
      "invalid_request",
    );
  },
);

test(
  "re-exchange refuses delegated tokens until delegation revocation can be checked",
  { skip },
  async () => {
    const claims = { act: { sub: AGENT }, task_id: "task-1" };
    const undelegated = await mint(claims);
    await exchangeToken(
      deps(),
      { audience: "gateway" },
      form({ subject_token: undelegated.token }),
    );
    const { token } = await mint({
      ...claims,
      delegation_id: `dlg_${"0".repeat(32)}`,
    });
    await oauthError(
      exchangeToken(
        deps(),
        { audience: "gateway" },
        form({ subject_token: token }),
      ),
      "invalid_request",
    );
  },
);

test(
  "re-exchange stops as soon as the principal, its actor or its session is no longer valid",
  { skip },
  async () => {
    const forLeaver = await mint({ sub: LEAVER, org_path: ["acme"] });
    const actedByAgent = await mint({ act: { sub: AGENT } });
    await db.query(
      "UPDATE principals SET status = 'disabled' WHERE id = ANY($1)",
      [[LEAVER, AGENT]],
    );
    for (const { token } of [forLeaver, actedByAgent])
      await oauthError(
        exchangeToken(
          deps(),
          { audience: "gateway" },
          form({ subject_token: token }),
        ),
        "invalid_request",
      );
    await db.query(
      "UPDATE principals SET status = 'active' WHERE id = ANY($1)",
      [[LEAVER, AGENT]],
    );
    for (const input of [
      { principal_type: "service" },
      { session_id: REVOKED_SESSION },
      { session_id: `ses_${"9".repeat(32)}` },
    ]) {
      const { token } = await mint(input);
      await oauthError(
        exchangeToken(
          deps(),
          { audience: "gateway" },
          form({ subject_token: token }),
        ),
        "invalid_request",
      );
    }
  },
);

test(
  "rotation publishes the next key first and keeps the old one through the overlap",
  { skip },
  async () => {
    const signedByA = await mint();
    await registerKey(db, keyB);
    await registerKey(db, keyB);
    await assert.rejects(promoteNextKey(db, signers), KeyError);
    assert.deepEqual(
      new Set((await publishedKeys(db)).map((k) => k.kid)),
      new Set([keyA.kid, keyB.kid]),
    );
    await assert.rejects(
      registerKey(db, localSigner(pem("P-256"))),
      /another next key/,
    );

    await backdate(keyB.kid, "created_at");
    await assert.rejects(
      promoteNextKey(db, new Map([[keyA.kid, keyA]])),
      /no signer configured for next key/,
    );
    assert.equal(await promoteNextKey(db, signers), keyB.kid);
    await assert.rejects(registerKey(db, keyA), /already retired/);
    await assert.rejects(registerKey(db, keyB), /already active/);
    const signedByB = await mint();
    assert.equal(headerOf(signedByB.token).kid, keyB.kid);
    const opts = { issuer: ISSUER, audience: "gateway" };
    assert.ok(await verifyToken(db, signedByA.token, opts));
    assert.ok(await verifyToken(db, signedByB.token, opts));

    await backdate(keyA.kid, "retired_at");
    assert.deepEqual(
      (await publishedKeys(db)).map((k) => k.kid),
      [keyB.kid],
    );
    await rejects(verifyToken(db, signedByA.token, opts));

    await assert.rejects(mintToken(db, new Map(), ISSUER, base), KeyError);
  },
);
