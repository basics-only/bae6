import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type pg from "pg";
import {
  AUTHN_AUDIENCE,
  CSRF_COOKIE,
  createBffRoutes,
  LOGIN_COOKIE_PREFIX,
  type LoginProvider,
} from "./bff.js";
import { migratedTestDatabase } from "./db/test-database.js";
import { createDelegation } from "./delegations.js";
import { localSigner, syncKeys } from "./keys.js";
import { OidcError } from "./oidc.js";
import { PrincipalError, setPrincipalStatus } from "./principals.js";
import { createAuthnApi } from "./server.js";
import { createSession, readSession, SESSION_COOKIE } from "./sessions.js";
import { type MintInput, mintToken, verifyToken } from "./tokens.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ISSUER = "https://ping.example/acme";
const AUTHN_ISSUER = "https://authn.bae6.test";
const signer = localSigner(
  generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ type: "pkcs8", format: "pem" })
    .toString(),
);
const signers = new Map([[signer.kid, signer]]);
const tenantsByHost = new Map<string, string>();
let db: pg.Pool;
let close: () => Promise<void>;
let server: ReturnType<typeof createAuthnApi>;
let base: string;
let origin: string;
let n = 0;
const redirectUris: string[] = [];

const provider: LoginProvider = {
  async beginLogin() {
    n += 1;
    const pending = {
      state: `state${n}`,
      nonce: `nonce${n}`,
      codeVerifier: `cv${n}`,
    };
    return { url: new URL(`${ISSUER}/authorize?state=${n}`), pending };
  },
  async completeLogin(query, pending) {
    if (query.get("state") !== pending.state)
      throw new OidcError("invalid_callback");
    return {
      identity: {
        issuer: ISSUER,
        subject: query.get("code") ?? "",
        claims: {},
      },
      providerAccessToken: "at",
      providerAccessTokenExpiresAt: undefined,
    };
  },
  async clientCredentials() {
    throw new Error("not used for Ping");
  },
};

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_bff",
  ));
  await db.query(
    `INSERT INTO provider_connections
       (tenant_id, id, kind, issuer, client_id, client_secret_ref, jit_provisioning, status)
     VALUES ('acme', 'ping', 'pingfederate', $1, 'c', 's', true, 'active'),
            ('acme', 'ping2', 'pingfederate', $1, 'c', 's', true, 'active'),
            ('acme', 'off', 'pingfederate', 'https://ping.example/off', 'c', 's', true, 'disabled'),
            ('globex', 'ping', 'pingfederate', 'https://ping.example/globex', 'c', 's', true, 'active')`,
    [ISSUER],
  );
  await syncKeys(db, signers, signer.kid);
  server = createAuthnApi({
    ping: async () => {},
    requestTimeoutMs: 5000,
    routes: createBffRoutes({
      db,
      provider: async (_connection, redirectUri) => {
        redirectUris.push(redirectUri);
        return provider;
      },
      tenantsByHost,
      sessionTtlSeconds: 3600,
      issuer: AUTHN_ISSUER,
      delegation: {
        signers,
        audiences: new Set([AUTHN_AUDIENCE, "bae6-authz"]),
        policyVersion: "test-model",
        limits: {
          maxDepth: 3,
          maxLifetimeSeconds: 3600,
          highImpact: (action) => action === "tool:delete",
        },
      },
    }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const host = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  tenantsByHost.set(host, "acme");
  tenantsByHost.set("acme.bae6.test", "acme");
  base = `http://${host}`;
  origin = `https://${host}`;
});

after(async () => {
  if (skip) return;
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await close();
});

const cookieFrom = (res: Response, name: string) => {
  const line = res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
  return line
    ? { value: line.slice(name.length + 1).split(";")[0] ?? "", line }
    : undefined;
};

const get = (path: string, cookie?: string) =>
  fetch(`${base}${path}`, {
    redirect: "manual",
    headers: cookie ? { cookie } : {},
  });

async function start(returnTo = "/dash", provider = "ping") {
  const res = await get(
    `/auth/login/${provider}?returnTo=${encodeURIComponent(returnTo)}`,
  );
  assert.equal(res.status, 302);
  const state = `state${n}`;
  const login = cookieFrom(res, `${LOGIN_COOKIE_PREFIX}${state}`);
  assert.ok(login);
  return { res, state, login };
}

const finish = (
  state: string,
  login: string,
  subject: string,
  extra = "",
  provider = "ping",
) =>
  get(
    `/auth/callback/${provider}?code=${subject}&state=${state}`,
    `${LOGIN_COOKIE_PREFIX}${state}=${login}${extra}`,
  );

async function signIn(subject: string, extra = "") {
  const { state, login } = await start();
  return finish(state, login.value, subject, extra);
}

const sessionCookie = (res: Response) => {
  const c = cookieFrom(res, SESSION_COOKIE);
  assert.ok(c, `no session cookie (status ${res.status})`);
  return `${SESSION_COOKIE}=${c.value}`;
};

const logout = (cookie: string, headers: Record<string, string>) =>
  fetch(`${base}/auth/logout`, {
    method: "POST",
    headers: { cookie, ...headers },
  });

test(
  "sign-in sets host-only secure cookies and returns to the requested page",
  { skip },
  async () => {
    const { res, state, login } = await start();
    assert.equal(res.headers.get("location"), `${ISSUER}/authorize?state=${n}`);
    assert.equal(redirectUris.at(-1), `${origin}/auth/callback/ping`);
    assert.match(
      login.line,
      /^__Host-bae6-login-state\d+=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax$/,
    );
    const done = await finish(state, login.value, "alice");
    assert.equal(done.status, 303);
    assert.equal(done.headers.get("location"), "/dash");
    assert.match(
      cookieFrom(done, SESSION_COOKIE)?.line ?? "",
      /^__Host-bae6-session=ses_[0-9a-f]{32}\.[\w-]{43}; Path=\/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax$/,
    );
    assert.match(
      cookieFrom(done, CSRF_COOKIE)?.line ?? "",
      /^__Host-bae6-csrf=[\w-]{43}; Path=\/; Max-Age=3600; Secure; SameSite=Lax$/,
    );
    assert.ok(
      done.headers
        .getSetCookie()
        .some((c) => c.startsWith(`${LOGIN_COOKIE_PREFIX}${state}=;`)),
    );
    const me = await get("/auth/me", sessionCookie(done));
    assert.equal(me.status, 200);
    const body = await me.json();
    assert.deepEqual(Object.keys(body).sort(), ["orgPath", "principal"]);
    assert.equal(body.principal.tenantId, "acme");
    assert.equal(body.principal.type, "user");
    assert.equal(body.principal.status, "active");
    assert.match(body.principal.id, /^prn_[0-9a-f]{32}$/);
    assert.deepEqual(body.orgPath, ["acme"]);
  },
);

test(
  "providers lists this tenant's active connections with display names",
  { skip },
  async () => {
    await db.query(
      "UPDATE provider_connections SET display_name = 'Acme SSO' WHERE tenant_id = 'acme' AND id = 'ping'",
    );
    await db.query(
      `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
       VALUES ('acme', 'unpinned', 'entra', 'https://login.microsoftonline.com/common/v2.0', 'c', 's')`,
    );
    const res = await get("/auth/providers");
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      providers: [
        { id: "ping", kind: "pingfederate", displayName: "Acme SSO" },
        { id: "ping2", kind: "pingfederate", displayName: "ping2" },
      ],
    });
    const other = await fetch(
      `http://localhost:${new URL(base).port}/auth/providers`,
    );
    assert.equal(other.status, 404);
    for (const spoof of ["Okta‮gnp.", "   ", "a​b", "a\nb", "Ok⁠ta", "Ok­ta"])
      await assert.rejects(
        db.query(
          "UPDATE provider_connections SET display_name = $1 WHERE tenant_id = 'acme' AND id = 'ping'",
          [spoof],
        ),
        /provider_connections_display_name_check/,
        JSON.stringify(spoof),
      );
  },
);

test(
  "a bae6 token issued to authn identifies its principal on /auth/me",
  { skip },
  async () => {
    const cookie = sessionCookie(await signIn("hank"));
    const s = await readSession(db, cookie.split("=")[1]);
    assert.ok(s);
    const helper = `prn_${"8".repeat(32)}`;
    const outsider = `prn_${"6".repeat(32)}`;
    await db.query(
      `INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'acme', 'service'), ($2, 'globex', 'user')`,
      [helper, outsider],
    );
    const token = async (claims: Partial<MintInput> = {}) =>
      (
        await mintToken(db, signers, AUTHN_ISSUER, {
          aud: AUTHN_AUDIENCE,
          sub: s.principalId,
          txn: "req-1",
          tenant_id: "acme",
          org_path: ["acme"],
          principal_type: "user",
          session_id: s.id,
          ...claims,
        })
      ).token;
    const me = (authorization: string, host = base, cookie?: string) =>
      fetch(`${host}/auth/me`, {
        headers: { authorization, ...(cookie ? { cookie } : {}) },
      });
    const ok = await me(`bearer ${await token()}`);
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).principal.id, s.principalId);
    assert.equal((await me("Basic abc", base, cookie)).status, 200);
    const acted = await token({
      act: { sub: helper, principal_type: "service" },
    });
    assert.equal(
      (
        await me(
          `Bearer ${await token({ act: { sub: helper, principal_type: "agent" } })}`,
        )
      ).status,
      401,
    );
    assert.equal((await me(`Bearer ${acted}`)).status, 200);
    await db.query("UPDATE principals SET status = 'disabled' WHERE id = $1", [
      helper,
    ]);
    for (const bad of [
      `Bearer ${acted}`,
      `Bearer ${await token({ aud: "gateway" })}`,
      `Bearer ${await token({ session_id: `ses_${"9".repeat(32)}` })}`,
      `Bearer ${await token({ principal_type: "service" })}`,
      `Bearer ${await token({ sub: outsider, tenant_id: "globex", org_path: ["globex"] })}`,
      "Bearer not-a-token",
    ])
      assert.equal((await me(bad)).status, 401, bad.slice(0, 20));
    const onHost = (
      hostHeader: string,
      authorization: string,
      cookie?: string,
    ) =>
      new Promise<{ status: number | undefined; tenantId?: string }>(
        (resolve, reject) =>
          request(
            `${base}/auth/me`,
            {
              headers: {
                host: hostHeader,
                authorization,
                ...(cookie ? { cookie } : {}),
              },
            },
            async (res) => {
              let body = "";
              for await (const chunk of res) body += chunk;
              resolve({
                status: res.statusCode,
                tenantId:
                  res.statusCode === 200
                    ? JSON.parse(body).principal.tenantId
                    : undefined,
              });
            },
          )
            .on("error", reject)
            .end(),
      );
    const internal = new URL(AUTHN_ISSUER).host;
    const globex = `Bearer ${
      (
        await mintToken(db, signers, AUTHN_ISSUER, {
          aud: AUTHN_AUDIENCE,
          sub: outsider,
          txn: "req-2",
          tenant_id: "globex",
          org_path: ["globex"],
          principal_type: "user",
        })
      ).token
    }`;
    assert.deepEqual(await onHost(internal, `Bearer ${await token()}`), {
      status: 200,
      tenantId: "acme",
    });
    assert.deepEqual(await onHost(internal, globex), {
      status: 200,
      tenantId: "globex",
    });
    assert.equal((await onHost("acme.bae6.test", globex)).status, 401);
    for (const unmapped of ["localhost", `${internal}.`, `${internal}:8443`])
      assert.equal(
        (await onHost(unmapped, `Bearer ${await token()}`)).status,
        404,
        unmapped,
      );
    assert.equal((await onHost(internal, "Basic abc", cookie)).status, 404);
  },
);

test(
  "two sign-ins started in different tabs both complete",
  { skip },
  async () => {
    const first = await start();
    const second = await start();
    assert.equal(
      (await finish(first.state, first.login.value, "tabs")).status,
      303,
    );
    assert.equal(
      (await finish(second.state, second.login.value, "tabs")).status,
      303,
    );
  },
);

test(
  "logout needs the same origin, a session and its CSRF token, then the session is gone",
  { skip },
  async () => {
    const done = await signIn("bob");
    const cookie = sessionCookie(done);
    const csrf = cookieFrom(done, CSRF_COOKIE)?.value ?? "";
    assert.equal((await logout(cookie, { origin })).status, 403);
    assert.equal(
      (await logout(cookie, { origin, "x-csrf-token": "x".repeat(43) })).status,
      403,
    );
    assert.equal(
      (
        await logout(cookie, {
          origin: "https://evil.example",
          "x-csrf-token": csrf,
        })
      ).status,
      403,
    );
    assert.equal(
      (await logout("", { origin, "x-csrf-token": csrf })).status,
      401,
    );
    assert.equal((await get("/auth/me", cookie)).status, 200);
    const out = await logout(cookie, { origin, "x-csrf-token": csrf });
    assert.equal(out.status, 204);
    assert.ok(
      out.headers
        .getSetCookie()
        .some((c) => c.startsWith(`${SESSION_COOKIE}=;`)),
    );
    assert.equal((await get("/auth/me", cookie)).status, 401);
  },
);

test(
  "with http allowed, sign-in and logout use the http origin",
  { skip },
  async () => {
    const dev = createAuthnApi({
      ping: async () => {},
      requestTimeoutMs: 5000,
      routes: createBffRoutes({
        db,
        provider: async (_connection, redirectUri) => {
          redirectUris.push(redirectUri);
          return provider;
        },
        tenantsByHost,
        sessionTtlSeconds: 3600,
        issuer: AUTHN_ISSUER,
        allowHttp: true,
        httpOrigin: true,
      }),
    });
    await new Promise<void>((r) => dev.listen(0, "127.0.0.1", r));
    const host = `127.0.0.1:${(dev.address() as AddressInfo).port}`;
    tenantsByHost.set(host, "acme");
    try {
      const at = (path: string, init: RequestInit = {}) =>
        fetch(`http://${host}${path}`, { redirect: "manual", ...init });
      const begin = await at("/auth/login/ping");
      assert.equal(begin.status, 302);
      assert.equal(redirectUris.at(-1), `http://${host}/auth/callback/ping`);
      const state = `state${n}`;
      const login = cookieFrom(begin, `${LOGIN_COOKIE_PREFIX}${state}`);
      assert.ok(login);
      const done = await at(`/auth/callback/ping?code=httpdev&state=${state}`, {
        headers: {
          cookie: `${LOGIN_COOKIE_PREFIX}${state}=${login.value}`,
        },
      });
      assert.equal(done.status, 303);
      const csrf = cookieFrom(done, CSRF_COOKIE)?.value ?? "";
      const out = await at("/auth/logout", {
        method: "POST",
        headers: {
          cookie: sessionCookie(done),
          origin: `http://${host}`,
          "x-csrf-token": csrf,
        },
      });
      assert.equal(out.status, 204);
    } finally {
      tenantsByHost.delete(host);
      dev.closeAllConnections();
      await new Promise<void>((r) => dev.close(() => r()));
    }
  },
);

test(
  "allowing http issuers alone keeps the https origin",
  { skip },
  async () => {
    const dev = createAuthnApi({
      ping: async () => {},
      requestTimeoutMs: 5000,
      routes: createBffRoutes({
        db,
        provider: async (_connection, redirectUri) => {
          redirectUris.push(redirectUri);
          return provider;
        },
        tenantsByHost,
        sessionTtlSeconds: 3600,
        issuer: AUTHN_ISSUER,
        allowHttp: true,
      }),
    });
    await new Promise<void>((r) => dev.listen(0, "127.0.0.1", r));
    const host = `127.0.0.1:${(dev.address() as AddressInfo).port}`;
    tenantsByHost.set(host, "acme");
    try {
      const at = (path: string, init: RequestInit = {}) =>
        fetch(`http://${host}${path}`, { redirect: "manual", ...init });
      const begin = await at("/auth/login/ping");
      assert.equal(begin.status, 302);
      assert.equal(redirectUris.at(-1), `https://${host}/auth/callback/ping`);
    } finally {
      tenantsByHost.delete(host);
      dev.closeAllConnections();
      await new Promise<void>((r) => dev.close(() => r()));
    }
  },
);

test(
  "sign-in refuses open redirects, unknown or disabled providers, and unknown hosts",
  { skip },
  async () => {
    for (const to of [
      "//evil.example",
      "/\\evil.example",
      "https://evil.example",
      "dash",
      "/a b",
    ])
      assert.equal(
        (await get(`/auth/login/ping?returnTo=${encodeURIComponent(to)}`))
          .status,
        400,
        to,
      );
    assert.equal((await get("/auth/login/off")).status, 404);
    assert.equal((await get("/auth/login/nope")).status, 404);
    assert.equal((await get("/auth/login/PING")).status, 404);
    const other = await fetch(
      `http://localhost:${new URL(base).port}/auth/login/ping`,
      {
        redirect: "manual",
      },
    );
    assert.equal(other.status, 404);
  },
);

test(
  "a tenant host matches exactly, with the default https port optional",
  { skip },
  async () => {
    const statusFor = (hostHeader: string) =>
      new Promise<number | undefined>((resolve, reject) =>
        request(
          `${base}/auth/providers`,
          { headers: { host: hostHeader } },
          (res) => {
            res.resume();
            resolve(res.statusCode);
          },
        )
          .on("error", reject)
          .end(),
      );
    assert.equal(await statusFor("acme.bae6.test"), 200);
    assert.equal(await statusFor("ACME.bae6.test:443"), 200);
    for (const other of [
      "acme.bae6.test:1",
      "acme.bae6.test:0443",
      "acme.bae6.test:8443",
      "evil.example:443",
    ])
      assert.equal(await statusFor(other), 404, other);
  },
);

test(
  "starting sign-in expires the oldest pending logins so the cookie header stays bounded",
  { skip },
  async () => {
    const pending = ["old1", "old2", "old3"].map(
      (s) => `${LOGIN_COOKIE_PREFIX}${s}=x`,
    );
    const res = await get(
      "/auth/login/ping",
      [...pending, `${SESSION_COOKIE}=keep`].join("; "),
    );
    assert.equal(res.status, 302);
    const set = res.headers.getSetCookie();
    const cleared = (s: string) =>
      set.some((c) => c.startsWith(`${LOGIN_COOKIE_PREFIX}${s}=;`));
    assert.ok(cleared("old1"));
    assert.ok(!cleared("old2") && !cleared("old3"));
    assert.ok(!set.some((c) => c.startsWith(`${SESSION_COOKIE}=`)));
    assert.equal(
      set.filter(
        (c) => c.startsWith(LOGIN_COOKIE_PREFIX) && !c.includes("Max-Age=0"),
      ).length,
      1,
    );
    const underCap = await get(
      "/auth/login/ping",
      [pending[0], pending[1], pending[1]].join("; "),
    );
    assert.ok(
      !underCap.headers.getSetCookie().some((c) => c.includes("Max-Age=0")),
    );
  },
);

test(
  "a callback without its login cookie, or for another provider, creates no session",
  { skip },
  async () => {
    assert.equal(
      (await get("/auth/callback/ping?code=eve&state=state1")).status,
      400,
    );
    const { state, login } = await start();
    for (const res of [
      await finish(state, "bnVsbA", "eve"),
      await finish(state, login.value, "eve", "", "ping2"),
      await get(
        `/auth/callback/ping?code=eve&state=forged`,
        `${LOGIN_COOKIE_PREFIX}${state}=${login.value}`,
      ),
    ]) {
      assert.equal(res.status, 400);
      assert.equal(cookieFrom(res, SESSION_COOKIE), undefined);
    }
  },
);

test(
  "a forged or tampered session cookie is not a session",
  { skip },
  async () => {
    const cookie = sessionCookie(await signIn("carol"));
    const [id] = cookie.split("=")[1]?.split(".") ?? [];
    for (const forged of [`${id}.${"A".repeat(43)}`, `${id}`, "ses_x.y", ""])
      assert.equal(
        (await get("/auth/me", `${SESSION_COOKIE}=${forged}`)).status,
        401,
      );
  },
);

test(
  "another tenant's session is not accepted on this host",
  { skip },
  async () => {
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO principals (id, tenant_id, type) VALUES ('prn_${"7".repeat(32)}', 'globex', 'user') RETURNING id`,
    );
    const { cookie } = await createSession(db, {
      tenantId: "globex",
      principalId: rows[0]?.id as string,
      connectionId: "ping",
      ttlSeconds: 3600,
    });
    assert.equal(
      (await get("/auth/me", `${SESSION_COOKIE}=${cookie}`)).status,
      401,
    );
  },
);

test("signing in again replaces the previous session", { skip }, async () => {
  const first = sessionCookie(await signIn("dave"));
  const second = sessionCookie(await signIn("dave", `; ${first}`));
  assert.notEqual(first, second);
  assert.equal((await get("/auth/me", first)).status, 401);
  assert.equal((await get("/auth/me", second)).status, 200);
});

test(
  "disabling a principal or its connection ends their sessions",
  { skip },
  async () => {
    const cookie = sessionCookie(await signIn("erin"));
    const { principal } = await (await get("/auth/me", cookie)).json();
    await setPrincipalStatus(db, {
      tenantId: "acme",
      principalId: principal.id,
      status: "disabled",
      actor: "test",
    });
    assert.equal((await get("/auth/me", cookie)).status, 401);
    assert.equal((await signIn("erin")).status, 401);

    const { state, login } = await start("/", "ping2");
    const viaPing2 = sessionCookie(
      await finish(state, login.value, "gina", "", "ping2"),
    );
    await db.query(
      "UPDATE provider_connections SET status = 'disabled' WHERE tenant_id = 'acme' AND id = 'ping2'",
    );
    assert.equal((await get("/auth/me", viaPing2)).status, 401);
  },
);

test(
  "a session insert racing a disable waits for it and is refused",
  { skip },
  async () => {
    const cookie = sessionCookie(await signIn("frank"));
    const s = await readSession(db, cookie.split("=")[1]);
    assert.ok(s);
    const disabler = await db.connect();
    try {
      await disabler.query("BEGIN");
      await disabler.query(
        "SELECT 1 FROM principals WHERE id = $1 FOR UPDATE",
        [s.principalId],
      );
      await disabler.query(
        "UPDATE principals SET status = 'disabled' WHERE id = $1",
        [s.principalId],
      );
      const racing = createSession(db, {
        tenantId: "acme",
        principalId: s.principalId,
        connectionId: "ping",
        ttlSeconds: 3600,
      });
      await new Promise((r) => setTimeout(r, 100));
      await disabler.query("COMMIT");
      await assert.rejects(
        racing,
        (e: unknown) =>
          e instanceof PrincipalError && e.code === "principal_inactive",
      );
    } finally {
      disabler.release();
    }
  },
);

test(
  "only the direct initiating principal can revoke a delegation tree",
  { skip },
  async () => {
    const ownerCookie = sessionCookie(await signIn("delegation-owner"));
    const otherCookie = sessionCookie(await signIn("delegation-stranger"));
    const owner = await readSession(db, ownerCookie.split("=")[1]);
    const other = await readSession(db, otherCookie.split("=")[1]);
    assert.ok(owner && other);
    const actor = `prn_${randomBytes(16).toString("hex")}`;
    const childActor = `prn_${randomBytes(16).toString("hex")}`;
    await db.query(
      `INSERT INTO principals (id, tenant_id, type, owner_application_id)
     VALUES ($1, 'acme', 'agent', 'helper'), ($2, 'acme', 'agent', 'helper')`,
      [actor, childActor],
    );
    const common = {
      tenantId: "acme",
      initiatingPrincipalId: owner.principalId,
      applicationId: "helper",
      taskId: "revoke-route",
      allowedResources: ["document:d1"],
      allowedActions: ["document:read"],
      expiresAt: new Date(Date.now() + 60_000),
      policyVersion: "test",
    };
    const limits = { maxDepth: 3, maxLifetimeSeconds: 3600 };
    const { id: root } = await createDelegation(db, limits, {
      ...common,
      actorPrincipalId: actor,
    });
    const { id: child } = await createDelegation(db, limits, {
      ...common,
      actorPrincipalId: childActor,
      parentDelegationId: root,
      createdByPrincipalId: actor,
    });
    const tokenFor = (session: typeof owner, over: Partial<MintInput> = {}) =>
      mintToken(db, signers, AUTHN_ISSUER, {
        aud: AUTHN_AUDIENCE,
        sub: session.principalId,
        txn: "revoke-test",
        tenant_id: session.tenantId,
        org_path: [session.tenantId],
        principal_type: "user",
        session_id: session.id,
        ...over,
      }).then(({ token }) => token);
    const revoke = (id: string, token?: string) =>
      fetch(`${base}/v1/delegations/${id}/revoke`, {
        method: "POST",
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
    assert.equal((await revoke(root)).status, 401);
    assert.equal(
      (
        await revoke(
          root,
          await tokenFor(owner, {
            act: { sub: actor, principal_type: "agent" },
            task_id: common.taskId,
            application_id: "helper",
            delegation_id: root,
            delegated_resources: common.allowedResources,
            delegated_actions: common.allowedActions,
          }),
        )
      ).status,
      401,
    );
    assert.equal(
      (await revoke(root, await tokenFor(owner, { aud: "other-audience" })))
        .status,
      401,
    );
    assert.equal((await revoke(root, await tokenFor(other))).status, 404);
    const revoked = () =>
      db.query(
        "SELECT id FROM delegations WHERE id = ANY($1) AND revoked_at IS NOT NULL",
        [[root, child]],
      );
    assert.equal((await revoked()).rowCount, 0);
    const ownerToken = await tokenFor(owner);
    assert.equal(
      (await revoke(`dlg_${"0".repeat(32)}`, ownerToken)).status,
      404,
    );
    assert.equal((await revoke(root, ownerToken)).status, 204);
    assert.equal((await revoked()).rowCount, 2);
    assert.equal((await revoke(root, ownerToken)).status, 204);
  },
);

test(
  "a user delegates a task scope to an agent and the agent may only narrow it under its own delegation",
  { skip },
  async () => {
    const owner = await readSession(
      db,
      sessionCookie(await signIn("delegator")).split("=")[1],
    );
    assert.ok(owner);
    const [agent, helper] = [1, 2].map(
      () => `prn_${randomBytes(16).toString("hex")}`,
    ) as [string, string];
    await db.query(
      `INSERT INTO principals (id, tenant_id, type, owner_application_id)
       VALUES ($1, 'acme', 'agent', 'helper'), ($2, 'acme', 'agent', 'helper')`,
      [agent, helper],
    );
    const ownerToken = (
      await mintToken(db, signers, AUTHN_ISSUER, {
        aud: AUTHN_AUDIENCE,
        sub: owner.principalId,
        txn: "delegate-test",
        tenant_id: "acme",
        org_path: ["acme"],
        principal_type: "user",
        session_id: owner.id,
      })
    ).token;
    const scope = {
      actorPrincipalId: agent,
      applicationId: "helper",
      taskId: "summarize",
      allowedResources: ["model:llm", "document:d1"],
      allowedActions: ["model:invoke", "document:read"],
      expiresInSeconds: 120,
      audience: AUTHN_AUDIENCE,
    };
    const delegate = (body: Record<string, unknown>, token?: string) =>
      fetch(`${base}/v1/delegations`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });

    const created = await delegate(scope, ownerToken);
    assert.equal(created.status, 201);
    const { delegationId, token } = await created.json();
    const claims = await verifyToken(db, token.access_token, {
      issuer: AUTHN_ISSUER,
      audience: AUTHN_AUDIENCE,
    });
    assert.equal(claims.sub, owner.principalId);
    assert.deepEqual(claims.act, { sub: agent, principal_type: "agent" });
    assert.equal(claims.delegation_id, delegationId);
    assert.equal(claims.task_id, "summarize");
    assert.deepEqual(claims.delegated_resources, scope.allowedResources);
    assert.deepEqual(claims.delegated_actions, scope.allowedActions);
    assert.equal(claims.session_id, owner.id);
    assert.ok(claims.exp <= Math.floor(Date.now() / 1000) + 120);

    const sessionless = (
      await mintToken(db, signers, AUTHN_ISSUER, {
        aud: AUTHN_AUDIENCE,
        sub: owner.principalId,
        txn: "delegate-test",
        tenant_id: "acme",
        org_path: ["acme"],
        principal_type: "user",
      })
    ).token;
    const risky = {
      ...scope,
      allowedActions: ["tool:delete"],
      approvedActions: ["tool:delete"],
    };
    for (const [body, status, bearer] of [
      [scope, 401, undefined],
      [{ ...scope, audience: "nobody" }, 400, ownerToken],
      [{ ...scope, applicationId: undefined }, 400, ownerToken],
      [{ ...scope, applicationId: "other-app" }, 400, ownerToken],
      [{ ...scope, expiresInSeconds: 7200 }, 400, ownerToken],
      [{ ...scope, approvedActions: null }, 400, ownerToken],
      [
        { ...risky, approvedActions: ["tool:delete", "tool:delete"] },
        400,
        ownerToken,
      ],
      [{ ...scope, allowedActions: ["tool:delete"] }, 403, ownerToken],
      [risky, 403, sessionless],
      [{ ...scope, parentDelegationId: delegationId }, 403, ownerToken],
    ] as const)
      assert.equal(
        (await delegate(body, bearer)).status,
        status,
        JSON.stringify(body),
      );
    assert.equal((await delegate(risky, ownerToken)).status, 201);

    const nested = {
      ...scope,
      actorPrincipalId: helper,
      parentDelegationId: delegationId,
      allowedResources: ["document:d1"],
      allowedActions: ["document:read"],
      expiresInSeconds: 60,
      audience: "bae6-authz",
    };
    const agentToken = token.access_token;
    assert.equal(
      (
        await delegate(
          { ...nested, allowedResources: ["document:d2"] },
          agentToken,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await delegate(
          { ...nested, parentDelegationId: `dlg_${"0".repeat(32)}` },
          agentToken,
        )
      ).status,
      403,
    );
    const child = await delegate(nested, agentToken);
    assert.equal(child.status, 201);
    const childClaims = await verifyToken(
      db,
      (await child.json()).token.access_token,
      { issuer: AUTHN_ISSUER, audience: "bae6-authz" },
    );
    assert.equal(childClaims.sub, owner.principalId);
    assert.deepEqual(childClaims.act, { sub: helper, principal_type: "agent" });
    assert.equal(childClaims.session_id, owner.id);

    assert.equal(
      (
        await fetch(`${base}/v1/delegations/${delegationId}/revoke`, {
          method: "POST",
          headers: { authorization: `Bearer ${ownerToken}` },
        })
      ).status,
      204,
    );
    assert.equal((await delegate(nested, agentToken)).status, 404);
  },
);
