import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type pg from "pg";
import {
  CSRF_COOKIE,
  createBffRoutes,
  LOGIN_COOKIE_PREFIX,
  type LoginProvider,
} from "./bff.js";
import { migratedTestDatabase } from "./db/test-database.js";
import { OidcError } from "./oidc.js";
import { PrincipalError, setPrincipalStatus } from "./principals.js";
import { createAuthnApi } from "./server.js";
import { createSession, readSession, SESSION_COOKIE } from "./sessions.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ISSUER = "https://ping.example/acme";
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
    }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const host = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  tenantsByHost.set(host, "acme");
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
