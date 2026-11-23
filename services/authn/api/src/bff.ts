import type { IncomingMessage, ServerResponse } from "node:http";
import type { Pool } from "pg";
import {
  checkConnection,
  type GraphOptions,
  overageGroups,
} from "./adapters.js";
import { allActive, sessionLive } from "./exchange.js";
import { HttpError, send } from "./http.js";
import {
  OidcError,
  type OidcErrorCode,
  type OidcProvider,
  type PendingLogin,
} from "./oidc.js";
import {
  type ConnectionPolicy,
  loadConnection,
  PrincipalError,
  resolvePrincipal,
} from "./principals.js";
import {
  createSession,
  csrfMatches,
  readSession,
  revokeSession,
  SESSION_COOKIE,
} from "./sessions.js";
import { TokenError, verifyToken } from "./tokens.js";

export const LOGIN_COOKIE_PREFIX = "__Host-bae6-login-";
export const CSRF_COOKIE = "__Host-bae6-csrf";
export const AUTHN_AUDIENCE = "bae6-authn";
const LOGIN_TTL_SECONDS = 600;
const MAX_PROVIDERS = 50;
const BEARER = /^bearer ([A-Za-z0-9_.-]{1,8192})$/i;
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const RETURN_TO = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@/?-]{0,1023}$/;
const OPAQUE = /^[A-Za-z0-9_-]{1,128}$/;
const ROUTE = /^\/auth\/(login|callback)\/([^/]+)$/;

export type LoginProvider = Pick<
  OidcProvider,
  "beginLogin" | "completeLogin" | "clientCredentials"
>;

export interface BffDeps {
  db: Pool;
  provider(
    connection: ConnectionPolicy,
    redirectUri: string,
  ): Promise<LoginProvider>;
  tenantsByHost: ReadonlyMap<string, string>;
  sessionTtlSeconds: number;
  issuer: string;
  graph?: GraphOptions;
  allowHttp?: boolean;
}

interface LoginCookie extends PendingLogin {
  connectionId: string;
  returnTo: string;
}

export function readCookie(
  req: IncomingMessage,
  name: string,
): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name)
      return part.slice(eq + 1).trim();
  }
  return undefined;
}

const MAX_PENDING_LOGINS = 3;

const pendingLoginsOldestFirst = (req: IncomingMessage) => [
  ...new Set(
    (req.headers.cookie ?? "")
      .split(";")
      .filter((part) => part.indexOf("=") > 0)
      .map((part) => part.slice(0, part.indexOf("=")).trim())
      .filter(
        (name) =>
          name.startsWith(LOGIN_COOKIE_PREFIX) &&
          OPAQUE.test(name.slice(LOGIN_COOKIE_PREFIX.length)),
      ),
  ),
];

const cookie = (name: string, value: string, maxAge: number, httpOnly = true) =>
  `${name}=${value}; Path=/; Max-Age=${maxAge};${httpOnly ? " HttpOnly;" : ""} Secure; SameSite=Lax`;

function decodeLogin(value: string | undefined): LoginCookie | undefined {
  if (!value || value.length > 2048) return undefined;
  let c: unknown;
  try {
    c = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
  if (typeof c !== "object" || c === null) return undefined;
  const v = c as Partial<Record<keyof LoginCookie, unknown>>;
  const ok =
    typeof v.connectionId === "string" &&
    SLUG.test(v.connectionId) &&
    typeof v.returnTo === "string" &&
    RETURN_TO.test(v.returnTo) &&
    [v.state, v.nonce, v.codeVerifier].every(
      (x) => typeof x === "string" && OPAQUE.test(x),
    );
  return ok ? (v as LoginCookie) : undefined;
}

const OIDC_STATUS: Record<OidcErrorCode, number> = {
  invalid_request: 400,
  invalid_callback: 400,
  provider_denied: 401,
  discovery_failed: 503,
  provider_unavailable: 503,
  provider_misconfigured: 503,
};

function asHttp(err: unknown): unknown {
  if (err instanceof OidcError)
    return new HttpError(OIDC_STATUS[err.code], err.code, "Sign-in failed.");
  if (err instanceof PrincipalError)
    return new HttpError(
      ["invalid_identity", "invalid_groups"].includes(err.code) ? 400 : 401,
      err.code,
      "Sign-in refused.",
    );
  return err;
}

export function createBffRoutes(deps: BffDeps) {
  const { db } = deps;

  function site(req: IncomingMessage) {
    const host = (req.headers.host ?? "").toLowerCase();
    const tenantId = deps.tenantsByHost.get(host);
    if (!tenantId) throw new HttpError(404, "not_found", "Not found.");
    return { tenantId, origin: `https://${host}` };
  }

  async function activeConnection(tenantId: string, id: string) {
    const connection = SLUG.test(id)
      ? await loadConnection(db, tenantId, id)
      : undefined;
    if (!connection || connection.status !== "active")
      throw new HttpError(404, "not_found", "Unknown provider.");
    checkConnection(connection, { allowHttp: deps.allowHttp ?? false });
    return connection;
  }

  const redirectUri = (origin: string, id: string) =>
    `${origin}/auth/callback/${id}`;

  async function login(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    providerId: string,
  ) {
    const { tenantId, origin } = site(req);
    const returnTo = url.searchParams.get("returnTo") ?? "/";
    if (!RETURN_TO.test(returnTo))
      throw new HttpError(400, "invalid_request", "Invalid returnTo.");
    const connection = await activeConnection(tenantId, providerId);
    const provider = await deps.provider(
      connection,
      redirectUri(origin, connection.id),
    );
    const { url: to, pending } = await provider.beginLogin();
    const state: LoginCookie = {
      ...pending,
      connectionId: connection.id,
      returnTo,
    };
    const older = pendingLoginsOldestFirst(req);
    const stale = older.slice(
      0,
      Math.max(0, older.length - (MAX_PENDING_LOGINS - 1)),
    );
    res.writeHead(302, {
      location: to.toString(),
      "set-cookie": [
        ...stale.map((name) => cookie(name, "", 0)),
        cookie(
          `${LOGIN_COOKIE_PREFIX}${pending.state}`,
          Buffer.from(JSON.stringify(state)).toString("base64url"),
          LOGIN_TTL_SECONDS,
        ),
      ],
      "cache-control": "no-store",
    });
    res.end();
  }

  async function callback(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    providerId: string,
  ) {
    const { tenantId, origin } = site(req);
    const state = url.searchParams.get("state") ?? "";
    if (!OPAQUE.test(state))
      throw new HttpError(400, "invalid_callback", "Invalid callback.");
    const name = `${LOGIN_COOKIE_PREFIX}${state}`;
    res.setHeader("set-cookie", cookie(name, "", 0));
    const pending = decodeLogin(readCookie(req, name));
    if (!pending || pending.connectionId !== providerId)
      throw new HttpError(
        400,
        "invalid_callback",
        "Sign-in expired. Start again.",
      );
    const connection = await activeConnection(tenantId, providerId);
    const provider = await deps.provider(
      connection,
      redirectUri(origin, connection.id),
    );
    const verified = await provider.completeLogin(url.searchParams, pending);
    const groups = await overageGroups(
      connection,
      provider,
      verified,
      deps.graph,
    );
    const resolved = await resolvePrincipal(
      db,
      connection,
      verified.identity,
      groups,
    );
    const previous = await readSession(db, readCookie(req, SESSION_COOKIE));
    if (previous) await revokeSession(db, previous.id);
    const created = await createSession(db, {
      tenantId: resolved.tenantId,
      principalId: resolved.principalId,
      connectionId: connection.id,
      ttlSeconds: deps.sessionTtlSeconds,
    });
    res.writeHead(303, {
      location: pending.returnTo,
      "set-cookie": [
        cookie(name, "", 0),
        cookie(SESSION_COOKIE, created.cookie, deps.sessionTtlSeconds),
        cookie(
          CSRF_COOKIE,
          created.session.csrfToken,
          deps.sessionTtlSeconds,
          false,
        ),
      ],
      "cache-control": "no-store",
    });
    res.end();
  }

  async function currentSession(req: IncomingMessage) {
    const { tenantId } = site(req);
    const s = await readSession(db, readCookie(req, SESSION_COOKIE));
    if (!s || s.tenantId !== tenantId)
      throw new HttpError(401, "unauthenticated", "Not signed in.");
    return s;
  }

  async function bearerCaller(req: IncomingMessage, authorization: string) {
    const { tenantId } = site(req);
    const token = BEARER.exec(authorization)?.[1];
    const unauthenticated = new HttpError(
      401,
      "unauthenticated",
      "Invalid bearer token.",
    );
    if (!token) throw unauthenticated;
    let claims: Awaited<ReturnType<typeof verifyToken>>;
    try {
      claims = await verifyToken(db, token, {
        issuer: deps.issuer,
        audience: AUTHN_AUDIENCE,
      });
    } catch (err) {
      if (err instanceof TokenError) throw unauthenticated;
      throw err;
    }
    const principals: { id: string; type?: string }[] = [
      { id: claims.sub, type: claims.principal_type },
    ];
    if (claims.act) principals.push({ id: claims.act.sub });
    if (
      claims.tenant_id !== tenantId ||
      !(await allActive(db, tenantId, principals)) ||
      (claims.session_id !== undefined &&
        !(await sessionLive(db, tenantId, claims.sub, claims.session_id)))
    )
      throw unauthenticated;
    return { tenantId, principalId: claims.sub };
  }

  async function me(req: IncomingMessage, res: ServerResponse) {
    const authorization = req.headers.authorization;
    const s = /^bearer /i.test(authorization ?? "")
      ? await bearerCaller(req, authorization as string)
      : await currentSession(req);
    const { rows } = await db.query(
      `SELECT id, tenant_id AS "tenantId", type, status,
              owner_application_id AS "ownerApplicationId",
              created_at AS "createdAt", updated_at AS "updatedAt",
              org_path AS "orgPath"
         FROM principals WHERE tenant_id = $1 AND id = $2 AND status = 'active'`,
      [s.tenantId, s.principalId],
    );
    const row = rows[0];
    if (!row) throw new HttpError(401, "unauthenticated", "Not signed in.");
    const { orgPath, ownerApplicationId, ...principal } = row;
    send(res, 200, {
      principal: {
        ...principal,
        ...(ownerApplicationId ? { ownerApplicationId } : {}),
      },
      orgPath,
    });
  }

  async function providers(req: IncomingMessage, res: ServerResponse) {
    const { tenantId } = site(req);
    const { rows } = await db.query<{
      id: string;
      kind: ConnectionPolicy["kind"];
      issuer: string;
      displayName: string;
    }>(
      `SELECT id, kind, issuer, COALESCE(display_name, id) AS "displayName"
         FROM provider_connections WHERE tenant_id = $1 AND status = 'active'
        ORDER BY "displayName", id LIMIT $2`,
      [tenantId, MAX_PROVIDERS],
    );
    const usable = rows.filter((c) => {
      try {
        checkConnection(c, { allowHttp: deps.allowHttp ?? false });
        return true;
      } catch (err) {
        if (err instanceof OidcError) return false;
        throw err;
      }
    });
    send(res, 200, {
      providers: usable.map(({ id, kind, displayName }) => ({
        id,
        kind,
        displayName,
      })),
    });
  }

  async function logout(req: IncomingMessage, res: ServerResponse) {
    const { origin } = site(req);
    if (req.headers.origin !== origin)
      throw new HttpError(403, "forbidden", "Cross-site request refused.");
    const s = await currentSession(req);
    if (!csrfMatches(s, req.headers["x-csrf-token"]))
      throw new HttpError(403, "forbidden", "Missing or wrong CSRF token.");
    await revokeSession(db, s.id);
    res.writeHead(204, {
      "set-cookie": [
        cookie(SESSION_COOKIE, "", 0),
        cookie(CSRF_COOKIE, "", 0, false),
      ],
      "cache-control": "no-store",
    });
    res.end();
  }

  return async function route(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
  ): Promise<boolean> {
    const flow = ROUTE.exec(url.pathname);
    try {
      if (req.method === "GET" && flow?.[1] === "login")
        await login(req, res, url, flow[2] as string);
      else if (req.method === "GET" && flow?.[1] === "callback")
        await callback(req, res, url, flow[2] as string);
      else if (req.method === "GET" && url.pathname === "/auth/me")
        await me(req, res);
      else if (req.method === "GET" && url.pathname === "/auth/providers")
        await providers(req, res);
      else if (req.method === "POST" && url.pathname === "/auth/logout")
        await logout(req, res);
      else return false;
    } catch (err) {
      throw asHttp(err);
    }
    return true;
  };
}
