// Development-only imitations of Entra, Okta and PingFederate: their paths, claim shapes and quirks,
// so authn's provider adapters can be tested without real tenants. Users sign in without a password.
import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  SignJWT,
} from "jose";

export const GRAPH_AUDIENCE = "https://graph.microsoft.com";
const MAX_CODES = 100;
const CODE_TTL_MS = 60_000;
const TOKEN_TTL_S = 300;
const MAX_KEYS = 2;
const MAX_BODY = 4096;
const REALM_ID = /^[A-Za-z0-9-]{1,64}$/;
const RESERVED = [
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "nonce",
  "auth_time",
];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GRAPH =
  /^\/entra\/graph\/v1\.0\/users\/([0-9a-f-]{36})\/getMemberObjects$/;

function layout(kind, id) {
  if (kind === "entra") {
    const r = `/entra/${id}`;
    return {
      issuer: `${r}/v2.0`,
      discovery: `${r}/v2.0/.well-known/openid-configuration`,
      authorize: `${r}/oauth2/v2.0/authorize`,
      token: `${r}/oauth2/v2.0/token`,
      jwks: `${r}/discovery/v2.0/keys`,
      rotate: `${r}/_mock/rotate`,
    };
  }
  if (kind === "okta") {
    const r = `/okta/oauth2/${id}`;
    return {
      issuer: r,
      discovery: `${r}/.well-known/openid-configuration`,
      authorize: `${r}/v1/authorize`,
      token: `${r}/v1/token`,
      jwks: `${r}/v1/keys`,
      rotate: `${r}/_mock/rotate`,
    };
  }
  const r = `/ping/${id}`;
  return {
    issuer: r,
    discovery: `${r}/.well-known/openid-configuration`,
    authorize: `${r}/as/authorization.oauth2`,
    token: `${r}/as/token.oauth2`,
    jwks: `${r}/pf/JWKS`,
    rotate: `${r}/_mock/rotate`,
  };
}

export function validateConfig(config) {
  const fail = (m) => {
    throw new Error(`mock idp config: ${m}`);
  };
  if (!Array.isArray(config?.clients) || config.clients.length === 0)
    fail("clients is required");
  const clientIds = new Set();
  for (const c of config.clients) {
    if (clientIds.has(c.id)) fail(`duplicate client ${c.id}`);
    clientIds.add(c.id);
    if (
      typeof c.id !== "string" ||
      typeof c.secret !== "string" ||
      c.secret.length < 8
    )
      fail("each client needs an id and a secret of 8+ characters");
    if (!Array.isArray(c.redirectUris) || c.redirectUris.length === 0)
      fail(`${c.id}: redirectUris`);
    for (const u of c.redirectUris) new URL(u);
  }
  if (!Array.isArray(config.realms) || config.realms.length === 0)
    fail("realms is required");
  const seen = new Set();
  for (const r of config.realms) {
    if (!["entra", "okta", "ping"].includes(r.kind))
      fail(`unknown kind ${r.kind}`);
    if (!REALM_ID.test(r.id ?? "")) fail(`bad realm id ${r.id}`);
    if (seen.has(`${r.kind}/${r.id}`))
      fail(`duplicate realm ${r.kind}/${r.id}`);
    seen.add(`${r.kind}/${r.id}`);
    if (r.kind !== "entra" && typeof r.audience !== "string")
      fail(`${r.id}: audience is required`);
    if (!Array.isArray(r.users) || r.users.length === 0)
      fail(`${r.id}: users is required`);
    const logins = new Set();
    const oids = new Set();
    for (const u of r.users) {
      if (typeof u.login !== "string" || typeof u.sub !== "string")
        fail(`${r.id}: user login and sub`);
      if (typeof u.claims !== "object" || u.claims === null)
        fail(`${r.id}/${u.login}: claims must be an object`);
      if (logins.has(u.login)) fail(`${r.id}: duplicate login ${u.login}`);
      logins.add(u.login);
      for (const k of RESERVED)
        if (k in u.claims)
          fail(`${r.id}/${u.login}: claim ${k} is set by the mock`);
      if (r.kind === "entra") {
        if (u.claims.tid !== r.id || !UUID.test(u.claims.oid ?? ""))
          fail(
            `${r.id}/${u.login}: Entra users need a lowercase UUID oid and tid equal to the realm id`,
          );
        if (oids.has(u.claims.oid))
          fail(`${r.id}: duplicate oid ${u.claims.oid}`);
        oids.add(u.claims.oid);
      }
    }
  }
  return config;
}

async function newKey() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const kid = randomBytes(8).toString("hex");
  return {
    kid,
    privateKey,
    jwk: { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" },
  };
}

const sha256 = (s) => createHash("sha256").update(s).digest("base64url");
const sameSecret = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

class BadRequest extends Error {}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new BadRequest("too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const formDecode = (s) => new URLSearchParams(`x=${s}`).get("x");

function json(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function redirect(res, url) {
  res.writeHead(302, { location: url.toString() });
  res.end();
}

export async function createIdp({ baseUrl, publicUrl = baseUrl, config }) {
  validateConfig(config);
  const clients = new Map(config.clients.map((c) => [c.id, c]));
  const routes = new Map();
  const realms = [];
  for (const r of config.realms) {
    const paths = layout(r.kind, r.id);
    const realm = {
      ...r,
      paths,
      iss: `${baseUrl}${paths.issuer}`,
      groupOverageLimit: r.groupOverageLimit ?? 200,
      keys: [await newKey()],
    };
    realm.keySet = (header, token) =>
      createLocalJWKSet({ keys: realm.keys.map((k) => k.jwk) })(header, token);
    realms.push(realm);
    for (const ep of ["discovery", "authorize", "token", "jwks", "rotate"])
      routes.set(paths[ep], { realm, ep });
  }
  const codes = new Map();

  const sign = (realm, claims, sub, aud) => {
    const key = realm.keys[0];
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: key.kid, typ: "JWT" })
      .setIssuer(realm.iss)
      .setSubject(sub)
      .setAudience(aud)
      .setIssuedAt()
      .setExpirationTime(`${TOKEN_TTL_S}s`)
      .setJti(randomUUID())
      .sign(key.privateKey);
  };

  function discovery(realm) {
    const { paths } = realm;
    return {
      issuer: realm.iss,
      authorization_endpoint: `${publicUrl}${paths.authorize}`,
      token_endpoint: `${baseUrl}${paths.token}`,
      jwks_uri: `${baseUrl}${paths.jwks}`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "client_credentials"],
      subject_types_supported: [realm.kind === "entra" ? "pairwise" : "public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
      ],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
    };
  }

  function authorize(realm, url, res) {
    const q = url.searchParams;
    const client = clients.get(q.get("client_id") ?? "");
    const redirectUri = q.get("redirect_uri") ?? "";
    if (!client || !client.redirectUris.includes(redirectUri))
      return json(res, 400, {
        error: "invalid_request",
        error_description: "unknown client_id or redirect_uri",
      });
    const back = new URL(redirectUri);
    const state = q.get("state");
    const fail = (error) => {
      back.searchParams.set("error", error);
      if (state) back.searchParams.set("state", state);
      redirect(res, back);
    };
    const scope = q.get("scope") ?? "";
    const challenge = q.get("code_challenge") ?? "";
    if (
      q.get("response_type") !== "code" ||
      !scope.split(" ").includes("openid") ||
      q.get("code_challenge_method") !== "S256" ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) ||
      !state
    )
      return fail("invalid_request");
    const hint = q.get("login_hint");
    const user =
      hint === null
        ? realm.users[0]
        : realm.users.find((u) => u.login === hint);
    if (!user) return fail("access_denied");
    const now = Date.now();
    for (const [k, v] of codes) if (v.expires < now) codes.delete(k);
    if (codes.size >= MAX_CODES) return fail("temporarily_unavailable");
    const code = randomBytes(24).toString("base64url");
    codes.set(code, {
      realm,
      clientId: client.id,
      redirectUri,
      challenge,
      nonce: q.get("nonce") ?? undefined,
      scope,
      user,
      authTime: Math.floor(now / 1000),
      expires: now + CODE_TTL_MS,
    });
    back.searchParams.set("code", code);
    back.searchParams.set("state", state);
    redirect(res, back);
  }

  function clientAuth(req, form) {
    let id = form.get("client_id");
    let secret = form.get("client_secret");
    const header = req.headers.authorization;
    if (header?.startsWith("Basic ")) {
      const decoded = Buffer.from(header.slice(6), "base64").toString();
      const i = decoded.indexOf(":");
      if (i < 0) return undefined;
      id = formDecode(decoded.slice(0, i));
      secret = formDecode(decoded.slice(i + 1));
    }
    const client = clients.get(id ?? "");
    return client && secret && sameSecret(secret, client.secret)
      ? client
      : undefined;
  }

  // Entra's sub is pairwise: the same user has a different sub at each client.
  const subjectFor = (realm, user, client) =>
    realm.kind === "entra"
      ? createHash("sha256")
          .update(`${user.sub}\0${client.id}`)
          .digest("base64url")
          .slice(0, 43)
      : user.sub;

  // Entra puts a pointer to Graph in place of `groups` once a user has too many to fit in the token.
  function groupClaims(realm, user) {
    const groups = user.claims.groups;
    if (
      realm.kind !== "entra" ||
      !Array.isArray(groups) ||
      groups.length <= realm.groupOverageLimit
    )
      return {};
    return {
      groups: undefined,
      _claim_names: { groups: "src1" },
      _claim_sources: {
        src1: {
          endpoint: `${baseUrl}/entra/graph/v1.0/users/${user.claims.oid}/getMemberObjects`,
        },
      },
    };
  }

  function accessToken(realm, client, user, scope) {
    if (realm.kind === "entra")
      return sign(
        realm,
        { tid: realm.id, oid: user.claims.oid, scp: scope, ver: "2.0" },
        user.claims.oid,
        GRAPH_AUDIENCE,
      );
    if (realm.kind === "okta")
      // Okta's access token `sub` is the login, not the user ID the ID token carries.
      return sign(
        realm,
        {
          ver: 1,
          cid: client.id,
          uid: user.sub,
          scp: scope.split(" "),
          groups: user.claims.groups,
        },
        user.login,
        realm.audience,
      );
    return sign(
      realm,
      { client_id: client.id, scope },
      user.sub,
      realm.audience,
    );
  }

  async function token(realm, req, res) {
    const form = new URLSearchParams(await readBody(req));
    const client = clientAuth(req, form);
    if (!client)
      return json(
        res,
        401,
        { error: "invalid_client" },
        { "www-authenticate": "Basic" },
      );
    const grant = form.get("grant_type");
    if (grant === "authorization_code") {
      const code = form.get("code") ?? "";
      const entry = codes.get(code);
      codes.delete(code);
      if (
        !entry ||
        entry.realm !== realm ||
        entry.expires < Date.now() ||
        entry.clientId !== client.id ||
        form.get("redirect_uri") !== entry.redirectUri ||
        sha256(form.get("code_verifier") ?? "") !== entry.challenge
      )
        return json(res, 400, { error: "invalid_grant" });
      const { user } = entry;
      const idClaims = JSON.parse(
        JSON.stringify({
          ...user.claims,
          ...groupClaims(realm, user),
          auth_time: entry.authTime,
          nonce: entry.nonce,
        }),
      );
      return json(res, 200, {
        token_type: "Bearer",
        expires_in: TOKEN_TTL_S,
        scope: entry.scope,
        id_token: await sign(
          realm,
          idClaims,
          subjectFor(realm, user, client),
          client.id,
        ),
        access_token: await accessToken(realm, client, user, entry.scope),
      });
    }
    if (grant === "client_credentials") {
      const scope = form.get("scope") ?? "";
      let aud = realm.audience;
      let claims;
      if (realm.kind === "entra") {
        const m = /^(\S+)\/\.default$/.exec(scope);
        if (!m) return json(res, 400, { error: "invalid_scope" });
        aud = m[1];
        claims = { tid: realm.id, azp: client.id, ver: "2.0" };
      } else if (realm.kind === "okta") {
        claims = { ver: 1, cid: client.id, scp: scope ? scope.split(" ") : [] };
      } else {
        claims = { client_id: client.id, scope };
      }
      return json(res, 200, {
        token_type: "Bearer",
        expires_in: TOKEN_TTL_S,
        access_token: await sign(realm, claims, client.id, aud),
      });
    }
    return json(res, 400, { error: "unsupported_grant_type" });
  }

  async function graph(req, res, oid) {
    await readBody(req);
    const header = req.headers.authorization ?? "";
    if (!header.startsWith("Bearer "))
      return json(res, 401, { error: { code: "InvalidAuthenticationToken" } });
    for (const realm of realms) {
      if (realm.kind !== "entra") continue;
      let verified = false;
      try {
        await jwtVerify(header.slice(7), realm.keySet, {
          issuer: realm.iss,
          audience: GRAPH_AUDIENCE,
          algorithms: ["RS256"],
        });
        verified = true;
      } catch {}
      if (!verified) continue;
      const user = realm.users.find((u) => u.claims.oid === oid);
      if (!user)
        return json(res, 404, { error: { code: "Request_ResourceNotFound" } });
      return json(res, 200, { value: user.claims.groups ?? [] });
    }
    return json(res, 401, { error: { code: "InvalidAuthenticationToken" } });
  }

  async function rotate(realm, res) {
    realm.keys.unshift(await newKey());
    realm.keys.length = Math.min(realm.keys.length, MAX_KEYS);
    json(res, 200, {
      kid: realm.keys[0].kid,
      published: realm.keys.map((k) => k.kid),
    });
  }

  return {
    // Returns false when the path is not one of the provider mocks.
    async handle(req, res, url) {
      const g = GRAPH.exec(url.pathname);
      const route = routes.get(url.pathname);
      if (!g && !route) return false;
      try {
        if (g) {
          if (req.method !== "POST")
            json(res, 405, { error: "method_not_allowed" });
          else await graph(req, res, g[1]);
          return true;
        }
        const { realm, ep } = route;
        const method = {
          discovery: "GET",
          jwks: "GET",
          authorize: "GET",
          token: "POST",
          rotate: "POST",
        }[ep];
        if (req.method !== method)
          json(res, 405, { error: "method_not_allowed" });
        else if (ep === "discovery")
          json(res, 200, discovery(realm), { "cache-control": "max-age=60" });
        else if (ep === "jwks")
          json(
            res,
            200,
            { keys: realm.keys.map((k) => k.jwk) },
            { "cache-control": "max-age=60" },
          );
        else if (ep === "authorize") authorize(realm, url, res);
        else if (ep === "token") await token(realm, req, res);
        else await rotate(realm, res);
      } catch (err) {
        if (!(err instanceof BadRequest)) console.error(err);
        if (!res.headersSent)
          json(res, err instanceof BadRequest ? 400 : 500, {
            error:
              err instanceof BadRequest ? "invalid_request" : "server_error",
          });
      }
      return true;
    },
  };
}
