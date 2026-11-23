// Development-only OIDC issuer: serves a JWKS and mints tokens on request.
// Anyone who can reach it can mint any identity, so it refuses production and must never be exposed.
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createIdp } from "./idp.mjs";

if (process.env.NODE_ENV === "production")
  throw new Error("mock-oidc must not run in production");
const issuer = process.env.MOCK_OIDC_ISSUER;
if (!issuer)
  throw new Error(
    "MOCK_OIDC_ISSUER is required (the iss value services trust)",
  );

async function newIssuer(iss) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  return {
    iss,
    privateKey,
    jwks: JSON.stringify({
      keys: [{ ...jwk, kid: "mock-1", alg: "RS256", use: "sig" }],
    }),
  };
}

const root = await newIssuer(issuer);

// `/orgs/<org>/...` is a separate issuer with its own key, so one container can stand in for many tenants.
const ORG = /^\/orgs\/([a-z0-9][a-z0-9-]{0,62})(\/.*)$/;
const MAX_ORGS = 64;
const orgs = new Map();
async function orgIssuer(org) {
  if (!orgs.has(org)) {
    if (orgs.size >= MAX_ORGS) return undefined;
    orgs.set(org, newIssuer(`${issuer}/orgs/${org}`));
  }
  return orgs.get(org);
}

async function body(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 4096) throw new Error("too large");
  }
  return raw;
}

// A client-credentials form has a fixed audience; anything else is the JSON request.
function clientCredentials(raw) {
  const aud = process.env.MOCK_OIDC_CLIENT_AUDIENCE;
  if (!aud) throw new Error("MOCK_OIDC_CLIENT_AUDIENCE is not set");
  const form = new URLSearchParams(raw);
  if (form.get("grant_type") !== "client_credentials")
    throw new Error("unsupported grant_type");
  return {
    sub: form.get("client_id") ?? undefined,
    aud,
    scope: form.get("scope") ?? undefined,
  };
}

const sign = (claims, sub, aud, ttlSeconds, from = root) =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "mock-1" })
    .setIssuer(from.iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .sign(from.privateKey);

// Browser login: only on when MOCK_OIDC_PUBLIC_URL (how the browser reaches this server) is set. It signs in
// MOCK_OIDC_LOGIN_SUBJECT without asking, so it is for local development only.
const publicUrl = process.env.MOCK_OIDC_PUBLIC_URL;
const loginSubject = process.env.MOCK_OIDC_LOGIN_SUBJECT ?? "dev-operator";
const loginRedirect = process.env.MOCK_OIDC_REDIRECT_URI;
const codes = new Map();
const MAX_CODES = 100;

// The provider mocks sign users in without asking too, so they share the browser-login opt-in.
const idp = publicUrl
  ? await createIdp({
      baseUrl: issuer,
      publicUrl,
      config: JSON.parse(
        readFileSync(
          process.env.MOCK_IDP_CONFIG ??
            new URL("./providers.json", import.meta.url),
          "utf8",
        ),
      ),
    })
  : undefined;

function authorize(url, send, res) {
  const q = url.searchParams;
  if (
    q.get("response_type") !== "code" ||
    q.get("code_challenge_method") !== "S256" ||
    q.get("redirect_uri") !== loginRedirect ||
    !q.get("client_id") ||
    !q.get("code_challenge")
  )
    return send(400, { code: "invalid_request", requestId: "mock" });
  const now = Date.now();
  for (const [k, v] of codes) if (v.expires < now) codes.delete(k);
  if (codes.size >= MAX_CODES)
    return send(429, { code: "rate_limited", requestId: "mock" });
  const code = randomBytes(24).toString("base64url");
  codes.set(code, {
    clientId: q.get("client_id"),
    challenge: q.get("code_challenge"),
    nonce: q.get("nonce"),
    audience: q.get("audience") ?? q.get("client_id"),
    expires: now + 60_000,
  });
  const back = new URL(loginRedirect);
  back.searchParams.set("code", code);
  back.searchParams.set("state", q.get("state") ?? "");
  res.writeHead(302, { location: back.toString() });
  res.end();
}

async function exchange(form, send) {
  const entry = codes.get(form.get("code") ?? "");
  codes.delete(form.get("code") ?? "");
  const verifier = form.get("code_verifier") ?? "";
  if (
    !entry ||
    entry.expires < Date.now() ||
    entry.clientId !== form.get("client_id") ||
    form.get("redirect_uri") !== loginRedirect ||
    createHash("sha256").update(verifier).digest("base64url") !==
      entry.challenge
  )
    return send(400, { error: "invalid_grant" });
  send(200, {
    token_type: "Bearer",
    access_token: await sign(
      { scope: process.env.MOCK_OIDC_LOGIN_SCOPE ?? "" },
      loginSubject,
      entry.audience,
      300,
    ),
    id_token: await sign(
      { nonce: entry.nonce },
      loginSubject,
      entry.clientId,
      300,
    ),
  });
}

createServer(async (req, res) => {
  const send = (status, value) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(typeof value === "string" ? value : JSON.stringify(value));
  };
  const url = new URL(req.url, "http://mock");
  if (idp && (await idp.handle(req, res, url))) return;
  const org = ORG.exec(url.pathname);
  const from = org ? await orgIssuer(org[1]) : root;
  if (!from) return send(429, { code: "too_many_orgs", requestId: "mock" });
  const path = org ? org[2] : req.url;
  if (!org && publicUrl && req.method === "GET") {
    if (url.pathname === "/.well-known/openid-configuration")
      return send(200, {
        issuer,
        authorization_endpoint: `${publicUrl}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      });
    if (url.pathname === "/authorize") return authorize(url, send, res);
  }
  if (req.method === "GET" && path === "/.well-known/jwks.json")
    return send(200, from.jwks);
  if (req.method === "GET" && req.url === "/health/live")
    return send(200, { status: "ok" });
  if (req.method !== "POST" || path !== "/token")
    return send(404, {
      code: "not_found",
      message: "Not found.",
      requestId: "mock",
    });
  try {
    const raw = await body(req);
    const form = raw !== "" && !raw.trimStart().startsWith("{");
    if (
      !org &&
      publicUrl &&
      form &&
      new URLSearchParams(raw).get("grant_type") === "authorization_code"
    )
      return await exchange(new URLSearchParams(raw), send);
    const {
      sub,
      aud,
      scope,
      claims = {},
      ttlSeconds = 300,
    } = form ? clientCredentials(raw) : JSON.parse(raw || "{}");
    if (
      typeof sub !== "string" ||
      typeof aud !== "string" ||
      !Number.isInteger(ttlSeconds) ||
      ttlSeconds < -3600 ||
      ttlSeconds > 3600
    ) {
      return send(400, {
        code: "invalid_request",
        message: "sub and aud are required; ttlSeconds in [-3600, 3600].",
        requestId: "mock",
      });
    }
    const token = await sign(
      { ...claims, ...(scope ? { scope } : {}) },
      sub,
      aud,
      ttlSeconds,
      from,
    );
    send(200, {
      access_token: token,
      token_type: "Bearer",
      ...(form ? { expires_in: ttlSeconds } : {}),
    });
  } catch {
    send(400, {
      code: "invalid_request",
      message: "Body must be JSON under 4 KiB.",
      requestId: "mock",
    });
  }
}).listen(Number(process.env.PORT ?? 8080), "0.0.0.0");
