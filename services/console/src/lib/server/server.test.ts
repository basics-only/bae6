import assert from "node:assert/strict";
import { test } from "node:test";
import { Authn, AuthnAuthError, AuthnValidationError } from "@bae6/authn";
import { UnsecuredJWT } from "jose";
import { type ApiError, apiJson } from "./api.js";
import { crossSiteMutation, loginRedirect } from "./guard.js";
import { resolveSession, tokenCache, tokenFor } from "./session.js";

const COOKIE = "session-cookie-value";

/** An authn token endpoint that knows one live session and the audiences it may mint for. */
function fakeAuthn(opts: { live?: boolean; secret?: string } = {}) {
  const seen: URLSearchParams[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    const form = new URLSearchParams(String(init.body));
    seen.push(form);
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status });
    if (
      new Headers(init.headers).get("authorization") !== "Bearer console-secret"
    )
      return reply(401, { error: "invalid_client" });
    if (!["bae6-authn", "bae6-authz"].includes(form.get("audience") ?? ""))
      return reply(400, { error: "invalid_target" });
    if (!(opts.live ?? true) || form.get("subject_token") !== COOKIE)
      return reply(400, { error: "invalid_request" });
    return reply(200, {
      access_token: new UnsecuredJWT({ aud: form.get("audience") ?? "" })
        .setSubject("prn_anne")
        .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
        .encode(),
      issued_token_type: "urn:ietf:params:oauth:token-type:jwt",
      token_type: "Bearer",
      expires_in: 300,
    });
  }) as typeof fetch;
  const authn = new Authn({
    baseUrl: "http://authn",
    credentials: opts.secret ?? "console-secret",
    fetch: fetchImpl,
    maxRetries: 0,
  });
  return { authn, seen };
}

test("a live authn session resolves to its principal", async () => {
  const { authn, seen } = fakeAuthn();
  assert.deepEqual(await resolveSession(authn, COOKIE), {
    cookie: COOKIE,
    subject: "prn_anne",
  });
  assert.equal(
    seen[0]?.get("subject_token_type"),
    "urn:bae6:params:oauth:token-type:session",
  );
});

test("no cookie, or one authn no longer honours, is no session", async () => {
  const { authn, seen } = fakeAuthn({ live: false });
  assert.equal(await resolveSession(authn, undefined), null);
  assert.equal(seen.length, 0);
  assert.equal(await resolveSession(authn, COOKIE), null);
  assert.equal(await tokenFor(authn, COOKIE, "bae6-authz"), null);
});

test("misconfiguration fails loudly instead of looking like a signed-out user", async () => {
  await assert.rejects(
    resolveSession(fakeAuthn({ secret: "wrong" }).authn, COOKIE),
    AuthnAuthError,
  );
  await assert.rejects(
    tokenFor(fakeAuthn().authn, COOKIE, "unknown-service"),
    AuthnValidationError,
  );
});

test("each service gets a token minted for its own audience", async () => {
  const { authn, seen } = fakeAuthn();
  const token = await tokenFor(authn, COOKIE, "bae6-authz");
  assert.ok(token);
  assert.equal(seen[0]?.get("audience"), "bae6-authz");
  assert.equal(seen[0]?.get("subject_token"), COOKIE);
});

test("a service token is reused until shortly before it expires, per session and audience", async () => {
  const { authn, seen } = fakeAuthn();
  let clock = Date.now();
  const tokens = tokenCache(authn, () => clock);
  const first = await tokens(COOKIE, "bae6-authz");
  assert.equal(await tokens(COOKIE, "bae6-authz"), first);
  assert.equal(seen.length, 1);
  await tokens(COOKIE, "bae6-authn");
  assert.equal(seen.length, 2);
  clock += 280_000;
  await tokens(COOKIE, "bae6-authz");
  assert.equal(seen.length, 3);
});

test("a session authn no longer honours is not served from the cache", async () => {
  const { authn, seen } = fakeAuthn({ live: false });
  const tokens = tokenCache(authn);
  assert.equal(await tokens(COOKIE, "bae6-authz"), null);
  assert.equal(await tokens(COOKIE, "bae6-authz"), null);
  assert.equal(seen.length, 2);
});

test("only the public pages are reachable without a session", () => {
  const session = { cookie: "c", subject: "a" };
  assert.equal(loginRedirect("/applications", null), "/login");
  assert.equal(loginRedirect("/", null), "/login");
  assert.equal(loginRedirect("/login", null), null);
  assert.equal(loginRedirect("/signed-out", null), null);
  assert.equal(loginRedirect("/auth/callback", null), "/login");
  assert.equal(loginRedirect("/applications", session), null);
});

test("a mutation from another origin is refused, reads are not", () => {
  const own = "https://console.example";
  assert.equal(crossSiteMutation("POST", "https://evil.example", own), true);
  assert.equal(crossSiteMutation("DELETE", null, own), true);
  assert.equal(crossSiteMutation("POST", own, own), false);
  assert.equal(crossSiteMutation("GET", null, own), false);
});

test("the API is called with the user's token and failures keep their status", async () => {
  const seen: { url: string; auth: string | null }[] = [];
  const stub = (async (url: string, init: RequestInit) => {
    seen.push({
      url,
      auth: new Headers(init.headers).get("authorization"),
    });
    return url.endsWith("/forbidden")
      ? new Response(JSON.stringify({ code: "forbidden", message: "no" }), {
          status: 403,
        })
      : new Response(JSON.stringify({ items: [] }), { status: 200 });
  }) as typeof fetch;
  const session = { accessToken: "tok" };

  assert.deepEqual(
    await apiJson("http://api", session, "/v1/applications", {}, stub),
    { items: [] },
  );
  assert.equal(seen[0]?.auth, "Bearer tok");
  await assert.rejects(
    apiJson("http://api", session, "/forbidden", {}, stub),
    (err: ApiError) => err.status === 403 && err.code === "forbidden",
  );
});
