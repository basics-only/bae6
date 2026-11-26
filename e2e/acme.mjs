import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

export const site = "http://acme.bae6.localhost:8091";
const runtime = process.env.BAE6_CONTAINER_RUNTIME ?? "podman";
export const inside = (container, ...args) =>
  execFileSync(runtime, ["exec", container, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

export async function signIn(login) {
  const jar = new Map();
  const send = async (url, init = {}) => {
    const res = await fetch(url, {
      redirect: "manual",
      ...init,
      headers: {
        cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
        ...init.headers,
      },
    });
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = pair.indexOf("=");
      jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
    return res;
  };
  const begin = await send(`${site}/auth/login/entra?returnTo=/`);
  assert.equal(begin.status, 302, login);
  const authorize = new URL(begin.headers.get("location"));
  authorize.searchParams.set("login_hint", login);
  const idp = await send(authorize);
  assert.equal(idp.status, 302, login);
  assert.equal((await send(idp.headers.get("location"))).status, 303, login);
  const me = await send(`${site}/auth/me`);
  assert.equal(me.status, 200, login);
  const { principal } = await me.json();
  return {
    session: jar.get("__Host-bae6-session"),
    subject: `${principal.type}:${principal.id}`,
  };
}

export const consoleSecret = () =>
  inside("bae6-console-1", "cat", "/run/secrets/authn/authn-client-secret");

export async function authzToken(session, secret, audience = "bae6-authz") {
  const res = await fetch(`${site}/auth/token`, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}` },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: session,
      subject_token_type: "urn:bae6:params:oauth:token-type:session",
      audience,
    }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()).access_token;
}

/** A bae6 token for a workload the authn seed linked to the mock IdP. */
export async function workloadToken(subject, audience = "bae6-ai") {
  const idp = await fetch("http://127.0.0.1:8085/token", {
    method: "POST",
    body: JSON.stringify({ sub: subject, aud: "bae6-authn-workloads" }),
  });
  assert.equal(idp.status, 200);
  const res = await fetch("http://127.0.0.1:8092/auth/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: (await idp.json()).access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      audience,
    }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()).access_token;
}

export function bootstrapRoot(admin) {
  try {
    inside(
      "bae6-authz-api-1",
      "node",
      "dist/tenant/bootstrap-root.js",
      "--operator",
      "service:e2e",
      "--admin",
      admin,
    );
  } catch (err) {
    if (!String(err.stderr).includes("already has a root")) throw err;
  }
}
