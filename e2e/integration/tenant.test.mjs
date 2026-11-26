import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

const site = "http://acme.bae6.localhost:8091";
const authz = "http://127.0.0.1:8080";
const runtime = process.env.BAE6_CONTAINER_RUNTIME ?? "podman";
const inside = (container, ...args) =>
  execFileSync(runtime, ["exec", container, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

async function signIn(login) {
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

const consoleSecret = () =>
  inside("bae6-console-1", "cat", "/run/secrets/authn/authn-client-secret");

async function authzToken(session, secret) {
  const res = await fetch(`${site}/auth/token`, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}` },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: session,
      subject_token_type: "urn:bae6:params:oauth:token-type:session",
      audience: "bae6-authz",
    }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()).access_token;
}

function bootstrapRoot(admin) {
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

const call = async (jwt, method, path, body) => {
  const res = await fetch(`${authz}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${jwt}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : null,
  });
  return res.status;
};

const allowed = async (jwt, resourceId) => {
  const res = await fetch(`${authz}/v1/tenant/check`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${jwt}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ resourceType: "model", resourceId }),
  });
  assert.equal(res.status, 200);
  return (await res.json()).allowed;
};

test("authn tokens get tenant decisions, a delegated admin cannot escalate, and a block applies on the next check", async () => {
  const alice = await signIn("alice@acme.example");
  const bob = await signIn("bob@acme.example");
  bootstrapRoot(alice.subject);
  const secret = consoleSecret();
  const admin = await authzToken(alice.session, secret);
  const user = await authzToken(bob.session, secret);
  const run = randomBytes(4).toString("hex");
  const unit = `e2e-${run}`;
  const model = `e2e-${run}`;
  const bobSubject = encodeURIComponent(bob.subject);

  assert.equal(await allowed(user, model), false);
  assert.equal(
    await call(user, "POST", "/v1/tenant/units", { unit, parent: "acme" }),
    403,
  );

  assert.equal(
    await call(admin, "POST", "/v1/tenant/units", { unit, parent: "acme" }),
    201,
  );
  assert.equal(
    await call(admin, "PUT", `/v1/tenant/units/${unit}/ceilings/access`),
    200,
  );
  assert.equal(
    await call(
      admin,
      "PUT",
      `/v1/tenant/units/${unit}/admins/access/${bobSubject}`,
    ),
    200,
  );
  assert.equal(
    await call(admin, "PUT", "/v1/tenant/resources/unit", {
      resourceType: "model",
      resourceId: model,
      unit,
    }),
    200,
  );

  for (const [method, path] of [
    ["PUT", `/v1/tenant/units/${unit}/admins/settings/${bobSubject}`],
    ["PUT", `/v1/tenant/units/acme/admins/access/${bobSubject}`],
    ["PUT", `/v1/tenant/units/${unit}/ceilings/settings`],
    ["DELETE", `/v1/tenant/units/${unit}/ceilings/access`],
    ["PUT", `/v1/tenant/units/${unit}/guardrails/model_invoke/blocklist/user:*`],
  ])
    assert.equal(await call(user, method, path), 403, `${method} ${path}`);

  assert.equal(
    await call(
      user,
      "PUT",
      `/v1/tenant/resources/model/${model}/access/${bobSubject}`,
    ),
    200,
  );
  assert.equal(await allowed(user, model), true);
  const gateway = await fetch(`${authz}/v1/tenant/ext-authz/v1/chat`, {
    headers: {
      authorization: `Bearer ${user}`,
      "bae6-resource": `model:${model}`,
    },
  });
  assert.equal(gateway.status, 200);

  const block = `/v1/tenant/units/acme/guardrails/model_invoke/blocklist/${bobSubject}`;
  assert.equal(await call(admin, "PUT", block), 200);
  try {
    assert.equal(await allowed(user, model), false);
  } finally {
    assert.equal(await call(admin, "DELETE", block), 200);
  }
  assert.equal(await allowed(user, model), true);
});
