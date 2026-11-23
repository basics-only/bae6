import assert from "node:assert/strict";
import { test } from "node:test";

const console_ = "http://localhost:8091";

const get = (path, cookie) =>
  fetch(`${console_}${path}`, {
    redirect: "manual",
    headers: cookie ? { cookie } : {},
  });

test("a signed-out operator is sent to the sign-in page", async () => {
  const home = await get("/");
  assert.equal(home.status, 303);
  assert.equal(home.headers.get("location"), "/login");
  assert.equal((await get("/login")).status, 200);
});

test("an operator signs in through the mock IdP, uses the console, and signs out", async () => {
  const site = "http://acme.bae6.localhost:8091";
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

  const providers = await (await send(`${site}/auth/providers`)).json();
  assert.ok(providers.providers.some((p) => p.id === "entra"));
  const begin = await send(`${site}/auth/login/entra?returnTo=/`);
  assert.equal(begin.status, 302);
  const idp = await send(begin.headers.get("location"));
  assert.equal(idp.status, 302);
  const callback = idp.headers.get("location");
  assert.ok(callback.startsWith(`${site}/auth/callback/entra?`));
  const done = await send(callback);
  assert.equal(done.status, 303);
  assert.equal(done.headers.get("location"), "/");

  assert.equal((await send(`${site}/`)).status, 200);
  const out = await send(`${site}/auth/logout`, {
    method: "POST",
    headers: { origin: site, "x-csrf-token": jar.get("__Host-bae6-csrf") },
  });
  assert.equal(out.status, 204);
  const after = await send(`${site}/`);
  assert.equal(after.status, 303);
  assert.equal(after.headers.get("location"), "/login");
});

test("a session cookie authn never issued is no session", async () => {
  const forged = `__Host-bae6-session=${"A".repeat(43)}`;
  const home = await get("/applications", forged);
  assert.equal(home.status, 303);
  assert.equal(home.headers.get("location"), "/login");
});
