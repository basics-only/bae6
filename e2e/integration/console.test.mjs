import assert from "node:assert/strict";
import { test } from "node:test";

const console_ = "http://localhost:8091";

const get = (url, cookie) =>
  fetch(url, {
    redirect: "manual",
    headers: cookie ? { cookie } : {},
  });

const cookieOf = (res) =>
  res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");

async function startLogin() {
  const login = await get(`${console_}/login`);
  assert.equal(login.status, 303);
  const authorize = await get(login.headers.get("location"));
  assert.equal(authorize.status, 302);
  return {
    cookie: cookieOf(login),
    callback: authorize.headers.get("location"),
  };
}

test("an operator signs in through the OIDC authorization-code flow", async () => {
  const { cookie, callback } = await startLogin();
  const done = await get(callback, cookie);
  assert.equal(done.status, 303);
  const session = cookieOf(done);
  assert.match(session, /^[^=]+=.+/);
  const page = await get(`${console_}/`, session);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /dev-operator/);
});

test("a login response with a different state is refused", async () => {
  const { cookie, callback } = await startLogin();
  const forged = new URL(callback);
  forged.searchParams.set("state", "forged");
  assert.equal((await get(forged, cookie)).status, 401);
});

test("an authorization code works once", async () => {
  const { cookie, callback } = await startLogin();
  assert.equal((await get(callback, cookie)).status, 303);
  assert.equal((await get(callback, cookie)).status, 401);
});
