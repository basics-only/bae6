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

test("a session cookie authn never issued is no session", async () => {
  const forged = `__Host-bae6-session=${"A".repeat(43)}`;
  const home = await get("/applications", forged);
  assert.equal(home.status, 303);
  assert.equal(home.headers.get("location"), "/login");
});
