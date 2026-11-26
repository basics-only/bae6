import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  authzToken,
  bootstrapRoot,
  consoleSecret,
  inside,
  signIn,
  site,
} from "../acme.mjs";

const authz = "http://127.0.0.1:8080";

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
    [
      "PUT",
      `/v1/tenant/units/${unit}/guardrails/model_invoke/blocklist/user:*`,
    ],
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

const authn = site;

const delegate = async (jwt, body) => {
  const res = await fetch(`${authn}/v1/delegations`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${jwt}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      taskId: "summarize",
      expiresInSeconds: 120,
      ...body,
    }),
  });
  return {
    status: res.status,
    body: res.status === 201 ? await res.json() : null,
  };
};

const checkStatus = async (jwt, resourceId) =>
  (
    await fetch(`${authz}/v1/tenant/check`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ resourceType: "model", resourceId }),
    })
  ).status;

test("an agent runs only with its delegated scope, cannot widen it or nest under a revoked delegation, and is refused once it expires", async () => {
  const alice = await signIn("alice@acme.example");
  const bob = await signIn("bob@acme.example");
  bootstrapRoot(alice.subject);
  const secret = consoleSecret();
  const admin = await authzToken(alice.session, secret);
  const user = await authzToken(bob.session, secret);
  const userAuthn = await authzToken(bob.session, secret, "bae6-authn");
  const run = randomBytes(4).toString("hex");
  const unit = `e2e-dlg-${run}`;
  const [inScope, outOfScope] = [`e2e-in-${run}`, `e2e-out-${run}`];
  const agentId = `prn_${randomBytes(16).toString("hex")}`;
  const agent = encodeURIComponent(`agent:${agentId}`);
  inside(
    "bae6-postgres-1",
    "psql",
    "-U",
    "postgres",
    "-d",
    "authn",
    "-v",
    "ON_ERROR_STOP=1",
    "-c",
    `INSERT INTO principals (id, tenant_id, type, owner_application_id) VALUES ('${agentId}', 'acme', 'agent', 'e2e-helper')`,
  );

  assert.equal(
    await call(admin, "POST", "/v1/tenant/units", { unit, parent: "acme" }),
    201,
  );
  assert.equal(
    await call(admin, "PUT", `/v1/tenant/units/${unit}/ceilings/access`),
    200,
  );
  for (const model of [inScope, outOfScope]) {
    assert.equal(
      await call(admin, "PUT", "/v1/tenant/resources/unit", {
        resourceType: "model",
        resourceId: model,
        unit,
      }),
      200,
    );
    for (const subject of [encodeURIComponent(bob.subject), agent])
      assert.equal(
        await call(
          admin,
          "PUT",
          `/v1/tenant/resources/model/${model}/access/${subject}`,
        ),
        200,
      );
  }

  const scope = {
    actorPrincipalId: agentId,
    applicationId: "e2e-helper",
    allowedResources: [`model:${inScope}`],
    allowedActions: ["model:invoke"],
  };
  const root = await delegate(userAuthn, { ...scope, audience: "bae6-authz" });
  assert.equal(root.status, 201);
  const agentToken = root.body.token.access_token;
  assert.equal(await allowed(agentToken, inScope), true);
  assert.equal(await allowed(agentToken, outOfScope), false);
  assert.equal(await allowed(user, outOfScope), true);
  assert.equal(
    await call(agentToken, "POST", "/v1/tenant/units", {
      unit: `${unit}-x`,
      parent: "acme",
    }),
    403,
  );

  const agentAccess = `/v1/tenant/resources/model/${inScope}/access/${agent}`;
  assert.equal(await call(admin, "DELETE", agentAccess), 200);
  try {
    assert.equal(await allowed(agentToken, inScope), false);
  } finally {
    assert.equal(await call(admin, "PUT", agentAccess), 200);
  }
  const bobAccess = `/v1/tenant/resources/model/${inScope}/access/${encodeURIComponent(bob.subject)}`;
  assert.equal(await call(admin, "DELETE", bobAccess), 200);
  try {
    assert.equal(await allowed(agentToken, inScope), false);
  } finally {
    assert.equal(await call(admin, "PUT", bobAccess), 200);
  }

  const forAgent = await delegate(userAuthn, {
    ...scope,
    audience: "bae6-authn",
  });
  assert.equal(forAgent.status, 201);
  const agentAuthn = forAgent.body.token.access_token;
  const nested = {
    ...scope,
    parentDelegationId: forAgent.body.delegationId,
    audience: "bae6-authz",
    expiresInSeconds: 60,
  };
  assert.equal(
    (
      await delegate(agentAuthn, {
        ...nested,
        allowedResources: [`model:${outOfScope}`],
      })
    ).status,
    403,
  );
  assert.equal(
    (await delegate(agentAuthn, { ...nested, expiresInSeconds: 600 })).status,
    403,
  );
  assert.equal((await delegate(agentAuthn, nested)).status, 201);

  const revoked = await fetch(
    `${authn}/v1/delegations/${forAgent.body.delegationId}/revoke`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${userAuthn}` },
    },
  );
  assert.equal(revoked.status, 204);
  assert.equal((await delegate(agentAuthn, nested)).status, 404);

  const brief = await delegate(userAuthn, {
    ...scope,
    audience: "bae6-authz",
    expiresInSeconds: 5,
  });
  assert.equal(brief.status, 201);
  assert.equal(await allowed(brief.body.token.access_token, inScope), true);
  await new Promise((r) => setTimeout(r, 6000));
  assert.equal(await checkStatus(brief.body.token.access_token, inScope), 401);
});
