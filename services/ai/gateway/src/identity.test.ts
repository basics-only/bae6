import assert from "node:assert/strict";
import { test } from "node:test";
import type { Verdict } from "@bae6/authz/middleware";
import { fromGuard } from "./identity.js";

const jwt = (claims: object) =>
  `Bearer e30.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
const resource = { resourceType: "api", resourceId: "ai-invoke" } as const;
const context = {
  tenantId: "acme",
  orgPath: ["acme"],
  principalId: "prn_1",
  principalType: "service",
  actorId: "prn_1",
  requestId: "r",
};

function guarded(verdict: Verdict) {
  const seen: (string | undefined)[] = [];
  const authorize = fromGuard(async (authorization) => {
    seen.push(authorization);
    return verdict;
  });
  return { authorize, seen };
}

test("a token for another audience is unauthenticated without asking authn", async () => {
  const { authorize, seen } = guarded({ allowed: true });
  for (const bearer of [
    jwt({ aud: "data-api" }),
    jwt({ aud: ["bae6-ai"] }),
    "Bearer garbage",
    undefined,
  ]) {
    const decision = await authorize(bearer, resource);
    assert.equal(decision.allowed ? 200 : decision.status, 401, bearer);
  }
  assert.deepEqual(seen, []);
});

test("an allowed context becomes the caller, and one without an application is forbidden", async () => {
  const bearer = jwt({ aud: "bae6-ai" });
  const ok = await guarded({
    allowed: true,
    executionContext: { ...context, applicationId: "demo" },
  }).authorize(bearer, resource);
  assert.deepEqual(ok, {
    allowed: true,
    who: {
      subjectId: "prn_1",
      subjectType: "workload",
      organizationId: "acme",
      applicationId: "demo",
    },
  });
  const none = await guarded({
    allowed: true,
    executionContext: context,
  }).authorize(bearer, resource);
  assert.equal(none.allowed ? 200 : none.status, 403);
});
