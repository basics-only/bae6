// Dev data for acme: alice is root admin; alice, bob and the demo workloads may use the models; some usage exists.
import { authzToken, bootstrapRoot, consoleSecret, signIn } from "./acme.mjs";

const authz = "http://127.0.0.1:8080";
const ai = "http://127.0.0.1:8081";
const embedWorker = "service:prn_d0000000000000000000000000000001";
const researchAgent = "service:prn_d0000000000000000000000000000002";

async function send(base, jwt, method, path, body, headers = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${jwt}`,
      ...(body ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : null,
  });
  return { status: res.status, text: await res.text() };
}

async function expect(statuses, what, call) {
  const res = await call;
  if (!statuses.includes(res.status))
    throw new Error(`${what}: ${res.status} ${res.text.slice(0, 300)}`);
}

const alice = await signIn("alice@acme.example");
const bob = await signIn("bob@acme.example");
bootstrapRoot(alice.subject);
const secret = consoleSecret();
const admin = await authzToken(alice.session, secret);

await expect(
  [201, 409],
  "unit ai",
  send(authz, admin, "POST", "/v1/tenant/units", {
    unit: "ai",
    parent: "acme",
  }),
);
await expect(
  [200, 409],
  "ai access ceiling",
  send(authz, admin, "PUT", "/v1/tenant/units/ai/ceilings/access"),
);

const people = [alice.subject, bob.subject];
const grants = {
  "api:ai-invoke": [...people, embedWorker, researchAgent],
  "api:ai-usage-read": [...people, researchAgent],
  "api:ai-usage-admin": [alice.subject],
  "api:feedback-write": people,
  "api:feedback-read": [alice.subject],
  "model:chat-mock": [...people, embedWorker, researchAgent],
  "model:embed-mock": [alice.subject, embedWorker],
};
for (const [resource, subjects] of Object.entries(grants)) {
  const [resourceType, resourceId] = resource.split(":");
  await expect(
    [200],
    `place ${resource}`,
    send(authz, admin, "PUT", "/v1/tenant/resources/unit", {
      resourceType,
      resourceId,
      unit: "ai",
    }),
  );
  for (const subject of subjects)
    await expect(
      [200, 409],
      `grant ${resource} to ${subject}`,
      send(
        authz,
        admin,
        "PUT",
        `/v1/tenant/resources/${resourceType}/${resourceId}/access/${encodeURIComponent(subject)}`,
      ),
    );
}

const usageOf = async (who) => authzToken(who.session, secret, "bae6-ai");
const aliceAi = await usageOf(alice);
for (const [kind, id, name] of [
  ["task-types", "summarize", "Summarize"],
  ["task-types", "draft", "Draft a reply"],
  ["domains", "finance", "Finance"],
  ["domains", "support", "Support"],
])
  await expect(
    [200],
    `${kind} ${id}`,
    send(ai, aliceAi, "PUT", `/v1/${kind}/${id}`, { name }),
  );

const calls = [
  [aliceAi, "summarize", "finance", "Summarize the expense policy."],
  [aliceAi, "draft", "support", "Draft a reply to a refund request."],
  [await usageOf(bob), "summarize", "support", "Summarize this ticket."],
];
for (const [jwt, taskType, domain, content] of calls)
  await expect(
    [200],
    `chat ${taskType}`,
    send(
      ai,
      jwt,
      "POST",
      "/v1/chat/completions",
      { model: "chat-mock", messages: [{ role: "user", content }] },
      { "bae6-task-type": taskType, "bae6-domain": domain },
    ),
  );

console.log(
  "Seeded acme. Sign in at http://acme.bae6.localhost:8091 as alice@acme.example (admin) or bob@acme.example.",
);
