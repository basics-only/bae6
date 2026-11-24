import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { transformer } from "@openfga/syntax-transformer";
import autocannon from "autocannon";

const openfga = process.env.OPENFGA_API_URL;
if (!openfga) throw new Error("OPENFGA_API_URL is required");
const seconds = Number(process.env.LOAD_SECONDS ?? 5);
const depths = [
  ...new Set(
    (process.env.TENANT_DEPTHS ?? "1,8,16,24,25,26,32").split(",").map(Number),
  ),
];
const MAX_DEPTH = 22;
if (depths.some((d) => !Number.isInteger(d) || d < 1))
  throw new Error("TENANT_DEPTHS must be positive integers");

async function call(path: string, body: unknown) {
  const res = await fetch(`${openfga}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json()) as Record<string, unknown>;
  return { status: res.status, json };
}

async function ok(path: string, body: unknown) {
  const r = await call(path, body);
  if (r.status < 200 || r.status > 299)
    throw new Error(`${path}: ${r.status} ${JSON.stringify(r.json)}`);
  return r.json;
}

type Tuple = { user: string; relation: string; object: string };

const model = transformer.transformDSLToJSONObject(
  readFileSync(
    new URL("../../models/openfga/tenant.fga", import.meta.url),
    "utf8",
  ),
);
const store = (
  await ok("/stores", { name: `depth${randomBytes(4).toString("hex")}` })
).id as string;
const dropStore = () =>
  fetch(`${openfga}/stores/${store}`, { method: "DELETE" });
const modelId = (
  await ok(`/stores/${store}/authorization-models`, model).catch(
    async (err) => {
      await dropStore();
      throw err;
    },
  )
).authorization_model_id as string;

async function write(tuples: Tuple[]) {
  for (let i = 0; i < tuples.length; i += 100)
    await ok(`/stores/${store}/write`, {
      authorization_model_id: modelId,
      writes: { tuple_keys: tuples.slice(i, i + 100) },
    });
}

function chain(depth: number): Tuple[] {
  const node = (i: number) => `org_unit:d${depth}n${i}`;
  const tuples: Tuple[] = [
    { user: "user:*", relation: "is_root", object: node(0) },
    {
      user: "user:carl",
      relation: "model_invoke_blocklist",
      object: node(0),
    },
    { user: node(depth - 1), relation: "unit", object: `model:d${depth}` },
    { user: "user:alice", relation: "invoker", object: `model:d${depth}` },
    { user: "user:carl", relation: "invoker", object: `model:d${depth}` },
    { user: "user:boss", relation: "access_admin_grant", object: node(0) },
    {
      user: "group:ops#member",
      relation: "access_admin_grant",
      object: node(0),
    },
    { user: node(depth - 1), relation: "unit", object: `tool:d${depth}` },
    { user: "user:hank", relation: "invoker", object: `tool:d${depth}` },
    { user: "user:nobody", relation: "invoker", object: `tool:d${depth}` },
  ];
  for (let i = 0; i < depth; i++) {
    tuples.push({
      user: "group:staff#member",
      relation: "tool_invoke_allowlist",
      object: node(i),
    });
    tuples.push({
      user: "user:*",
      relation: "model_invoke_allowlist",
      object: node(i),
    });
    tuples.push({
      user: "user:*",
      relation: "access_admin_ceiling",
      object: node(i),
    });
    if (i > 0)
      tuples.push({ user: node(i - 1), relation: "parent", object: node(i) });
  }
  return tuples;
}

const checkBody = (user: string, depth: number) => ({
  authorization_model_id: modelId,
  tuple_key: { user, relation: "can_invoke", object: `model:d${depth}` },
});

function probes(depth: number) {
  const leaf = `org_unit:d${depth}n${depth - 1}`;
  const hasParent = depth > 1;
  return [
    ["user:alice", "can_invoke", `model:d${depth}`, true],
    ["user:carl", "can_invoke", `model:d${depth}`, false],
    ["user:boss", "can_grant_access_admin", leaf, true],
    ["user:boss", "can_set_access_admin_ceiling", leaf, hasParent],
    ["user:gina", "can_grant_access_admin", leaf, true],
    ["user:gina", "can_set_access_admin_ceiling", leaf, hasParent],
    ["user:alice", "can_grant_access_admin", leaf, false],
    ["user:hank", "can_invoke", `tool:d${depth}`, true],
    ["user:nobody", "can_invoke", `tool:d${depth}`, false],
  ] as const;
}

await write([
  { user: "user:gina", relation: "member", object: "group:ops" },
  { user: "user:hank", relation: "member", object: "group:all" },
  { user: "group:all#member", relation: "member", object: "group:staff" },
]);
console.log(
  "| depth | probes | connections | req/s | p50 ms | p99 ms | failed |",
);
console.log("| ---: | --- | ---: | ---: | ---: | ---: | ---: |");
try {
  for (const depth of depths) {
    await write(chain(depth));
    const results = [];
    for (const [user, relation, object, expected] of probes(depth)) {
      const r = await call(`/stores/${store}/check`, {
        authorization_model_id: modelId,
        tuple_key: { user, relation, object },
      });
      const got =
        r.status === 200
          ? String(r.json.allowed)
          : `${r.status} ${String(r.json.code ?? "")}`;
      if (depth <= MAX_DEPTH && got !== String(expected))
        throw new Error(
          `depth ${depth}: ${user} ${relation} ${object}: expected ${expected}, got ${got}`,
        );
      if (
        depth > MAX_DEPTH &&
        relation === "can_invoke" &&
        user === "user:hank" &&
        r.status === 200
      )
        throw new Error(
          `depth ${depth}: ${user} ${relation} resolved, so the ${MAX_DEPTH} cap is stale`,
        );
      results.push(got);
    }
    const summary =
      depth <= MAX_DEPTH ? "all correct" : [...new Set(results)].join(", ");
    for (const connections of [1, 16]) {
      const r = await autocannon({
        url: openfga,
        connections,
        duration: seconds,
        requests: ["user:alice", "user:carl"].map((user) => ({
          method: "POST" as const,
          path: `/stores/${store}/check`,
          headers: { "content-type": "application/json" },
          body: JSON.stringify(checkBody(user, depth)),
        })),
      });
      console.log(
        `| ${depth} | ${summary} | ${connections} | ${Math.round(r.requests.average)} | ${r.latency.p50} | ${r.latency.p99} | ${r.errors + r.timeouts + r.non2xx} |`,
      );
    }
  }
} finally {
  await dropStore();
}
