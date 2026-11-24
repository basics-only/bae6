import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import {
  createDelegation,
  DelegationError,
  type DelegationLimits,
  type NewDelegation,
  revokeDelegation,
} from "./delegations.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const ALICE = `prn_${"a".repeat(32)}`;
const AGENT = `prn_${"b".repeat(32)}`;
const AGENT2 = `prn_${"c".repeat(32)}`;
const GONE = `prn_${"d".repeat(32)}`;
const STRANGER = `prn_${"e".repeat(32)}`;
let db: pg.Pool;
let close: () => Promise<void>;

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_dlg",
  ));
  await db.query(
    `INSERT INTO principals (id, tenant_id, type, owner_application_id, status)
     VALUES ($1, 'acme', 'user', null, 'active'),
            ($2, 'acme', 'agent', 'helper', 'active'),
            ($3, 'acme', 'agent', 'helper', 'active'),
            ($4, 'acme', 'agent', 'helper', 'disabled'),
            ($5, 'other', 'agent', 'helper', 'active')`,
    [ALICE, AGENT, AGENT2, GONE, STRANGER],
  );
});

after(async () => {
  if (!skip) await close?.();
});

const limits: DelegationLimits = {
  maxLifetimeSeconds: 3600,
  maxDepth: 3,
  highImpact: (action) => action === "model:delete",
};
const inMinutes = (m: number) => new Date(Date.now() + m * 60_000);
const soon = inMinutes(10);
const input = (over: Partial<NewDelegation> = {}): NewDelegation => ({
  tenantId: "acme",
  initiatingPrincipalId: ALICE,
  actorPrincipalId: AGENT,
  applicationId: "helper",
  taskId: "task-1",
  allowedResources: ["model:finance-llm", "dataset:ledger"],
  allowedActions: ["model:invoke", "dataset:read"],
  expiresAt: inMinutes(30),
  policyVersion: "01HZ",
  ...over,
});
const create = (over: Partial<NewDelegation> = {}) =>
  createDelegation(db, limits, input(over));
const refused = (p: Promise<unknown>, code: string) =>
  assert.rejects(
    p,
    (e: unknown) => e instanceof DelegationError && e.code === code,
  );
const revokedAt = async (id: string) =>
  (await db.query("SELECT revoked_at FROM delegations WHERE id = $1", [id]))
    .rows[0].revoked_at;

test(
  "a delegation is stored with its scope, expiry and policy version",
  { skip },
  async () => {
    const { id } = await create();
    assert.match(id, /^dlg_[0-9a-f]{32}$/);
    const { rows } = await db.query(
      "SELECT depth, allowed_actions, policy_version FROM delegations WHERE id = $1",
      [id],
    );
    assert.deepEqual(rows[0], {
      depth: 1,
      allowed_actions: ["model:invoke", "dataset:read"],
      policy_version: "01HZ",
    });
  },
);

test(
  "a delegation needs a bounded lifetime, a bounded scope and two distinct active principals of the tenant",
  { skip },
  async () => {
    await refused(create({ expiresAt: inMinutes(61) }), "exceeds_limit");
    await refused(create({ expiresAt: inMinutes(-1) }), "invalid_request");
    await refused(create({ expiresAt: new Date("nope") }), "invalid_request");
    await refused(create({ actorPrincipalId: ALICE }), "invalid_request");
    await refused(create({ allowedResources: [] }), "invalid_request");
    await refused(
      create({ allowedActions: ["model:invoke", "model:invoke"] }),
      "invalid_request",
    );
    await refused(
      create({ allowedResources: ["not a resource"] }),
      "invalid_request",
    );
    await refused(
      create({
        allowedResources: Array.from({ length: 101 }, (_, i) => `model:m${i}`),
      }),
      "invalid_request",
    );
    await refused(create({ actorPrincipalId: GONE }), "principal_inactive");
    await refused(create({ actorPrincipalId: STRANGER }), "unknown_principal");
    await refused(
      createDelegation(db, { ...limits, maxDepth: 9 }, input()),
      "invalid_request",
    );
    for (const maxLifetimeSeconds of [Number.NaN, -1, 0, Infinity])
      await refused(
        createDelegation(db, { ...limits, maxLifetimeSeconds }, input()),
        "invalid_request",
      );
  },
);

test(
  "a high-impact action needs the initiator's approval",
  { skip },
  async () => {
    const actions = ["model:invoke", "model:delete"];
    await refused(create({ allowedActions: actions }), "approval_required");
    await refused(
      create({ allowedActions: actions, approvedActions: ["tool:run"] }),
      "invalid_request",
    );
    await create({
      allowedActions: actions,
      approvedActions: ["model:delete"],
    });
  },
);

test("a nested delegation can only narrow its parent", { skip }, async () => {
  const { id: parent } = await create();
  const child = (over: Partial<NewDelegation> = {}) =>
    create({
      actorPrincipalId: AGENT2,
      createdByPrincipalId: AGENT,
      parentDelegationId: parent,
      allowedResources: ["model:finance-llm"],
      allowedActions: ["model:invoke"],
      expiresAt: soon,
      ...over,
    });
  const { id } = await child();
  const { rows } = await db.query(
    "SELECT depth FROM delegations WHERE id = $1",
    [id],
  );
  assert.equal(rows[0].depth, 2);
  await refused(child({ allowedResources: ["model:other"] }), "exceeds_parent");
  await refused(
    child({
      allowedActions: ["model:delete"],
      approvedActions: ["model:delete"],
    }),
    "exceeds_parent",
  );
  await refused(child({ expiresAt: inMinutes(31) }), "exceeds_parent");
  await refused(child({ taskId: "task-2" }), "exceeds_parent");
  await refused(child({ createdByPrincipalId: AGENT2 }), "exceeds_parent");
  await refused(child({ createdByPrincipalId: ALICE }), "exceeds_parent");
  await refused(child({ applicationId: "other-app" }), "exceeds_parent");
  await refused(
    child({ parentDelegationId: `dlg_${"0".repeat(32)}` }),
    "unknown_parent",
  );
});

test("nesting stops at the depth cap", { skip }, async () => {
  let parent = (await create()).id;
  let creator = AGENT;
  for (let level = 2; level <= limits.maxDepth; level++) {
    parent = (
      await create({
        createdByPrincipalId: creator,
        parentDelegationId: parent,
        actorPrincipalId: AGENT2,
        expiresAt: soon,
      })
    ).id;
    creator = AGENT2;
  }
  await refused(
    create({
      createdByPrincipalId: creator,
      parentDelegationId: parent,
      actorPrincipalId: AGENT2,
      expiresAt: soon,
    }),
    "exceeds_limit",
  );
});

test(
  "a nested delegation cannot carry an approval its parent lacks",
  { skip },
  async () => {
    const actions = ["model:invoke", "model:delete"];
    const { id: parent } = await create({
      taskId: "task-a",
      allowedActions: actions,
      approvedActions: ["model:delete"],
    });
    const { id: bare } = await create({ taskId: "task-b" });
    const child = (p: string, task: string) =>
      create({
        taskId: task,
        createdByPrincipalId: AGENT,
        parentDelegationId: p,
        actorPrincipalId: AGENT2,
        allowedActions: actions,
        approvedActions: ["model:delete"],
        expiresAt: soon,
      });
    await child(parent, "task-a");
    await refused(child(bare, "task-b"), "exceeds_parent");
  },
);

test(
  "revoking a delegation revokes everything nested under it and nothing else",
  { skip },
  async () => {
    const { id: root } = await create({ taskId: "task-r" });
    const { id: mid } = await create({
      taskId: "task-r",
      createdByPrincipalId: AGENT,
      parentDelegationId: root,
      actorPrincipalId: AGENT2,
      expiresAt: soon,
    });
    const { id: leaf } = await create({
      taskId: "task-r",
      createdByPrincipalId: AGENT2,
      parentDelegationId: mid,
      actorPrincipalId: AGENT2,
      expiresAt: soon,
    });
    const { id: sibling } = await create({ taskId: "task-s" });
    assert.equal(await revokeDelegation(db, "other", root), 0);
    assert.equal(await revokeDelegation(db, "acme", mid), 2);
    assert.equal(await revokedAt(root), null);
    assert.notEqual(await revokedAt(leaf), null);
    assert.equal(await revokeDelegation(db, "acme", mid), 0);
    assert.equal(await revokedAt(sibling), null);
    await refused(
      create({
        taskId: "task-r",
        createdByPrincipalId: AGENT2,
        parentDelegationId: mid,
        actorPrincipalId: AGENT2,
        expiresAt: soon,
      }),
      "unknown_parent",
    );
    assert.equal(await revokeDelegation(db, "acme", root), 1);
  },
);
