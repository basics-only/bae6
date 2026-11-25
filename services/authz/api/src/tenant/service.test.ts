import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ConsistencyPreference, OpenFgaClient } from "@openfga/sdk";
import { transformer } from "@openfga/syntax-transformer";
import pg from "pg";
import { listAudit } from "../admin/audit.js";
import { InvalidCursor } from "../admin/service.js";
import { migrate } from "../db/migrate.js";
import { HttpError } from "../http.js";
import {
  createTenantService,
  type TenantService,
  tenantClient,
} from "./service.js";

// Integration: needs Postgres and OpenFGA. Unverified until run against both.
const url = process.env.BAE6_DATABASE_URL;
const apiUrl = process.env.OPENFGA_API_URL;
const opts = {
  skip: url && apiUrl ? false : "BAE6_DATABASE_URL and OPENFGA_API_URL not set",
};

const OPERATOR = "service:platform";
const ROOTADM = "user:rootadm";
const FIN = "user:fin";

type Placement = {
  tenantId: string;
  principalId: string;
  principalType: string;
  orgPath: string[];
};
class FakeAuthn {
  calls: Placement[] = [];
  failing = false;
  refusing: number | undefined;
  async place(input: Placement) {
    if (this.refusing)
      throw Object.assign(new Error("refused"), { status: this.refusing });
    if (this.failing) throw new Error("authn down");
    this.calls.push(input);
  }
}

async function withTenant(
  fn: (ctx: {
    svc: TenantService;
    client: OpenFgaClient;
    pool: pg.Pool;
    authn: FakeAuthn;
  }) => Promise<void>,
  maxDepth = 8,
) {
  const schema = `t_${randomUUID().replaceAll("-", "")}`;
  const setup = new pg.Client({ connectionString: url });
  await setup.connect();
  await setup.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({
    connectionString: url,
    options: `-c search_path=${schema}`,
  });
  const fga = new OpenFgaClient({ apiUrl: apiUrl as string });
  const { id } = await fga.createStore({ name: `tenant-${schema}` });
  const setupClient = new OpenFgaClient({
    apiUrl: apiUrl as string,
    storeId: id,
  });
  try {
    const c = await pool.connect();
    await migrate(c);
    c.release();
    const model = await setupClient.writeAuthorizationModel(
      transformer.transformDSLToJSONObject(
        readFileSync(
          join(import.meta.dirname, "../../models/openfga/tenant.fga"),
          "utf8",
        ),
      ),
    );
    const client = tenantClient({
      apiUrl: apiUrl as string,
      storeId: id,
      authorizationModelId: model.authorization_model_id,
    });
    const authn = new FakeAuthn();
    const svc = createTenantService({
      pool,
      client,
      organization: "acme",
      maxDepth,
      placements: authn,
    });
    await svc.bootstrap(OPERATOR, "acme", ROOTADM);
    await fn({ svc, client, pool, authn });
  } finally {
    await pool.end();
    await setup.query(`DROP SCHEMA ${schema} CASCADE`);
    await setup.end();
    await setupClient.deleteStore();
  }
}

const status = (code: number) => (e: unknown) =>
  e instanceof HttpError && e.status === code;

const allowed = async (
  client: OpenFgaClient,
  user: string,
  relation: string,
  object: string,
) =>
  (
    await client.check(
      { user, relation, object },
      { consistency: ConsistencyPreference.HigherConsistency },
    )
  ).allowed;

test("rejects a max depth above what OpenFGA resolves", () => {
  assert.throws(() =>
    createTenantService({
      pool: {} as pg.Pool,
      client: {} as OpenFgaClient,
      organization: "acme",
      maxDepth: 23,
    }),
  );
});

test(
  "a second bootstrap is rejected so a tenant has one root",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await assert.rejects(
        svc.bootstrap(OPERATOR, "acme", ROOTADM),
        status(409),
      );
      await assert.rejects(
        svc.bootstrap(OPERATOR, "other", ROOTADM),
        status(400),
      );
    });
  },
);

test(
  "a unit cannot be created twice, so it never gets a second parent or becomes a root",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "software", "acme");
      await assert.rejects(
        svc.createUnit(ROOTADM, "finance", "software"),
        status(409),
      );
      await assert.rejects(
        svc.createUnit(ROOTADM, "acme", "finance"),
        status(409),
      );
    });
  },
);

test(
  "creating a unit requires settings_admin on its parent",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await assert.rejects(
        svc.createUnit("user:nobody", "payroll", "finance"),
        status(403),
      );
      await assert.rejects(
        svc.createUnit(ROOTADM, "ghost-child", "ghost"),
        status(403),
      );
    });
  },
);

test("rejects a unit that would exceed the depth cap", opts, async () => {
  await withTenant(async ({ svc }) => {
    await svc.createUnit(ROOTADM, "a", "acme");
    await svc.createUnit(ROOTADM, "b", "a");
    await assert.rejects(svc.createUnit(ROOTADM, "c", "b"), status(400));
  }, 3);
});

test(
  "a new unit allows resources its principals hold, because creation writes the allow-lists",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.placeResource(ROOTADM, "model", "llm", "finance");
      await client.write({
        writes: [
          { user: "user:alice", relation: "invoker", object: "model:llm" },
        ],
      });
      assert.equal(
        await allowed(client, "user:alice", "can_invoke", "model:llm"),
        true,
      );
    });
  },
);

test(
  "a resource belongs to one unit and only app_admins place it",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "software", "acme");
      await svc.placeResource(ROOTADM, "tool", "ledger", "finance");
      await assert.rejects(
        svc.placeResource(ROOTADM, "tool", "ledger", "software"),
        status(409),
      );
      await assert.rejects(
        svc.placeResource("user:nobody", "tool", "other", "finance"),
        status(403),
      );
    });
  },
);

test(
  "resource placement retries a failed projection and repairs unit drift",
  opts,
  async () => {
    await withTenant(async ({ svc, client, pool }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "software", "acme");
      const object = "model:llm";
      const intended = { user: "org_unit:finance", relation: "unit", object };
      const drift = { ...intended, user: "org_unit:software" };
      const write = client.write.bind(client);
      client.write = async () => {
        throw new Error("OpenFGA unavailable");
      };
      try {
        await assert.rejects(
          svc.placeResource(ROOTADM, "model", "llm", "finance"),
          status(503),
        );
      } finally {
        client.write = write;
      }

      const scheduleNow = () =>
        pool.query(
          "UPDATE tenant_resource_outbox SET due_at = now() WHERE organization_id = $1 AND resource = $2",
          ["acme", object],
        );
      const readUnits = async () =>
        (
          await client.read(
            { object, relation: "unit" },
            {
              consistency: ConsistencyPreference.HigherConsistency,
            },
          )
        ).tuples.map((tuple) => tuple.key.user);
      assert.deepEqual(await readUnits(), []);
      await scheduleNow();
      await svc.reconcileResource();
      assert.deepEqual(await readUnits(), [intended.user]);
      await svc.placeResource(ROOTADM, "model", "llm", "finance");

      await client.write({ writes: [drift], deletes: [intended] });
      await scheduleNow();
      await svc.reconcileResource();
      assert.deepEqual(await readUnits(), [intended.user]);
    });
  },
);

test(
  "reconciliation reports each due resource until none are left, so a tick can drain a backlog",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      await svc.placeResource(ROOTADM, "model", "a", "acme");
      await svc.placeResource(ROOTADM, "model", "b", "acme");
      await pool.query(
        "UPDATE tenant_resource_outbox SET due_at = now() WHERE organization_id = $1",
        ["acme"],
      );
      assert.equal(await svc.reconcileResource(), true);
      assert.equal(await svc.reconcileResource(), true);
      assert.equal(await svc.reconcileResource(), false);
    });
  },
);

test(
  "rejects unknown resource types, capabilities and actions",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await assert.rejects(
        svc.placeResource(ROOTADM, "org_unit" as never, "x", "acme"),
        status(400),
      );
      await assert.rejects(
        svc.grant(ROOTADM, "root" as never, "user:x", "acme"),
        status(400),
      );
      await assert.rejects(
        svc.setGuardrail(
          ROOTADM,
          "acme",
          "nope" as never,
          "allowlist",
          "user:*",
          true,
        ),
        status(400),
      );
    });
  },
);

test(
  "grants stay inside the ceilings and subtree of the granter",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "software", "acme");
      await svc.createUnit(ROOTADM, "payroll", "finance");

      await assert.rejects(
        svc.grant(ROOTADM, "access", FIN, "finance"),
        status(403),
        "no ceiling at finance yet",
      );
      await svc.setCeiling(ROOTADM, "access", "finance", true);
      await svc.grant(ROOTADM, "access", FIN, "finance");
      assert.equal(
        await allowed(client, FIN, "access_admin", "org_unit:payroll"),
        true,
      );

      await assert.rejects(
        svc.grant(FIN, "access", "user:peer", "payroll"),
        status(403),
        "payroll has no ceiling until finance's admins are allowed to set it",
      );
      await assert.rejects(
        svc.setCeiling(FIN, "access", "finance", false),
        status(403),
        "raising or lowering your own ceiling",
      );
      await svc.setCeiling(FIN, "access", "payroll", true);
      await svc.grant(FIN, "access", "user:peer", "payroll");

      await assert.rejects(
        svc.grant(FIN, "access", "user:peer", "software"),
        status(403),
      );
      await assert.rejects(
        svc.grant(FIN, "access", "user:peer", "acme"),
        status(403),
      );
      await assert.rejects(
        svc.grant(FIN, "settings", "user:peer", "finance"),
        status(403),
      );
      await assert.rejects(
        svc.grant("user:peer", "access", "user:peer2", "finance"),
        status(403),
      );
    });
  },
);

test(
  "an agent cannot be given an admin capability, directly or through a group",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await assert.rejects(
        svc.grant(ROOTADM, "access", "agent:bot", "acme"),
        status(400),
      );
      await assert.rejects(
        svc.grant(ROOTADM, "access", "agent:bot#member", "acme"),
        status(400),
      );
    });
  },
);

test(
  "clearing a ceiling leaves the descendants' ceilings in place",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "payroll", "finance");
      await svc.setCeiling(ROOTADM, "app", "finance", true);
      await svc.setCeiling(ROOTADM, "app", "payroll", true);
      await svc.setCeiling(ROOTADM, "app", "finance", false);
      assert.equal(
        await allowed(
          client,
          "user:*",
          "app_admin_ceiling",
          "org_unit:payroll",
        ),
        true,
      );
      await assert.rejects(
        svc.grant(ROOTADM, "app", FIN, "finance"),
        status(403),
      );
    });
  },
);

test(
  "only a security_admin writes guardrails, and a child cannot widen its parent's",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.placeResource(ROOTADM, "model", "llm", "finance");
      await client.write({
        writes: [
          { user: "user:alice", relation: "invoker", object: "model:llm" },
          { user: "user:carl", relation: "invoker", object: "model:llm" },
        ],
      });
      await assert.rejects(
        svc.setGuardrail(
          "user:nobody",
          "acme",
          "model_invoke",
          "blocklist",
          "user:carl",
          true,
        ),
        status(403),
      );
      await svc.setGuardrail(
        ROOTADM,
        "acme",
        "model_invoke",
        "blocklist",
        "user:carl",
        true,
      );
      assert.equal(
        await allowed(client, "user:carl", "can_invoke", "model:llm"),
        false,
      );
      assert.equal(
        await allowed(client, "user:alice", "can_invoke", "model:llm"),
        true,
      );

      await svc.setGuardrail(
        ROOTADM,
        "acme",
        "model_invoke",
        "blocklist",
        "user:carl",
        false,
      );
      assert.equal(
        await allowed(client, "user:carl", "can_invoke", "model:llm"),
        true,
      );
    });
  },
);

test(
  "every change is audited with the actor, subject, unit and capability",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.setCeiling(ROOTADM, "access", "finance", true);
      const id = await svc.grant(ROOTADM, "access", FIN, "finance", "req-1");
      const { rows } = await pool.query(
        "SELECT actor, action, request_id, detail FROM audit_events WHERE id = $1",
        [id],
      );
      assert.deepEqual(rows[0], {
        actor: ROOTADM,
        action: "tenant.grant",
        request_id: "req-1",
        detail: {
          capability: "access",
          grantee: FIN,
          unit: "org_unit:finance",
        },
      });
    });
  },
);

test(
  "a denied change writes a denied audit row and no tuple",
  opts,
  async () => {
    await withTenant(async ({ svc, client, pool }) => {
      await assert.rejects(
        svc.grant(FIN, "access", "user:peer", "acme"),
        status(403),
      );
      const { rows } = await pool.query(
        "SELECT actor, action, outcome FROM audit_events WHERE outcome = 'denied'",
      );
      assert.deepEqual(rows, [
        { actor: FIN, action: "tenant.grant", outcome: "denied" },
      ]);
      assert.equal(
        await allowed(client, "user:peer", "access_admin", "org_unit:acme"),
        false,
      );
    });
  },
);

test(
  "a change that cannot get the tenant lock fails with 503 instead of waiting",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      const holder = await pool.connect();
      try {
        await holder.query("BEGIN");
        await holder.query(
          "SELECT pg_advisory_xact_lock(hashtextextended('tenant:acme', 0))",
        );
        await assert.rejects(
          svc.createUnit(ROOTADM, "finance", "acme"),
          status(503),
        );
      } finally {
        await holder.query("ROLLBACK");
        holder.release();
      }
    });
  },
);

test(
  "an OpenFGA failure during a write is audited as an error and reported as 503",
  opts,
  async () => {
    await withTenant(async ({ client, pool }) => {
      const failing = Object.assign(Object.create(client), {
        write: async () => {
          throw new Error("connection reset");
        },
      });
      const svc = createTenantService({
        pool,
        client: failing,
        organization: "acme",
      });
      await assert.rejects(
        svc.createUnit(ROOTADM, "finance", "acme"),
        status(503),
      );
      const { rows } = await pool.query(
        "SELECT actor, action, outcome FROM audit_events WHERE outcome = 'error'",
      );
      assert.deepEqual(rows, [
        { actor: ROOTADM, action: "tenant.unit.create", outcome: "error" },
      ]);
    });
  },
);

test(
  "an invalid actor is rejected before anything is audited",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      const before = await pool.query(
        "SELECT count(*)::int AS n FROM audit_events",
      );
      await assert.rejects(
        svc.grant("user:x\nadmin", "access", "user:peer", "acme"),
        status(403),
      );
      const after = await pool.query(
        "SELECT count(*)::int AS n FROM audit_events",
      );
      assert.equal(after.rows[0].n, before.rows[0].n);
    });
  },
);

test(
  "a denial that cannot be audited fails closed with 503",
  opts,
  async () => {
    await withTenant(async ({ client, pool }) => {
      let connects = 0;
      const noAuditPool = Object.assign(Object.create(pool), {
        connect: async () => {
          if (++connects > 1) throw new Error("audit store down");
          return pool.connect();
        },
      });
      const svc = createTenantService({
        pool: noAuditPool,
        client,
        organization: "acme",
      });
      await assert.rejects(
        svc.grant(FIN, "access", "user:peer", "acme"),
        status(503),
      );
    });
  },
);

test(
  "tenant audit events are visible to a wildcard allow-list and hidden from a scoped one",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      const page = { limit: 50 };
      const all = await listAudit(pool, "acme", ["*"], page);
      const scoped = await listAudit(pool, "acme", ["app1"], page);
      assert.ok(all.items.some((e) => e.action === "tenant.unit.create"));
      assert.equal(scoped.items.length, 0);
    });
  },
);

test(
  "a rejected duplicate unit is audited as an error without an applied marker",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await assert.rejects(
        svc.createUnit(ROOTADM, "finance", "acme"),
        status(409),
      );
      const { items } = await listAudit(pool, "acme", ["*"], { limit: 50 });
      const row = items.find((e) => e.outcome === "error");
      assert.ok(row);
      assert.equal(row.detail.applied, undefined);
    });
  },
);

test(
  "the root keeps its last administrator and nobody can clear its ceiling",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await assert.rejects(
        svc.revoke(ROOTADM, "access", ROOTADM, "acme"),
        status(409),
      );
      await svc.grant(ROOTADM, "access", FIN, "acme");
      await svc.revoke(ROOTADM, "access", ROOTADM, "acme");
      await assert.rejects(
        svc.setCeiling(FIN, "access", "acme", false),
        status(403),
      );
    });
  },
);

test(
  "a ceiling with only one of its tuples can still be cleared",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await client.write({
        writes: [
          {
            user: "user:*",
            relation: "budget_admin_ceiling",
            object: "org_unit:finance",
          },
        ],
      });
      await svc.setCeiling(ROOTADM, "budget", "finance", false);
      await assert.rejects(
        svc.setCeiling(ROOTADM, "budget", "finance", false),
        status(404),
      );
    });
  },
);

test(
  "a change rejected for the tenant lock is audited as an error",
  opts,
  async () => {
    await withTenant(async ({ svc, pool }) => {
      const holder = await pool.connect();
      try {
        await holder.query("BEGIN");
        await holder.query(
          "SELECT pg_advisory_xact_lock(hashtextextended('tenant:acme', 0))",
        );
        await assert.rejects(
          svc.createUnit(ROOTADM, "finance", "acme"),
          status(503),
        );
      } finally {
        await holder.query("ROLLBACK");
        holder.release();
      }
      const { items } = await listAudit(pool, "acme", ["*"], { limit: 50 });
      assert.ok(items.some((e) => e.outcome === "error"));
    });
  },
);

test("an audit cursor with extra characters is rejected", opts, async () => {
  await withTenant(async ({ pool }) => {
    const cursor = `${Buffer.from("123").toString("base64url")}!!`;
    await assert.rejects(
      listAudit(pool, "acme", ["*"], { limit: 5, cursor }),
      InvalidCursor,
    );
  });
});

test("a half-set ceiling can be completed", opts, async () => {
  await withTenant(async ({ svc, client }) => {
    await svc.createUnit(ROOTADM, "finance", "acme");
    await client.write({
      writes: [
        {
          user: "user:*",
          relation: "budget_admin_ceiling",
          object: "org_unit:finance",
        },
      ],
    });
    await svc.setCeiling(ROOTADM, "budget", "finance", true);
    await assert.rejects(
      svc.setCeiling(ROOTADM, "budget", "finance", true),
      status(409),
    );
  });
});

test(
  "a unit cannot be created under a parent that does not exist",
  opts,
  async () => {
    await withTenant(async ({ svc }) => {
      await assert.rejects(
        svc.createUnit(ROOTADM, "finance", "ghost"),
        (e: unknown) => e instanceof HttpError && e.status >= 400,
      );
    });
  },
);

test(
  "a root admin can be revoked when more than a page of others remain",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      for (const start of [0, 60]) {
        await client.write({
          writes: Array.from({ length: 60 }, (_, i) => ({
            user: `user:bulk${start + i}`,
            relation: "access_admin_grant",
            object: "org_unit:acme",
          })),
        });
      }
      await svc.revoke(ROOTADM, "access", ROOTADM, "acme");
    });
  },
);

const ALICE_ID = `prn_${"a".repeat(32)}`;
const ALICE = `user:${ALICE_ID}`;

test(
  "placing a principal records it in the unit and tells authn its path from the tenant root",
  opts,
  async () => {
    await withTenant(async ({ svc, client, authn }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "payroll", "finance");
      await svc.placePrincipal(ROOTADM, ALICE, "payroll");
      assert.equal(
        await allowed(client, ALICE, "placed", "org_unit:payroll"),
        true,
      );
      assert.deepEqual(authn.calls, [
        {
          tenantId: "acme",
          principalId: ALICE_ID,
          principalType: "user",
          orgPath: ["acme", "finance", "payroll"],
        },
      ]);
    });
  },
);

test(
  "moving a principal leaves its old unit and needs admin rights over both units",
  opts,
  async () => {
    await withTenant(async ({ svc, client, authn }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.createUnit(ROOTADM, "software", "acme");
      await svc.placePrincipal(ROOTADM, ALICE, "software");
      await svc.setCeiling(ROOTADM, "access", "finance", true);
      await svc.grant(ROOTADM, "access", FIN, "finance");
      await assert.rejects(
        svc.placePrincipal(FIN, ALICE, "finance"),
        status(403),
      );
      await svc.placePrincipal(ROOTADM, ALICE, "finance");
      assert.equal(
        await allowed(client, ALICE, "placed", "org_unit:software"),
        false,
      );
      assert.equal(
        await allowed(client, ALICE, "placed", "org_unit:finance"),
        true,
      );
      assert.deepEqual(authn.calls.at(-1)?.orgPath, ["acme", "finance"]);
      assert.equal(authn.calls.length, 2);
    });
  },
);

test(
  "placement refuses units the actor cannot administer, non-principal subjects and non-admins without calling authn",
  opts,
  async () => {
    await withTenant(async ({ svc, authn }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await assert.rejects(
        svc.placePrincipal(ROOTADM, ALICE, "ghost"),
        status(403),
      );
      await assert.rejects(
        svc.placePrincipal(ROOTADM, "user:alice", "finance"),
        status(400),
      );
      await assert.rejects(
        svc.placePrincipal(ROOTADM, `group:${ALICE_ID}#member`, "finance"),
        status(400),
      );
      await assert.rejects(
        svc.placePrincipal(ROOTADM, ALICE, "Finance_1"),
        status(400),
      );
      await assert.rejects(
        svc.placePrincipal("user:nobody", ALICE, "finance"),
        status(403),
      );
      assert.deepEqual(authn.calls, []);
    });
  },
);

test(
  "a placement authn did not accept leaves authz unchanged and repeating it finishes the job",
  opts,
  async () => {
    await withTenant(async ({ svc, client, authn }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      authn.failing = true;
      await assert.rejects(
        svc.placePrincipal(ROOTADM, ALICE, "finance"),
        status(503),
      );
      assert.equal(
        await allowed(client, ALICE, "placed", "org_unit:finance"),
        false,
      );
      authn.refusing = 409;
      await assert.rejects(
        svc.placePrincipal(ROOTADM, ALICE, "finance"),
        status(409),
      );
      assert.equal(
        await allowed(client, ALICE, "placed", "org_unit:finance"),
        false,
      );
      authn.failing = false;
      authn.refusing = undefined;
      await svc.placePrincipal(ROOTADM, ALICE, "finance");
      assert.deepEqual(
        authn.calls.map((c) => c.orgPath),
        [["acme", "finance"]],
      );
    });
  },
);

test(
  "a check denies by default, allows a granted principal, honours a blocklist and refuses non-principals",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.placeResource(ROOTADM, "model", "llm", "finance");
      assert.equal(await svc.check(ALICE, "model", "llm"), false);
      assert.equal(await svc.check(ALICE, "model", "unplaced"), false);
      await client.write({
        writes: [{ user: ALICE, relation: "invoker", object: "model:llm" }],
      });
      assert.equal(await svc.check(ALICE, "model", "llm"), true);
      await svc.setGuardrail(
        ROOTADM,
        "acme",
        "model_invoke",
        "blocklist",
        ALICE,
        true,
      );
      assert.equal(await svc.check(ALICE, "model", "llm"), false);
      for (const subject of [
        `group:${ALICE_ID}#member`,
        "user:alice",
        "user:*",
      ])
        await assert.rejects(svc.check(subject, "model", "llm"), status(403));
      await assert.rejects(
        svc.check(ALICE, "org_unit" as never, "finance"),
        status(400),
      );
      await assert.rejects(svc.check(ALICE, "model", "a b"), status(400));
    });
  },
);

test(
  "a check reports an unreachable store as 503, never as a denial",
  opts,
  async () => {
    await withTenant(async ({ pool }) => {
      const svc = createTenantService({
        pool,
        organization: "acme",
        client: tenantClient({
          apiUrl: "http://127.0.0.1:9",
          storeId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
          authorizationModelId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        }),
      });
      await assert.rejects(svc.check(ALICE, "model", "llm"), status(503));
    });
  },
);

test(
  "an actor without admin rights cannot tell a missing unit from an existing one",
  opts,
  async () => {
    await withTenant(async ({ svc, authn }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      for (const unit of ["finance", "nowhere"])
        await assert.rejects(
          svc.placePrincipal("user:nobody", ALICE, unit),
          status(403),
        );
      assert.deepEqual(authn.calls, []);
    });
  },
);

test(
  "a revoked grant and a cleared blocklist are seen by the very next check",
  opts,
  async () => {
    await withTenant(async ({ svc, client }) => {
      await svc.createUnit(ROOTADM, "finance", "acme");
      await svc.placeResource(ROOTADM, "model", "llm", "finance");
      const grant = { user: ALICE, relation: "invoker", object: "model:llm" };
      for (let round = 0; round < 3; round++) {
        await client.write({ writes: [grant] });
        assert.equal(await svc.check(ALICE, "model", "llm"), true);
        await client.write({ deletes: [grant] });
        assert.equal(await svc.check(ALICE, "model", "llm"), false);
      }
      await client.write({ writes: [grant] });
      const block = [
        ROOTADM,
        "acme",
        "model_invoke",
        "blocklist",
        ALICE,
      ] as const;
      await svc.setGuardrail(...block, true);
      assert.equal(await svc.check(ALICE, "model", "llm"), false);
      await svc.setGuardrail(...block, false);
      assert.equal(await svc.check(ALICE, "model", "llm"), true);
    });
  },
);
