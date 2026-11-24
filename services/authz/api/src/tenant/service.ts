import { AsyncLocalStorage } from "node:async_hooks";
import { ConsistencyPreference, OpenFgaClient } from "@openfga/sdk";
import type pg from "pg";
import { recordAudit } from "../admin/audit.js";
import { fga as guardedFga } from "../admin/relationships.js";
import { HttpError } from "../http.js";

export const MAX_DEPTH = 22;
const LOCK_TIMEOUT_MS = 5000;
const OPENFGA_TIMEOUT_MS = 10000;
const TRANSACTION_BUDGET_MS = 30000;
const deadline = new AsyncLocalStorage<number>();
const ambiguous = new WeakSet<Error>();
const markAmbiguous = (err: unknown): never => {
  if (err instanceof HttpError && err.code === "authorization_unavailable") {
    ambiguous.add(err);
  }
  throw err;
};

async function boundedAudit(
  pool: pg.Pool,
  event: Parameters<typeof recordAudit>[1],
): Promise<void> {
  const db = await pool.connect();
  let broken = false;
  try {
    await db.query("BEGIN");
    await db.query(`SET LOCAL statement_timeout = '${OPENFGA_TIMEOUT_MS}'`);
    await recordAudit(db, event);
    await db.query("COMMIT");
  } catch (err) {
    broken = true;
    throw err;
  } finally {
    db.release(broken);
  }
}

function fga<T>(
  call: () => Promise<T>,
  onInvalid: (message: string) => Error,
): Promise<T> {
  return guardedFga(() => {
    const left = (deadline.getStore() ?? Infinity) - Date.now();
    if (left <= 0) throw new Error("transaction budget exhausted");
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error("OpenFGA call timed out")),
        Math.min(OPENFGA_TIMEOUT_MS, left),
      );
    });
    timeout.catch(() => {});
    return Promise.race([Promise.resolve().then(call), timeout]).finally(() =>
      clearTimeout(timer),
    );
  }, onInvalid);
}

/** The client must come from here: its requests abort at the timeout instead of landing after the lock is released. */
export const tenantClient = (config: {
  apiUrl: string;
  storeId: string;
  authorizationModelId: string;
}) =>
  new OpenFgaClient({
    ...config,
    baseOptions: { timeout: OPENFGA_TIMEOUT_MS },
    retryParams: { maxRetry: 0 },
  });

export const CAPABILITIES = [
  "access",
  "settings",
  "app",
  "budget",
  "security",
] as const;
export const ACTIONS = [
  "application_use",
  "api_call",
  "model_invoke",
  "agent_run",
  "prompt_use",
  "mcp_server_use",
  "tool_invoke",
  "dataset_query",
  "document_read",
  "service_call",
] as const;
export const RESOURCE_TYPES = [
  "application",
  "api",
  "model",
  "agent_definition",
  "prompt",
  "mcp_server",
  "dataset",
  "document",
  "tool",
  "service_resource",
] as const;
const PRINCIPAL_TYPES = ["user", "service", "agent", "application"] as const;

export type Capability = (typeof CAPABILITIES)[number];
export type Action = (typeof ACTIONS)[number];
export type ResourceType = (typeof RESOURCE_TYPES)[number];
export type GuardrailList = "allowlist" | "blocklist";

interface Tuple {
  user: string;
  relation: string;
  object: string;
}

const ID = "[A-Za-z0-9_@.+|-]{1,256}";
const UNIT = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ADMIN_SUBJECT = new RegExp(`^((user|service):${ID}|group:${ID}#member)$`);
const GUARDRAIL_SUBJECT = new RegExp(
  `^((${PRINCIPAL_TYPES.join("|")}):(${ID}|\\*)|group:${ID}#member)$`,
);
const RESOURCE_ID = new RegExp(`^${ID}$`);
const ACTOR = new RegExp(`^(user|service):${ID}$`);

const invalid = (message: string) =>
  new HttpError(400, "invalid_request", message);
const forbidden = (message: string) => new HttpError(403, "forbidden", message);
const conflict = (message: string) => new HttpError(409, "conflict", message);
const unavailable = () =>
  new HttpError(
    503,
    "authorization_unavailable",
    "The authorization store is unavailable.",
  );

const oneOf = <T extends string>(
  list: readonly T[],
  v: unknown,
  what: string,
) => {
  if (!list.includes(v as T)) throw invalid(`Unknown ${what}.`);
  return v as T;
};

const defaultAllowlists = (unit: string): Tuple[] =>
  ACTIONS.flatMap((action) =>
    PRINCIPAL_TYPES.map((type) => ({
      user: `${type}:*`,
      relation: `${action}_allowlist`,
      object: unit,
    })),
  );

/**
 * The only writer of a tenant store. The model can't forbid a second `parent`, `is_root`
 * on a child, or a second `unit`, so no operation here can produce them: structure is
 * written only by bootstrap, createUnit and placeResource, each under a per-tenant lock.
 */
export function createTenantService(deps: {
  pool: pg.Pool;
  client: OpenFgaClient;
  organization: string;
  maxDepth?: number;
}) {
  const { pool, client, organization } = deps;
  const maxDepth = deps.maxDepth ?? 8;
  if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > MAX_DEPTH) {
    throw new Error(`maxDepth must be an integer from 1 to ${MAX_DEPTH}`);
  }

  const holds = async (actor: string, relation: string, object: string) =>
    (
      await fga(
        () =>
          client.check(
            { user: actor, relation, object },
            { consistency: ConsistencyPreference.HigherConsistency },
          ),
        unavailable,
      )
    ).allowed === true;

  async function requireRelation(
    actor: string,
    relation: string,
    object: string,
  ) {
    if (!ACTOR.test(actor)) throw forbidden("Unknown actor.");
    if (!(await holds(actor, relation, object))) {
      throw forbidden(`Not permitted: ${relation} on ${object}.`);
    }
  }

  const read = async (key: Partial<Tuple>) => {
    const page = await fga(
      () => client.read(key, { pageSize: 100 }),
      unavailable,
    );
    if (page.continuation_token) {
      throw new HttpError(500, "internal", "A tuple read was truncated.");
    }
    return page.tuples;
  };

  const write = (writes: Tuple[]) =>
    fga(
      () => client.write({ writes }),
      (m) => (/already exist/i.test(m) ? conflict(m) : invalid(m)),
    ).catch(markAmbiguous);

  const remove = (deletes: Tuple[]) =>
    fga(
      () => client.write({ deletes }),
      (m) =>
        /does not exist/i.test(m)
          ? new HttpError(404, "not_found", "Tuple not found.")
          : invalid(m),
    ).catch(markAmbiguous);

  async function depthOf(unit: string): Promise<number> {
    let depth = 1;
    let current = unit;
    for (;;) {
      const parents = await read({
        object: `org_unit:${current}`,
        relation: "parent",
      });
      if (parents.length > 1) {
        throw new HttpError(
          500,
          "internal",
          "A unit has more than one parent.",
        );
      }
      const parent = parents[0];
      if (!parent) return depth;
      if (++depth > MAX_DEPTH + 1) {
        throw new HttpError(500, "internal", "The unit tree is too deep.");
      }
      current = parent.key.user.slice("org_unit:".length);
    }
  }

  async function transact(
    event: Parameters<typeof recordAudit>[1],
    run: () => Promise<void>,
  ): Promise<string> {
    const db = await pool.connect();
    let broken = false;
    try {
      await db.query("BEGIN");
      await db.query(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT_MS}'`);
      await db.query(`SET LOCAL statement_timeout = '${OPENFGA_TIMEOUT_MS}'`);
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `tenant:${organization}`,
      ]);
      const id = await recordAudit(db, event);
      await deadline.run(Date.now() + TRANSACTION_BUDGET_MS, run);
      await db.query("COMMIT");
      return id;
    } catch (err) {
      await db.query("ROLLBACK").catch(() => {
        broken = true;
      });
      if ((err as { code?: string }).code === "55P03") {
        throw new HttpError(
          503,
          "busy",
          "Another tenant change is in progress.",
        );
      }
      throw err;
    } finally {
      db.release(broken);
    }
  }

  /**
   * Audit row and mutation commit together. Denials and ambiguous OpenFGA failures are
   * audited afterwards, once the connection is back in the pool.
   * shortcut: a COMMIT that fails after OpenFGA accepted leaves an unaudited change, and
   * upgrade to an outbox.
   */
  async function audited(
    actor: string,
    action: string,
    detail: Record<string, unknown>,
    requestId: string | undefined,
    run: () => Promise<void>,
  ): Promise<string> {
    if (!ACTOR.test(actor)) throw forbidden("Unknown actor.");
    const event = { actor, organization, action, requestId, detail };
    try {
      return await transact(event, run);
    } catch (err) {
      const outcome =
        err instanceof HttpError && err.status === 403
          ? "denied"
          : err instanceof HttpError && err.code === "busy"
            ? null
            : "error";
      if (outcome) {
        await boundedAudit(pool, {
          ...event,
          outcome,
          detail:
            err instanceof Error && ambiguous.has(err)
              ? { ...detail, applied: "unknown" }
              : detail,
        }).catch(() => {
          throw new HttpError(
            503,
            "audit_unavailable",
            "The audit store is unavailable.",
          );
        });
      }
      throw err;
    }
  }

  const unitOf = (unit: string) => {
    if (!UNIT.test(unit)) throw invalid("Invalid unit id.");
    return `org_unit:${unit}`;
  };

  async function adminGrant(
    actor: string,
    capability: Capability,
    subject: string,
    unit: string,
    enable: boolean,
    requestId: string | undefined,
  ) {
    oneOf(CAPABILITIES, capability, "capability");
    const node = unitOf(unit);
    if (!ADMIN_SUBJECT.test(subject)) {
      throw invalid("subject must be a user, service or group#member.");
    }
    const tuple = {
      user: subject,
      relation: `${capability}_admin_grant`,
      object: node,
    };
    return audited(
      actor,
      enable ? "tenant.grant" : "tenant.revoke",
      { capability, grantee: subject, unit: node },
      requestId,
      async () => {
        await requireRelation(actor, `can_grant_${capability}_admin`, node);
        await (enable ? write([tuple]) : remove([tuple]));
      },
    );
  }

  return {
    /** Platform operator only: the caller of this must be authorised outside the tenant. */
    async bootstrap(
      operator: string,
      root: string,
      admin: string,
      requestId?: string,
    ) {
      const node = unitOf(root);
      if (!ACTOR.test(operator) || !ACTOR.test(admin)) {
        throw invalid("operator and admin must be a user or service.");
      }
      return audited(
        operator,
        "tenant.bootstrap",
        { unit: node, admin },
        requestId,
        async () => {
          if (
            (
              await read({
                user: "user:*",
                relation: "is_root",
                object: "org_unit:",
              })
            ).length > 0
          ) {
            throw conflict("The tenant already has a root.");
          }
          await write([
            ...PRINCIPAL_TYPES.map((t) => ({
              user: `${t}:*`,
              relation: "is_root",
              object: node,
            })),
            ...CAPABILITIES.flatMap((c) =>
              ["user:*", "service:*"].map((user) => ({
                user,
                relation: `${c}_admin_ceiling`,
                object: node,
              })),
            ),
            ...CAPABILITIES.map((c) => ({
              user: admin,
              relation: `${c}_admin_grant`,
              object: node,
            })),
            ...defaultAllowlists(node),
          ]);
        },
      );
    },

    async createUnit(
      actor: string,
      unit: string,
      parent: string,
      requestId?: string,
    ) {
      const node = unitOf(unit);
      const parentNode = unitOf(parent);
      return audited(
        actor,
        "tenant.unit.create",
        { unit: node, parent: parentNode },
        requestId,
        async () => {
          await requireRelation(actor, "settings_admin", parentNode);
          const existing = [
            ...(await read({ object: node, relation: "parent" })),
            ...(await read({ object: node, relation: "is_root" })),
          ];
          if (existing.length > 0) throw conflict("The unit already exists.");
          if ((await depthOf(parent)) + 1 > maxDepth) {
            throw invalid(
              `The tree would exceed the depth cap of ${maxDepth}.`,
            );
          }
          await write([
            { user: parentNode, relation: "parent", object: node },
            ...defaultAllowlists(node),
          ]);
        },
      );
    },

    grant: (
      actor: string,
      capability: Capability,
      subject: string,
      unit: string,
      requestId?: string,
    ) => adminGrant(actor, capability, subject, unit, true, requestId),

    revoke: (
      actor: string,
      capability: Capability,
      subject: string,
      unit: string,
      requestId?: string,
    ) => adminGrant(actor, capability, subject, unit, false, requestId),

    /**
     * Clearing a ceiling leaves descendants' ceilings in place: they stay in the audit
     * trail and only take effect while an ancestor still holds the capability.
     */
    async setCeiling(
      actor: string,
      capability: Capability,
      unit: string,
      enable: boolean,
      requestId?: string,
    ) {
      oneOf(CAPABILITIES, capability, "capability");
      const node = unitOf(unit);
      const tuples = ["user:*", "service:*"].map((user) => ({
        user,
        relation: `${capability}_admin_ceiling`,
        object: node,
      }));
      return audited(
        actor,
        enable ? "tenant.ceiling.set" : "tenant.ceiling.clear",
        { capability, unit: node },
        requestId,
        async () => {
          await requireRelation(
            actor,
            `can_set_${capability}_admin_ceiling`,
            node,
          );
          await (enable ? write(tuples) : remove(tuples));
        },
      );
    },

    async setGuardrail(
      actor: string,
      unit: string,
      action: Action,
      list: GuardrailList,
      subject: string,
      enable: boolean,
      requestId?: string,
    ) {
      oneOf(ACTIONS, action, "action");
      oneOf(["allowlist", "blocklist"], list, "list");
      const node = unitOf(unit);
      if (!GUARDRAIL_SUBJECT.test(subject)) throw invalid("Invalid subject.");
      const tuple = {
        user: subject,
        relation: `${action}_${list}`,
        object: node,
      };
      return audited(
        actor,
        enable ? "tenant.guardrail.set" : "tenant.guardrail.clear",
        { unit: node, action, list, subject },
        requestId,
        async () => {
          await requireRelation(actor, "can_set_guardrails", node);
          await (enable ? write([tuple]) : remove([tuple]));
        },
      );
    },

    async placeResource(
      actor: string,
      type: ResourceType,
      id: string,
      unit: string,
      requestId?: string,
    ) {
      oneOf(RESOURCE_TYPES, type, "resource type");
      if (!RESOURCE_ID.test(id)) throw invalid("Invalid resource id.");
      const node = unitOf(unit);
      const object = `${type}:${id}`;
      return audited(
        actor,
        "tenant.resource.place",
        { resource: object, unit: node },
        requestId,
        async () => {
          await requireRelation(actor, "app_admin", node);
          if ((await read({ object, relation: "unit" })).length > 0) {
            throw conflict("The resource already belongs to a unit.");
          }
          await write([{ user: node, relation: "unit", object }]);
        },
      );
    },
  };
}

export type TenantService = ReturnType<typeof createTenantService>;
