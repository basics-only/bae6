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
const CHECK_BUDGET_MS = 2000;
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
const CHECK_RELATION: Record<(typeof RESOURCE_TYPES)[number], string> = {
  application: "can_use",
  api: "can_call",
  model: "can_invoke",
  agent_definition: "can_run",
  prompt: "can_use",
  mcp_server: "can_use",
  dataset: "can_query",
  document: "can_read",
  tool: "can_invoke",
  service_resource: "can_call",
};
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
const UNIT = /^[a-z0-9][a-z0-9-]{0,62}$/;
const PLACEABLE = /^(user|service|agent|application):(prn_[0-9a-f]{32})$/;
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

export function createTenantService(deps: {
  pool: pg.Pool;
  client: OpenFgaClient;
  organization: string;
  maxDepth?: number;
  placements?: {
    place(input: {
      tenantId: string;
      principalId: string;
      orgPath: string[];
    }): Promise<unknown>;
  };
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

  const dispatchable = () => {
    if ((deadline.getStore() ?? Infinity) <= Date.now()) throw unavailable();
  };

  const write = (writes: Tuple[]) => {
    dispatchable();
    return fga(
      () => client.write({ writes }),
      (m) => (/already exist/i.test(m) ? conflict(m) : invalid(m)),
    ).catch(markAmbiguous);
  };

  const remove = (deletes: Tuple[]) => {
    dispatchable();
    return fga(
      () => client.write({ deletes }),
      (m) =>
        /does not exist/i.test(m)
          ? new HttpError(404, "not_found", "Tuple not found.")
          : invalid(m),
    ).catch(markAmbiguous);
  };

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
      await db.query("COMMIT").catch((err) => {
        if (err instanceof Error) ambiguous.add(err);
        throw err;
      });
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

  // shortcut: a COMMIT that fails after OpenFGA accepted leaves an unaudited change, upgrade to an outbox.
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
      await boundedAudit(pool, {
        ...event,
        outcome:
          err instanceof HttpError && err.status === 403 ? "denied" : "error",
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
      throw err;
    }
  }

  const rewrite = (writes: Tuple[], deletes: Tuple[]) => {
    dispatchable();
    return fga(
      () => client.write({ writes, deletes }),
      (m) => (/already exist/i.test(m) ? conflict(m) : invalid(m)),
    ).catch(markAmbiguous);
  };

  async function pathOf(unit: string): Promise<string[]> {
    const path = [unit];
    for (;;) {
      const parents = await read({
        object: `org_unit:${path[0]}`,
        relation: "parent",
      });
      const parent = parents[0];
      if (!parent) break;
      if (parents.length > 1 || path.length > MAX_DEPTH)
        throw new HttpError(500, "internal", "The unit tree is malformed.");
      path.unshift(parent.key.user.slice("org_unit:".length));
    }
    if (path[0] !== organization)
      throw new HttpError(404, "not_found", "Unknown unit.");
    return path;
  }

  const isRoot = async (node: string) =>
    (await read({ object: node, relation: "is_root" })).length > 0;

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
        if (!enable && (await isRoot(node))) {
          const { tuples } = await fga(
            () =>
              client.read(
                { object: node, relation: tuple.relation },
                { pageSize: 2 },
              ),
            unavailable,
          );
          const others = tuples.filter((t) => t.key.user !== subject);
          if (others.length === 0) {
            throw conflict(
              "The root must keep an administrator for each capability.",
            );
          }
        }
        await (enable ? write([tuple]) : remove([tuple]));
      },
    );
  }

  return {
    async bootstrap(
      operator: string,
      root: string,
      admin: string,
      requestId?: string,
    ) {
      const node = unitOf(root);
      if (root !== organization)
        throw invalid("The root unit must be named after the tenant.");
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
          if (
            !(await isRoot(parentNode)) &&
            (await read({ object: parentNode, relation: "parent" })).length ===
              0
          ) {
            throw new HttpError(
              404,
              "not_found",
              "The parent unit does not exist.",
            );
          }
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
          const present = (
            await read({
              object: node,
              relation: `${capability}_admin_ceiling`,
            })
          ).map((t) => t.key as Tuple);
          if (enable) {
            const missing = tuples.filter(
              (t) => !present.some((p) => p.user === t.user),
            );
            if (missing.length === 0) {
              throw conflict("The ceiling is already set.");
            }
            return void (await write(missing));
          }
          if (await isRoot(node))
            throw conflict("The root ceiling must remain.");
          if (present.length === 0)
            throw new HttpError(404, "not_found", "Tuple not found.");
          await remove(present);
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

    async placePrincipal(
      actor: string,
      subject: string,
      unit: string,
      requestId?: string,
    ) {
      const match = PLACEABLE.exec(subject);
      if (!match)
        throw invalid(
          "subject must be a user, service, agent or application principal.",
        );
      const principalId = match[2] as string;
      const node = unitOf(unit);
      if (!deps.placements)
        throw new HttpError(500, "internal", "Placement is not configured.");
      const { placements } = deps;
      return audited(
        actor,
        "tenant.principal.place",
        { subject, unit: node },
        requestId,
        async () => {
          const orgPath = await pathOf(unit);
          await requireRelation(actor, "access_admin", node);
          const current = await read({
            user: subject,
            relation: "placed",
            object: "org_unit:",
          });
          if (current.length > 1)
            throw new HttpError(
              500,
              "internal",
              "A principal has more than one unit.",
            );
          const old = current[0]?.key as Tuple | undefined;
          if (old && old.object !== node) {
            await requireRelation(actor, "access_admin", old.object);
          }
          await placements
            .place({ tenantId: organization, principalId, orgPath })
            .catch((err: { status?: number }) => {
              if (
                err.status === 400 ||
                err.status === 404 ||
                err.status === 409
              )
                throw new HttpError(
                  err.status,
                  err.status === 409 ? "conflict" : "invalid_request",
                  "authn refused the placement.",
                );
              throw new HttpError(
                503,
                "placement_unavailable",
                "authn did not accept the placement; repeat the request.",
              );
            });
          if (old?.object !== node) {
            await rewrite(
              [{ user: subject, relation: "placed", object: node }],
              old ? [old] : [],
            );
          }
        },
      );
    },

    async check(subject: string, type: ResourceType, id: string) {
      if (!PLACEABLE.test(subject))
        throw forbidden("This principal cannot be checked.");
      oneOf(RESOURCE_TYPES, type, "resource type");
      if (!RESOURCE_ID.test(id)) throw invalid("Invalid resource id.");
      return deadline.run(Date.now() + CHECK_BUDGET_MS, () =>
        holds(subject, CHECK_RELATION[type], `${type}:${id}`),
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
