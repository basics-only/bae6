import { randomBytes } from "node:crypto";
import type { Pool } from "pg";
import { ACTION, MAX_DELEGATED, RESOURCE } from "./tokens.js";

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const TASK_ID = /^[A-Za-z0-9._-]{1,128}$/;
const PRINCIPAL_ID = /^prn_[0-9a-f]{32}$/;
const DELEGATION_ID = /^dlg_[0-9a-f]{32}$/;
const MAX_DEPTH = 8;

export type DelegationErrorCode =
  | "invalid_request"
  | "unknown_principal"
  | "principal_inactive"
  | "invalid_actor"
  | "unknown_parent"
  | "exceeds_parent"
  | "exceeds_limit"
  | "approval_required";

export class DelegationError extends Error {
  constructor(
    readonly code: DelegationErrorCode,
    options?: ErrorOptions,
  ) {
    super(code, options);
  }
}

export interface DelegationLimits {
  maxLifetimeSeconds: number;
  maxDepth: number;
  highImpact?: (action: string) => boolean;
}

export interface NewDelegation {
  tenantId: string;
  initiatingPrincipalId: string;
  actorPrincipalId: string;
  applicationId: string;
  taskId: string;
  parentDelegationId?: string;
  createdByPrincipalId?: string;
  allowedResources: string[];
  allowedActions: string[];
  approvedActions?: string[];
  expiresAt: Date;
  policyVersion: string;
}

const distinct = (values: string[], max: number, pattern: RegExp) =>
  Array.isArray(values) &&
  values.length >= 1 &&
  values.length <= max &&
  new Set(values).size === values.length &&
  values.every((v) => typeof v === "string" && pattern.test(v));

const subset = (child: string[], parent: string[]) => {
  const allowed = new Set(parent);
  return child.every((v) => allowed.has(v));
};

function validate(limits: DelegationLimits, d: NewDelegation) {
  const approved = d.approvedActions ?? [];
  const lifetime =
    d.expiresAt instanceof Date
      ? d.expiresAt.getTime() - Date.now()
      : Number.NaN;
  if (
    !Number.isInteger(limits.maxDepth) ||
    limits.maxDepth < 1 ||
    limits.maxDepth > MAX_DEPTH ||
    !(limits.maxLifetimeSeconds > 0) ||
    !Number.isFinite(limits.maxLifetimeSeconds) ||
    !SLUG.test(d.tenantId) ||
    !PRINCIPAL_ID.test(d.initiatingPrincipalId) ||
    !PRINCIPAL_ID.test(d.actorPrincipalId) ||
    d.initiatingPrincipalId === d.actorPrincipalId ||
    !SLUG.test(d.applicationId) ||
    !TASK_ID.test(d.taskId) ||
    (d.parentDelegationId !== undefined &&
      !DELEGATION_ID.test(d.parentDelegationId)) ||
    !distinct(d.allowedResources, MAX_DELEGATED, RESOURCE) ||
    !distinct(d.allowedActions, MAX_DELEGATED, ACTION) ||
    !Array.isArray(approved) ||
    (approved.length > 0 && !distinct(approved, MAX_DELEGATED, ACTION)) ||
    !(d.expiresAt instanceof Date) ||
    !subset(approved, d.allowedActions) ||
    typeof d.policyVersion !== "string" ||
    d.policyVersion.length < 1 ||
    d.policyVersion.length > 64 ||
    !(lifetime > 0)
  )
    throw new DelegationError("invalid_request");
  if (lifetime > limits.maxLifetimeSeconds * 1000)
    throw new DelegationError("exceeds_limit");
  const approvedSet = new Set(approved);
  if (
    d.allowedActions.some((a) => limits.highImpact?.(a) && !approvedSet.has(a))
  )
    throw new DelegationError("approval_required");
}

interface ParentRow {
  tenant_id: string;
  initiating_principal_id: string;
  actor_principal_id: string;
  application_id: string;
  task_id: string;
  depth: number;
  allowed_resources: string[];
  allowed_actions: string[];
  approved_actions: string[];
  expires_at: Date;
}

export async function createDelegation(
  db: Pool,
  limits: DelegationLimits,
  input: NewDelegation,
): Promise<{ id: string }> {
  validate(limits, input);
  const id = `dlg_${randomBytes(16).toString("hex")}`;
  const client = await db.connect();
  let broken = false;
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`delegations:${input.tenantId}`],
    );
    let depth = 1;
    if (input.parentDelegationId !== undefined) {
      const { rows } = await client.query<ParentRow>(
        `SELECT tenant_id, initiating_principal_id, actor_principal_id, application_id, task_id,
                depth, allowed_resources, allowed_actions, approved_actions, expires_at
           FROM delegations
          WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > now()
            FOR SHARE`,
        [input.parentDelegationId, input.tenantId],
      );
      const parent = rows[0];
      if (!parent) throw new DelegationError("unknown_parent");
      if (
        parent.actor_principal_id !== input.createdByPrincipalId ||
        parent.initiating_principal_id !== input.initiatingPrincipalId ||
        parent.application_id !== input.applicationId ||
        parent.task_id !== input.taskId ||
        input.expiresAt > parent.expires_at ||
        !subset(input.allowedResources, parent.allowed_resources) ||
        !subset(input.allowedActions, parent.allowed_actions) ||
        !subset(input.approvedActions ?? [], parent.approved_actions)
      )
        throw new DelegationError("exceeds_parent");
      depth = parent.depth + 1;
      if (depth > limits.maxDepth) throw new DelegationError("exceeds_limit");
    }
    const { rows: principals } = await client.query<{
      id: string;
      type: string;
      status: string;
      owner_application_id: string | null;
    }>(
      "SELECT id, type, status, owner_application_id FROM principals WHERE tenant_id = $1 AND id = ANY($2) FOR SHARE",
      [input.tenantId, [input.initiatingPrincipalId, input.actorPrincipalId]],
    );
    if (principals.length !== 2) throw new DelegationError("unknown_principal");
    if (principals.some((p) => p.status !== "active"))
      throw new DelegationError("principal_inactive");
    const actor = principals.find((p) => p.id === input.actorPrincipalId);
    if (
      actor?.type === "agent"
        ? actor.owner_application_id !== input.applicationId
        : actor?.type !== "service"
    )
      throw new DelegationError("invalid_actor");
    await client.query(
      `INSERT INTO delegations
         (id, tenant_id, initiating_principal_id, actor_principal_id, application_id,
          task_id, parent_id, depth, allowed_resources, allowed_actions, approved_actions,
          policy_version, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        id,
        input.tenantId,
        input.initiatingPrincipalId,
        input.actorPrincipalId,
        input.applicationId,
        input.taskId,
        input.parentDelegationId ?? null,
        depth,
        input.allowedResources,
        input.allowedActions,
        input.approvedActions ?? [],
        input.policyVersion,
        input.expiresAt,
      ],
    );
    await client.query("COMMIT");
    return { id };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {
      broken = true;
    });
    throw err;
  } finally {
    client.release(broken);
  }
}

export async function revokeDelegation(
  db: Pool,
  tenantId: string,
  id: string,
  initiator: string,
): Promise<number | undefined> {
  const client = await db.connect();
  let broken = false;
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`delegations:${tenantId}`],
    );
    const { rows } = await client.query<{ found: boolean; revoked: number }>(
      `WITH RECURSIVE root AS (
         SELECT id FROM delegations
          WHERE tenant_id = $1 AND id = $2 AND initiating_principal_id = $3
       ), tree AS (
         SELECT id FROM root
         UNION ALL
         SELECT d.id FROM delegations d JOIN tree t ON d.parent_id = t.id
          WHERE d.tenant_id = $1
       ), updated AS (
         UPDATE delegations SET revoked_at = now()
          WHERE id IN (SELECT id FROM tree) AND revoked_at IS NULL
          RETURNING id
       )
       SELECT EXISTS (SELECT FROM root) AS found,
              (SELECT count(*)::int FROM updated) AS revoked`,
      [tenantId, id, initiator],
    );
    await client.query("COMMIT");
    return rows[0]?.found ? rows[0].revoked : undefined;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {
      broken = true;
    });
    throw err;
  } finally {
    client.release(broken);
  }
}

export async function liveDelegationExpiry(
  db: Pool,
  claims: {
    delegationId: string;
    tenantId: string;
    initiatingPrincipalId: string;
    actorPrincipalId: string;
    taskId: string;
    applicationId: string | undefined;
  },
): Promise<Date | undefined> {
  const { rows } = await db.query<{ expires_at: Date }>(
    `SELECT expires_at FROM delegations
      WHERE id = $1 AND tenant_id = $2 AND initiating_principal_id = $3
        AND actor_principal_id = $4 AND task_id = $5 AND application_id = $6
        AND revoked_at IS NULL AND expires_at > now()`,
    [
      claims.delegationId,
      claims.tenantId,
      claims.initiatingPrincipalId,
      claims.actorPrincipalId,
      claims.taskId,
      claims.applicationId ?? null,
    ],
  );
  return rows[0]?.expires_at;
}
