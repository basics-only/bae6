import { randomBytes } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { VerifiedLogin } from "./oidc.js";

const MAX_GROUPS = 1000;
const MAX_OVERAGE_GROUPS = 20_000;
const MAX_GROUP_LENGTH = 256;

export type PrincipalErrorCode =
  | "invalid_request"
  | "connection_unavailable"
  | "invalid_identity"
  | "unknown_identity"
  | "principal_inactive"
  | "principal_not_user"
  | "invalid_groups"
  | "group_overage_unresolved"
  | "unknown_principal"
  | "unknown_connection"
  | "invalid_transition"
  | "identity_already_linked";

export class PrincipalError extends Error {
  constructor(
    readonly code: PrincipalErrorCode,
    options?: ErrorOptions,
  ) {
    super(code, options);
  }
}

export interface ConnectionPolicy {
  tenantId: string;
  id: string;
  kind: "pingfederate" | "entra" | "okta" | "oidc";
  issuer: string;
  status: "active" | "disabled";
  jitProvisioning: boolean;
  groupClaim: string | null;
}

export interface ResolvedPrincipal {
  principalId: string;
  tenantId: string;
  groupPrincipalIds: string[];
  created: boolean;
}

export type PrincipalStatus = "active" | "disabled" | "deprovisioned";

const newId = (prefix: string) =>
  `${prefix}_${randomBytes(16).toString("hex")}`;

function checkActor(actor: string) {
  if (actor.length < 1 || actor.length > 128)
    throw new PrincipalError("invalid_request");
}

async function inTransaction<T>(
  db: Pool,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await db.connect();
  let broken: Error | undefined;
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch((rollbackErr: Error) => {
      broken = rollbackErr;
    });
    throw err;
  } finally {
    client.release(broken);
  }
}

const CONNECTION_SQL = `SELECT tenant_id AS "tenantId", id, kind, issuer, status,
    jit_provisioning AS "jitProvisioning", group_claim AS "groupClaim"
  FROM provider_connections WHERE tenant_id = $1 AND id = $2`;

export async function loadConnection(
  db: Pool,
  tenantId: string,
  id: string,
): Promise<ConnectionPolicy | undefined> {
  return (await db.query<ConnectionPolicy>(CONNECTION_SQL, [tenantId, id]))
    .rows[0];
}

interface ExternalKey {
  issuer: string;
  subject: string;
  externalTenantId: string | null;
  externalObjectId: string | null;
}

function externalKey(
  connection: ConnectionPolicy,
  identity: VerifiedLogin["identity"],
): ExternalKey {
  const { issuer, subject, claims } = identity;
  if (
    issuer !== connection.issuer ||
    subject.length < 1 ||
    subject.length > 256
  )
    throw new PrincipalError("invalid_identity");
  if (connection.kind !== "entra")
    return { issuer, subject, externalTenantId: null, externalObjectId: null };
  const { tid, oid } = claims;
  if (
    typeof tid !== "string" ||
    typeof oid !== "string" ||
    tid.length < 1 ||
    tid.length > 128 ||
    oid.length < 1 ||
    oid.length > 256 ||
    !new URL(issuer).pathname.split("/").includes(tid)
  )
    throw new PrincipalError("invalid_identity");
  return { issuer, subject, externalTenantId: tid, externalObjectId: oid };
}

export function hasGroupOverage(
  connection: Pick<ConnectionPolicy, "groupClaim">,
  claims: Readonly<Record<string, unknown>>,
): boolean {
  const claim = connection.groupClaim;
  if (!claim) return false;
  const pointers = claims._claim_names;
  return (
    typeof pointers === "object" &&
    pointers !== null &&
    Object.hasOwn(pointers, claim)
  );
}

function externalGroups(
  connection: ConnectionPolicy,
  claims: Readonly<Record<string, unknown>>,
  overageGroups: unknown,
): string[] {
  const claim = connection.groupClaim;
  if (!claim) return [];
  let value: unknown;
  let limit = MAX_GROUPS;
  if (hasGroupOverage(connection, claims)) {
    if (overageGroups === undefined)
      throw new PrincipalError("group_overage_unresolved");
    value = overageGroups;
    limit = MAX_OVERAGE_GROUPS;
  } else if (Object.hasOwn(claims, claim)) value = claims[claim];
  else return [];
  if (
    !Array.isArray(value) ||
    value.length > limit ||
    !value.every(
      (g) =>
        typeof g === "string" && g.length >= 1 && g.length <= MAX_GROUP_LENGTH,
    )
  )
    throw new PrincipalError("invalid_groups");
  return [...new Set(value as string[])];
}

async function findLinked(
  db: Pool,
  connection: ConnectionPolicy,
  key: ExternalKey,
) {
  const { rows } = await db.query<{
    id: string;
    status: PrincipalStatus;
    type: string;
  }>(
    `UPDATE external_identities e
        SET last_verified_at = CASE WHEN p.status = 'active' AND p.type = 'user'
                                    THEN now() ELSE e.last_verified_at END
       FROM principals p
      WHERE e.tenant_id = $1 AND e.provider_connection_id = $2 AND e.issuer = $3
        AND e.subject = $4 AND e.external_tenant_id IS NOT DISTINCT FROM $5
        AND p.tenant_id = e.tenant_id AND p.id = e.principal_id
      RETURNING p.id, p.status, p.type`,
    [
      connection.tenantId,
      connection.id,
      key.issuer,
      key.subject,
      key.externalTenantId,
    ],
  );
  return rows[0];
}

class LostRace extends Error {}

async function createJit(
  db: Pool,
  connection: ConnectionPolicy,
  key: ExternalKey,
): Promise<string | undefined> {
  try {
    return await insertJit(db, connection, key);
  } catch (err) {
    if (err instanceof LostRace) return undefined;
    throw err;
  }
}

function insertJit(db: Pool, connection: ConnectionPolicy, key: ExternalKey) {
  return inTransaction(db, async (client) => {
    const principalId = newId("prn");
    const identityId = newId("xid");
    await client.query(
      "INSERT INTO principals (id, tenant_id, type) VALUES ($1, $2, 'user')",
      [principalId, connection.tenantId],
    );
    const linked = await client.query(
      `INSERT INTO external_identities
         (id, tenant_id, principal_id, provider_connection_id, issuer, subject,
          external_tenant_id, external_object_id, last_verified_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
       ON CONFLICT DO NOTHING RETURNING id`,
      [
        identityId,
        connection.tenantId,
        principalId,
        connection.id,
        key.issuer,
        key.subject,
        key.externalTenantId,
        key.externalObjectId,
      ],
    );
    if (linked.rowCount === 0) throw new LostRace();
    await client.query(
      `INSERT INTO principal_events (tenant_id, principal_id, type, actor, detail)
       VALUES ($1, $2, 'created', $3, $4)`,
      [
        connection.tenantId,
        principalId,
        `jit:${connection.id}`,
        { externalIdentityId: identityId },
      ],
    );
    return principalId;
  });
}

async function mappedGroups(
  db: Pool,
  connection: ConnectionPolicy,
  groups: string[],
) {
  if (groups.length === 0) return [];
  const { rows } = await db.query<{ id: string }>(
    `SELECT m.group_principal_id AS id
       FROM group_mappings m
       JOIN principals g ON g.tenant_id = m.tenant_id AND g.id = m.group_principal_id
      WHERE m.tenant_id = $1 AND m.provider_connection_id = $2
        AND m.external_group = ANY($3) AND g.status = 'active'
      ORDER BY 1`,
    [connection.tenantId, connection.id, groups],
  );
  return rows.map((r) => r.id);
}

export async function resolvePrincipal(
  db: Pool,
  connection: ConnectionPolicy,
  identity: VerifiedLogin["identity"],
  overageGroups?: unknown,
): Promise<ResolvedPrincipal> {
  if (connection.status !== "active")
    throw new PrincipalError("connection_unavailable");
  const key = externalKey(connection, identity);
  const groups = externalGroups(connection, identity.claims, overageGroups);
  let principal = await findLinked(db, connection, key);
  let created = false;
  if (!principal) {
    if (!connection.jitProvisioning)
      throw new PrincipalError("unknown_identity");
    const id = await createJit(db, connection, key);
    if (id) {
      principal = { id, status: "active", type: "user" };
      created = true;
    } else {
      principal = await findLinked(db, connection, key);
      if (!principal)
        throw new Error(
          "external identity vanished after a conflicting insert",
        );
    }
  }
  if (principal.type !== "user") throw new PrincipalError("principal_not_user");
  if (principal.status !== "active")
    throw new PrincipalError("principal_inactive");
  return {
    principalId: principal.id,
    tenantId: connection.tenantId,
    groupPrincipalIds: await mappedGroups(db, connection, groups),
    created,
  };
}

const EVENT: Record<PrincipalStatus, string> = {
  active: "enabled",
  disabled: "disabled",
  deprovisioned: "deprovisioned",
};

export function setPrincipalStatus(
  db: Pool,
  change: {
    tenantId: string;
    principalId: string;
    status: PrincipalStatus;
    actor: string;
  },
): Promise<void> {
  checkActor(change.actor);
  return inTransaction(db, async (client) => {
    const { rows } = await client.query<{ status: PrincipalStatus }>(
      "SELECT status FROM principals WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
      [change.tenantId, change.principalId],
    );
    const current = rows[0]?.status;
    if (!current) throw new PrincipalError("unknown_principal");
    if (current === change.status) return;
    if (current === "deprovisioned")
      throw new PrincipalError("invalid_transition");
    await client.query(
      "UPDATE principals SET status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2",
      [change.tenantId, change.principalId, change.status],
    );
    if (change.status !== "active") {
      await client.query(
        `UPDATE sessions SET revoked_at = now()
          WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL`,
        [change.tenantId, change.principalId],
      );
    }
    await client.query(
      `INSERT INTO principal_events (tenant_id, principal_id, type, actor)
       VALUES ($1, $2, $3, $4)`,
      [change.tenantId, change.principalId, EVENT[change.status], change.actor],
    );
  });
}

export async function linkExternalIdentity(
  db: Pool,
  link: {
    tenantId: string;
    principalId: string;
    connectionId: string;
    subject: string;
    externalTenantId?: string;
    externalObjectId?: string;
    actor: string;
    proof: "admin" | "verified_login";
  },
): Promise<string> {
  checkActor(link.actor);
  return inTransaction(db, async (client) => {
    const connection = (
      await client.query<ConnectionPolicy>(`${CONNECTION_SQL} FOR SHARE`, [
        link.tenantId,
        link.connectionId,
      ])
    ).rows[0];
    if (!connection) throw new PrincipalError("unknown_connection");
    if (connection.status !== "active")
      throw new PrincipalError("connection_unavailable");
    const key = externalKey(connection, {
      issuer: connection.issuer,
      subject: link.subject,
      claims: { tid: link.externalTenantId, oid: link.externalObjectId },
    });
    if (
      connection.kind !== "entra" &&
      (link.externalTenantId || link.externalObjectId)
    )
      throw new PrincipalError("invalid_identity");
    const { rows } = await client.query<{
      status: PrincipalStatus;
      type: string;
    }>(
      "SELECT status, type FROM principals WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
      [link.tenantId, link.principalId],
    );
    if (!rows[0]) throw new PrincipalError("unknown_principal");
    if (rows[0].type !== "user") throw new PrincipalError("principal_not_user");
    if (rows[0].status !== "active")
      throw new PrincipalError("principal_inactive");
    const identityId = newId("xid");
    const inserted = await client.query(
      `INSERT INTO external_identities
         (id, tenant_id, principal_id, provider_connection_id, issuer, subject,
          external_tenant_id, external_object_id, last_verified_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
       ON CONFLICT DO NOTHING`,
      [
        identityId,
        link.tenantId,
        link.principalId,
        connection.id,
        key.issuer,
        key.subject,
        key.externalTenantId,
        key.externalObjectId,
      ],
    );
    if (inserted.rowCount === 0)
      throw new PrincipalError("identity_already_linked");
    await client.query(
      `INSERT INTO principal_events (tenant_id, principal_id, type, actor, detail)
       VALUES ($1, $2, 'linked', $3, $4)`,
      [
        link.tenantId,
        link.principalId,
        link.actor,
        {
          externalIdentityId: identityId,
          connectionId: connection.id,
          proof: link.proof,
        },
      ],
    );
    return identityId;
  });
}

const ORG_UNIT = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function setPrincipalOrgPath(
  db: Pool,
  change: {
    tenantId: string;
    principalId: string;
    principalType: string;
    orgPath: string[];
    actor: string;
  },
): Promise<void> {
  checkActor(change.actor);
  const { orgPath } = change;
  if (
    !Array.isArray(orgPath) ||
    orgPath.length < 1 ||
    orgPath.length > 32 ||
    orgPath[0] !== change.tenantId ||
    !orgPath.every((unit) => typeof unit === "string" && ORG_UNIT.test(unit))
  )
    throw new PrincipalError("invalid_request");
  return inTransaction(db, async (client) => {
    const { rows } = await client.query<{
      status: PrincipalStatus;
      type: string;
      org_path: string[];
    }>(
      "SELECT status, type, org_path FROM principals WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
      [change.tenantId, change.principalId],
    );
    const current = rows[0];
    if (!current) throw new PrincipalError("unknown_principal");
    if (current.type !== change.principalType)
      throw new PrincipalError("invalid_request");
    if (current.status === "deprovisioned")
      throw new PrincipalError("invalid_transition");
    if (current.org_path.join() === orgPath.join()) return;
    await client.query(
      "UPDATE principals SET org_path = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2",
      [change.tenantId, change.principalId, orgPath],
    );
    await client.query(
      `INSERT INTO principal_events (tenant_id, principal_id, type, actor, detail)
       VALUES ($1, $2, 'placed', $3, $4)`,
      [
        change.tenantId,
        change.principalId,
        change.actor,
        { from: current.org_path, to: orgPath },
      ],
    );
  });
}
