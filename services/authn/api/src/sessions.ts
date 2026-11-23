import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Pool } from "pg";
import { PrincipalError } from "./principals.js";

export const SESSION_COOKIE = "__Host-bae6-session";
export const MAX_SESSION_TTL_SECONDS = 24 * 60 * 60;
const COOKIE_VALUE = /^(ses_[0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/;

export interface Session {
  id: string;
  tenantId: string;
  principalId: string;
  connectionId: string;
  expiresAt: Date;
  csrfToken: string;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest();
const csrfFor = (secret: string) =>
  createHash("sha256").update(`csrf\0${secret}`).digest("base64url");

export async function createSession(
  db: Pool,
  input: {
    tenantId: string;
    principalId: string;
    connectionId: string;
    ttlSeconds: number;
  },
): Promise<{ cookie: string; session: Session }> {
  if (
    !Number.isInteger(input.ttlSeconds) ||
    input.ttlSeconds < 60 ||
    input.ttlSeconds > MAX_SESSION_TTL_SECONDS
  )
    throw new RangeError("session TTL must be 60 s to 24 h");
  const id = `ses_${randomBytes(16).toString("hex")}`;
  const secret = randomBytes(32).toString("base64url");
  const csrfToken = csrfFor(secret);
  // FOR SHARE waits on a concurrent status change, so a disabled principal never gets a session.
  const { rows } = await db.query<{ expiresAt: Date }>(
    `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash,
         provider_connection_id, expires_at)
     SELECT $1, p.tenant_id, p.id, $4, $5, $6, now() + make_interval(secs => $7)
       FROM principals p
      WHERE p.tenant_id = $2 AND p.id = $3 AND p.status = 'active' AND p.type = 'user'
      FOR SHARE
     RETURNING expires_at AS "expiresAt"`,
    [
      id,
      input.tenantId,
      input.principalId,
      sha256(secret),
      sha256(csrfToken),
      input.connectionId,
      input.ttlSeconds,
    ],
  );
  const row = rows[0];
  if (!row) throw new PrincipalError("principal_inactive");
  return {
    cookie: `${id}.${secret}`,
    session: {
      id,
      tenantId: input.tenantId,
      principalId: input.principalId,
      connectionId: input.connectionId,
      expiresAt: row.expiresAt,
      csrfToken,
    },
  };
}

export async function readSession(
  db: Pool,
  cookie: string | undefined,
): Promise<Session | undefined> {
  const m = cookie ? COOKIE_VALUE.exec(cookie) : null;
  if (!m) return undefined;
  const [, id, secret] = m as unknown as [string, string, string];
  const { rows } = await db.query<{
    tenantId: string;
    principalId: string;
    connectionId: string;
    expiresAt: Date;
    secretHash: Buffer;
  }>(
    `SELECT s.tenant_id AS "tenantId", s.principal_id AS "principalId",
            s.provider_connection_id AS "connectionId", s.expires_at AS "expiresAt",
            s.secret_hash AS "secretHash"
       FROM sessions s
       JOIN principals p ON p.tenant_id = s.tenant_id AND p.id = s.principal_id
       JOIN provider_connections c
         ON c.tenant_id = s.tenant_id AND c.id = s.provider_connection_id
      WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
        AND p.status = 'active' AND c.status = 'active'`,
    [id],
  );
  const row = rows[0];
  if (!row || !timingSafeEqual(row.secretHash, sha256(secret)))
    return undefined;
  return {
    id,
    tenantId: row.tenantId,
    principalId: row.principalId,
    connectionId: row.connectionId,
    expiresAt: row.expiresAt,
    csrfToken: csrfFor(secret),
  };
}

export function csrfMatches(session: Session, supplied: unknown): boolean {
  if (typeof supplied !== "string" || supplied.length !== 43) return false;
  return timingSafeEqual(sha256(supplied), sha256(session.csrfToken));
}

export async function revokeSession(db: Pool, id: string): Promise<void> {
  await db.query(
    "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    [id],
  );
}
