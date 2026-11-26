import { randomBytes } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import type { Pool } from "pg";
import {
  activeSigner,
  CLOCK_SKEW_SECONDS,
  publishedKeys,
  type Signer,
  TOKEN_TTL_SECONDS,
} from "./keys.js";

export const TOKEN_TYPE = "bae6+jwt";

const PRINCIPAL_ID = /^prn_[0-9a-f]{32}$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const REQUEST_ID = /^[A-Za-z0-9._-]{1,64}$/;
const SESSION_ID = /^ses_[0-9a-f]{32}$/;
const TRACE_ID = /^[0-9a-f]{32}$/;
const TASK_ID = /^[A-Za-z0-9._-]{1,128}$/;
const DELEGATION_ID = /^dlg_[0-9a-f]{32}$/;
const JTI = /^[A-Za-z0-9_-]{16,64}$/;
export const RESOURCE =
  /^(application|api|model|agent|prompt|mcp_server|tool|dataset|document|service):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const ACTION = /^[a-z][a-z0-9_]{0,31}:[a-z][a-z0-9_]{0,31}$/;
export const MAX_DELEGATED = 16;
const PRINCIPAL_TYPES = new Set([
  "user",
  "group",
  "service",
  "application",
  "agent",
]);

export interface Bae6Claims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  txn: string;
  tenant_id: string;
  org_path: string[];
  principal_type: string;
  act?: { sub: string; principal_type: "agent" | "service" };
  application_id?: string;
  session_id?: string;
  task_id?: string;
  delegation_id?: string;
  delegated_resources?: string[];
  delegated_actions?: string[];
  cost_center_id?: string;
  trace_id?: string;
}

export type MintInput = Omit<Bae6Claims, "iss" | "iat" | "exp" | "jti"> & {
  notAfter?: number;
};

export class TokenError extends Error {}

const b64url = (data: string | Uint8Array) =>
  Buffer.from(data).toString("base64url");

const OPTIONAL: [keyof Bae6Claims, RegExp][] = [
  ["application_id", SLUG],
  ["session_id", SESSION_ID],
  ["task_id", TASK_ID],
  ["delegation_id", DELEGATION_ID],
  ["cost_center_id", SLUG],
  ["trace_id", TRACE_ID],
];

const KNOWN = new Set([
  "iss",
  "aud",
  "sub",
  "iat",
  "nbf",
  "exp",
  "jti",
  "txn",
  "tenant_id",
  "org_path",
  "principal_type",
  "act",
  "delegated_resources",
  "delegated_actions",
  ...OPTIONAL.map(([name]) => name),
]);

const scopeList = (v: unknown, re: RegExp) =>
  Array.isArray(v) &&
  v.length >= 1 &&
  v.length <= MAX_DELEGATED &&
  new Set(v).size === v.length &&
  v.every((s) => typeof s === "string" && re.test(s));

function claimsProblem(c: Record<string, unknown>): string | undefined {
  const str = (v: unknown, re: RegExp) => typeof v === "string" && re.test(v);
  const unknown = Object.keys(c).find((k) => !KNOWN.has(k));
  if (unknown) return unknown;
  if (!str(c.jti, JTI)) return "jti";
  if (!str(c.sub, PRINCIPAL_ID)) return "sub";
  if (!str(c.tenant_id, SLUG)) return "tenant_id";
  if (!str(c.txn, REQUEST_ID)) return "txn";
  if (typeof c.aud !== "string" || c.aud.length < 1 || c.aud.length > 512)
    return "aud";
  if (
    typeof c.principal_type !== "string" ||
    !PRINCIPAL_TYPES.has(c.principal_type)
  )
    return "principal_type";
  const path = c.org_path;
  if (
    !Array.isArray(path) ||
    path.length < 1 ||
    path.length > 32 ||
    path[0] !== c.tenant_id ||
    !path.every((u) => str(u, SLUG))
  )
    return "org_path";
  if (c.act !== undefined) {
    const act = c.act as Record<string, unknown> | null;
    if (
      !act ||
      typeof act !== "object" ||
      Object.keys(act).sort().join() !== "principal_type,sub" ||
      !str(act.sub, PRINCIPAL_ID) ||
      (act.principal_type !== "agent" && act.principal_type !== "service")
    )
      return "act";
  }
  for (const [name, re] of OPTIONAL)
    if (c[name] !== undefined && !str(c[name], re)) return name;
  if (
    c.delegation_id !== undefined &&
    (c.act === undefined || c.task_id === undefined)
  )
    return "delegation_id";
  const delegated = c.delegation_id !== undefined;
  if (
    delegated
      ? !scopeList(c.delegated_resources, RESOURCE)
      : c.delegated_resources !== undefined
  )
    return "delegated_resources";
  if (
    delegated
      ? !scopeList(c.delegated_actions, ACTION)
      : c.delegated_actions !== undefined
  )
    return "delegated_actions";
  return undefined;
}

export async function mintToken(
  db: Pool,
  signers: ReadonlyMap<string, Signer>,
  issuer: string,
  { notAfter, ...input }: MintInput,
  now = Math.floor(Date.now() / 1000),
): Promise<{ token: string; expiresIn: number }> {
  const exp = Math.min(
    now + TOKEN_TTL_SECONDS,
    notAfter ?? Number.POSITIVE_INFINITY,
  );
  if (exp <= now) throw new TokenError("token would already be expired");
  const claims: Bae6Claims = {
    ...input,
    iss: issuer,
    iat: now,
    exp,
    jti: randomBytes(16).toString("base64url"),
  };
  const problem = claimsProblem(claims as unknown as Record<string, unknown>);
  if (problem) throw new TokenError(`invalid claim ${problem}`);
  const signer = await activeSigner(db, signers);
  const signingInput = `${b64url(JSON.stringify({ alg: signer.alg, kid: signer.kid, typ: TOKEN_TYPE }))}.${b64url(JSON.stringify(claims))}`;
  const signature = await signer.sign(Buffer.from(signingInput));
  return {
    token: `${signingInput}.${b64url(signature)}`,
    expiresIn: exp - now,
  };
}

export async function verifyToken(
  db: Pool,
  token: string,
  { issuer, audience }: { issuer: string; audience: string },
): Promise<Bae6Claims> {
  let payload: Record<string, unknown>;
  try {
    decodeProtectedHeader(token);
  } catch (err) {
    throw new TokenError("token rejected", { cause: err });
  }
  const keys = createLocalJWKSet({ keys: await publishedKeys(db) });
  try {
    ({ payload } = await jwtVerify(token, keys, {
      issuer,
      audience,
      typ: TOKEN_TYPE,
      algorithms: ["ES256", "EdDSA"],
      requiredClaims: ["iat", "exp", "jti"],
      clockTolerance: CLOCK_SKEW_SECONDS,
    }));
  } catch (err) {
    throw new TokenError("token rejected", { cause: err });
  }
  const { iat, exp } = payload as { iat: number; exp: number };
  if (
    exp <= Date.now() / 1000 ||
    exp - iat > TOKEN_TTL_SECONDS ||
    iat > Date.now() / 1000 + CLOCK_SKEW_SECONDS
  )
    throw new TokenError("token lifetime out of bounds");
  if (Array.isArray(payload.aud))
    throw new TokenError("token has several audiences");
  const problem = claimsProblem(payload);
  if (problem) throw new TokenError(`invalid claim ${problem}`);
  return payload as unknown as Bae6Claims;
}
