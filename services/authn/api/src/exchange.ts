import type { Pool } from "pg";
import { liveDelegationExpiry } from "./delegations.js";
import type { Signer } from "./keys.js";
import { readSession } from "./sessions.js";
import {
  type Bae6Claims,
  type MintInput,
  mintToken,
  TokenError,
  verifyToken,
} from "./tokens.js";

const CARRIED = [
  "sub",
  "txn",
  "tenant_id",
  "org_path",
  "principal_type",
  "act",
  "application_id",
  "session_id",
  "task_id",
  "delegation_id",
  "cost_center_id",
  "trace_id",
] as const;

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
export const SESSION_TOKEN_TYPE = "urn:bae6:params:oauth:token-type:session";
const SUBJECT_TYPES = new Set([JWT_TYPE, SESSION_TOKEN_TYPE]);
const MAX_TOKEN_LENGTH = 8192;
const PARAMS = new Set([
  "grant_type",
  "subject_token",
  "subject_token_type",
  "audience",
  "requested_token_type",
]);

export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "unsupported_grant_type"
  | "invalid_target";

export class OAuthError extends Error {
  readonly status: 400 | 401;
  constructor(
    readonly error: OAuthErrorCode,
    options?: ErrorOptions,
  ) {
    super(error, options);
    this.status = error === "invalid_client" ? 401 : 400;
  }
}

export interface ExchangeRequest {
  subjectToken: string;
  subjectTokenType: string;
  audience: string;
}

export interface TokenResponse {
  access_token: string;
  issued_token_type: typeof JWT_TYPE;
  token_type: "Bearer";
  expires_in: number;
}

export interface ExchangeDeps {
  db: Pool;
  signers: ReadonlyMap<string, Signer>;
  issuer: string;
  audiences: ReadonlySet<string>;
  reexchangeTargets: ReadonlyMap<string, ReadonlySet<string>>;
}

export function parseTokenTargets(
  raw: string,
  audiences: ReadonlySet<string>,
): Map<string, Set<string>> {
  const targets = new Map<string, Set<string>>();
  for (const entry of raw
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean)) {
    const [caller = "", list = "", ...rest] = entry
      .split("=")
      .map((s) => s.trim());
    const allowed = new Set(list.split("|").map((t) => t.trim()));
    if (
      rest.length > 0 ||
      !audiences.has(caller) ||
      targets.has(caller) ||
      allowed.has(caller) ||
      ![...allowed].every((t) => audiences.has(t))
    )
      throw new Error(
        "BAE6_AUTHN_TOKEN_TARGETS must be caller=target|target entries naming other BAE6_AUTHN_AUDIENCES, each caller once",
      );
    targets.set(caller, allowed);
  }
  return targets;
}

export function parseExchangeRequest(form: URLSearchParams): ExchangeRequest {
  const one = (name: string) => {
    const values = form.getAll(name);
    if (values.length > 1) throw new OAuthError("invalid_request");
    return values[0];
  };
  for (const name of form.keys())
    if (!PARAMS.has(name)) throw new OAuthError("invalid_request");
  const grantType = one("grant_type");
  if (grantType === undefined) throw new OAuthError("invalid_request");
  if (grantType !== GRANT_TYPE) throw new OAuthError("unsupported_grant_type");
  const subjectToken = one("subject_token");
  const subjectTokenType = one("subject_token_type");
  const audience = one("audience");
  const requested = one("requested_token_type");
  if (
    !subjectToken ||
    subjectToken.length > MAX_TOKEN_LENGTH ||
    !subjectTokenType ||
    !SUBJECT_TYPES.has(subjectTokenType) ||
    !audience ||
    audience.length > 512 ||
    (requested !== undefined && requested !== JWT_TYPE)
  )
    throw new OAuthError("invalid_request");
  return { subjectToken, subjectTokenType, audience };
}

export async function allActive(
  db: Pool,
  tenantId: string,
  principals: { id: string; type?: string }[],
): Promise<boolean> {
  const { rows } = await db.query<{ id: string; type: string }>(
    `SELECT id, type FROM principals
      WHERE tenant_id = $1 AND id = ANY($2) AND status = 'active'`,
    [tenantId, principals.map((p) => p.id)],
  );
  const found = new Map(rows.map((r) => [r.id, r.type]));
  return principals.every(
    (p) =>
      found.has(p.id) && (p.type === undefined || found.get(p.id) === p.type),
  );
}

export async function sessionLive(
  db: Pool,
  tenantId: string,
  principalId: string,
  sessionId: string,
): Promise<boolean> {
  const { rowCount } = await db.query(
    `SELECT 1 FROM sessions s
       JOIN provider_connections c
         ON c.tenant_id = s.tenant_id AND c.id = s.provider_connection_id
      WHERE s.tenant_id = $1 AND s.id = $2 AND s.principal_id = $3
        AND s.revoked_at IS NULL AND s.expires_at > now() AND c.status = 'active'`,
    [tenantId, sessionId, principalId],
  );
  return rowCount === 1;
}

export async function exchangeToken(
  deps: ExchangeDeps,
  caller: { audience: string },
  request: ExchangeRequest,
): Promise<TokenResponse> {
  if (request.subjectTokenType !== JWT_TYPE)
    throw new OAuthError("invalid_request");
  if (!deps.audiences.has(request.audience))
    throw new OAuthError("invalid_target");
  let subject: Awaited<ReturnType<typeof verifyToken>>;
  try {
    subject = await verifyToken(deps.db, request.subjectToken, {
      issuer: deps.issuer,
      audience: caller.audience,
    });
  } catch (err) {
    if (err instanceof TokenError)
      throw new OAuthError("invalid_request", { cause: err });
    throw err;
  }
  if (!deps.reexchangeTargets.get(caller.audience)?.has(request.audience))
    throw new OAuthError("invalid_target");
  const principals: { id: string; type?: string }[] = [
    { id: subject.sub, type: subject.principal_type },
  ];
  if (subject.act) principals.push({ id: subject.act.sub });
  if (
    subject.exp <= Math.floor(Date.now() / 1000) ||
    !(await allActive(deps.db, subject.tenant_id, principals)) ||
    (subject.session_id !== undefined &&
      !(await sessionLive(
        deps.db,
        subject.tenant_id,
        subject.sub,
        subject.session_id,
      )))
  )
    throw new OAuthError("invalid_request");
  let notAfter = subject.exp;
  if (subject.delegation_id !== undefined) {
    const expires = await liveDelegationExpiry(deps.db, {
      delegationId: subject.delegation_id,
      tenantId: subject.tenant_id,
      initiatingPrincipalId: subject.sub,
      actorPrincipalId: subject.act?.sub ?? "",
      taskId: subject.task_id ?? "",
      applicationId: subject.application_id,
    });
    if (!expires) throw new OAuthError("invalid_request");
    notAfter = Math.min(notAfter, Math.floor(expires.getTime() / 1000));
  }
  const carried = Object.fromEntries(
    CARRIED.filter((c) => subject[c] !== undefined).map((c) => [c, subject[c]]),
  ) as Pick<Bae6Claims, (typeof CARRIED)[number]>;
  return issue(deps, {
    ...carried,
    aud: request.audience,
    notAfter,
  });
}

export async function exchangeSession(
  deps: ExchangeDeps,
  request: ExchangeRequest,
  txn: string,
): Promise<TokenResponse> {
  if (request.subjectTokenType !== SESSION_TOKEN_TYPE)
    throw new OAuthError("invalid_request");
  if (!deps.audiences.has(request.audience))
    throw new OAuthError("invalid_target");
  const session = await readSession(deps.db, request.subjectToken);
  if (!session) throw new OAuthError("invalid_request");
  const { rows } = await deps.db.query<{ orgPath: string[] }>(
    `SELECT org_path AS "orgPath" FROM principals
      WHERE tenant_id = $1 AND id = $2 AND status = 'active' AND type = 'user'`,
    [session.tenantId, session.principalId],
  );
  const principal = rows[0];
  if (!principal) throw new OAuthError("invalid_request");
  return issue(deps, {
    aud: request.audience,
    sub: session.principalId,
    txn,
    tenant_id: session.tenantId,
    org_path: principal.orgPath,
    principal_type: "user",
    session_id: session.id,
    notAfter: Math.floor(session.expiresAt.getTime() / 1000),
  });
}

async function issue(
  deps: ExchangeDeps,
  input: MintInput,
): Promise<TokenResponse> {
  let minted: Awaited<ReturnType<typeof mintToken>>;
  try {
    minted = await mintToken(deps.db, deps.signers, deps.issuer, input);
  } catch (err) {
    if (err instanceof TokenError)
      throw new OAuthError("invalid_request", { cause: err });
    throw err;
  }
  return {
    access_token: minted.token,
    issued_token_type: JWT_TYPE,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
  };
}
