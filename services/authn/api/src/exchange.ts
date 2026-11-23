import type { Pool } from "pg";
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
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
export const SESSION_TOKEN_TYPE = "urn:bae6:params:oauth:token-type:session";
const TOKEN_TYPES = new Set([JWT_TYPE, ACCESS_TOKEN_TYPE]);
const SUBJECT_TYPES = new Set([JWT_TYPE, SESSION_TOKEN_TYPE]);
const MAX_TOKEN_LENGTH = 8192;
const PARAMS = new Set([
  "grant_type",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
  "audience",
  "delegation_id",
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
  actorToken?: string;
  actorTokenType?: string;
  delegationId?: string;
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
  const actorToken = one("actor_token");
  const actorTokenType = one("actor_token_type");
  const delegationId = one("delegation_id");
  const requested = one("requested_token_type");
  if (
    !subjectToken ||
    subjectToken.length > MAX_TOKEN_LENGTH ||
    !subjectTokenType ||
    !SUBJECT_TYPES.has(subjectTokenType) ||
    !audience ||
    audience.length > 512 ||
    (requested !== undefined && requested !== JWT_TYPE) ||
    (actorToken === undefined) !== (actorTokenType === undefined) ||
    (actorToken !== undefined &&
      (actorToken.length < 1 ||
        actorToken.length > MAX_TOKEN_LENGTH ||
        !TOKEN_TYPES.has(actorTokenType as string))) ||
    (delegationId !== undefined && actorToken === undefined)
  )
    throw new OAuthError("invalid_request");
  return {
    subjectToken,
    subjectTokenType,
    audience,
    ...(actorToken === undefined ? {} : { actorToken, actorTokenType }),
    ...(delegationId === undefined ? {} : { delegationId }),
  };
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
  if (request.actorToken !== undefined || request.subjectTokenType !== JWT_TYPE)
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
  const principals: { id: string; type?: string }[] = [
    { id: subject.sub, type: subject.principal_type },
  ];
  if (subject.act) principals.push({ id: subject.act.sub });
  // shortcut: delegations aren't stored, so revocation can't be checked; refuse until they are.
  if (
    subject.delegation_id !== undefined ||
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
  const carried = Object.fromEntries(
    CARRIED.filter((c) => subject[c] !== undefined).map((c) => [c, subject[c]]),
  ) as Pick<Bae6Claims, (typeof CARRIED)[number]>;
  return issue(deps, {
    ...carried,
    aud: request.audience,
    notAfter: subject.exp,
  });
}

export async function exchangeSession(
  deps: ExchangeDeps,
  request: ExchangeRequest,
  txn: string,
): Promise<TokenResponse> {
  if (
    request.actorToken !== undefined ||
    request.subjectTokenType !== SESSION_TOKEN_TYPE
  )
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
