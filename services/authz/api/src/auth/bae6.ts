import {
  createRemoteJWKSet,
  decodeJwt,
  type JWTPayload,
  jwtVerify,
} from "jose";
import { directExecutionContext } from "./execution-context.js";
import { INVALID_TOKEN_CODES } from "./oidc.js";
import { type Authenticator, ORGANIZATION_ID } from "./principal.js";

export const TENANT_SCOPE = "tenant";
const TOKEN_TYPE = "bae6+jwt";
const PRINCIPAL_TYPES = new Set([
  "user",
  "service",
  "agent",
  "application",
  "group",
]);
const PRINCIPAL_ID = /^prn_[0-9a-f]{32}$/;
const DELEGATION_ID = /^dlg_[0-9a-f]{32}$/;
const RESOURCE =
  /^(application|api|model|agent|prompt|mcp_server|tool|dataset|document|service):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ACTION = /^[a-z][a-z0-9_]{0,31}:[a-z][a-z0-9_]{0,31}$/;
export const DELEGATED_SCOPE = "tenant:delegated";

const scopeList = (value: unknown, pattern: RegExp): value is string[] =>
  Array.isArray(value) &&
  value.length >= 1 &&
  value.length <= 16 &&
  new Set(value).size === value.length &&
  value.every((v) => typeof v === "string" && pattern.test(v));

function delegationOf(payload: JWTPayload, sub: string) {
  const {
    act,
    delegation_id: id,
    task_id: taskId,
    delegated_resources: resources,
    delegated_actions: actions,
  } = payload;
  if ([act, id, resources, actions].every((c) => c === undefined))
    return undefined;
  const actor = act as { sub?: unknown; principal_type?: unknown } | null;
  if (
    typeof id !== "string" ||
    !DELEGATION_ID.test(id) ||
    typeof taskId !== "string" ||
    typeof actor !== "object" ||
    actor === null ||
    typeof actor.sub !== "string" ||
    !PRINCIPAL_ID.test(actor.sub) ||
    actor.sub === sub ||
    (actor.principal_type !== "agent" && actor.principal_type !== "service") ||
    !scopeList(resources, RESOURCE) ||
    !scopeList(actions, ACTION)
  )
    return null;
  return {
    actorId: actor.sub,
    delegation: {
      actor: `${actor.principal_type}:${actor.sub}`,
      resources,
      actions,
    },
  };
}

export function bae6Authenticator(config: {
  issuer: string;
  jwksUri: string;
  audience: string;
  organization: string;
}): Authenticator {
  if (!ORGANIZATION_ID.test(config.organization))
    throw new Error("organization is not a valid organization id");
  const keys = createRemoteJWKSet(new URL(config.jwksUri), {
    cooldownDuration: 30_000,
    cacheMaxAge: 600_000,
    timeoutDuration: 5_000,
  });
  return async (authorization) => {
    const token = /^Bearer (\S+)$/.exec(authorization ?? "")?.[1];
    if (!token) return null;
    try {
      if (decodeJwt(token).iss !== config.issuer) return null;
    } catch {
      return null;
    }
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer: config.issuer,
        audience: config.audience,
        typ: TOKEN_TYPE,
        algorithms: ["ES256", "EdDSA"],
        requiredClaims: ["exp", "sub", "tenant_id", "principal_type"],
      });
      const { sub, tenant_id: tenant, principal_type: type } = payload;
      if (
        typeof sub !== "string" ||
        !PRINCIPAL_ID.test(sub) ||
        typeof tenant !== "string" ||
        tenant !== config.organization ||
        typeof type !== "string" ||
        !PRINCIPAL_TYPES.has(type)
      )
        return null;
      const delegated = delegationOf(payload, sub);
      if (delegated === null) return null;
      const executionContext = directExecutionContext(
        payload,
        tenant,
        sub,
        type,
        delegated?.actorId,
      );
      if (!executionContext) return null;
      return {
        executionContext,
        ...(delegated && { delegation: delegated.delegation }),
        subject: `${type}:${sub}`,
        organization: tenant,
        scopes: [delegated ? DELEGATED_SCOPE : TENANT_SCOPE],
        applications: [],
        issuer: config.issuer,
      };
    } catch (err) {
      const code = (err as { code?: unknown }).code;
      if (typeof code === "string" && INVALID_TOKEN_CODES.has(code))
        return null;
      throw err;
    }
  };
}

export const firstOf =
  (first: Authenticator, second: Authenticator): Authenticator =>
  async (authorization) =>
    (await first(authorization)) ?? second(authorization);
