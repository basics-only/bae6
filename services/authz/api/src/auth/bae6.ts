import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
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
    cacheMaxAge: 300_000,
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
        payload.act !== undefined ||
        payload.delegation_id !== undefined ||
        typeof sub !== "string" ||
        !PRINCIPAL_ID.test(sub) ||
        typeof tenant !== "string" ||
        tenant !== config.organization ||
        typeof type !== "string" ||
        !PRINCIPAL_TYPES.has(type)
      )
        return null;
      return {
        subject: `${type}:${sub}`,
        organization: tenant,
        scopes: [TENANT_SCOPE],
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
