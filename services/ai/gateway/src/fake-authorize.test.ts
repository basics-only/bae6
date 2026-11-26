import type { Authorize, Identity } from "./identity.js";

export type Fixture = Identity & { scopes: string[]; models?: string[] };

const SCOPE_OF_API: Record<string, string> = {
  "ai-invoke": "ai:invoke",
  "ai-usage-read": "ai:usage:read",
  "ai-usage-admin": "ai:usage:admin",
  "feedback-read": "feedback:read",
  "feedback-write": "feedback:write",
};

/** A fixture holding scope s may call the api whose scope is s; a model needs ai:invoke and, if listed, a place in `models`. */
export const fakeAuthorize =
  (fixtures: Record<string, Fixture>, calls: string[] = []): Authorize =>
  async (authorization, { resourceType, resourceId }) => {
    calls.push(`${resourceType}:${resourceId}`);
    const token = /^Bearer (.+)$/.exec(authorization ?? "")?.[1];
    const fixture = token === undefined ? undefined : fixtures[token];
    if (!fixture)
      return {
        allowed: false,
        status: 401,
        code: "unauthenticated",
        message: "Unknown token.",
      };
    const scope =
      resourceType === "model" ? "ai:invoke" : SCOPE_OF_API[resourceId];
    const modelRefused =
      resourceType === "model" &&
      fixture.models !== undefined &&
      !fixture.models.includes(resourceId);
    if (scope === undefined || !fixture.scopes.includes(scope) || modelRefused)
      return {
        allowed: false,
        status: 403,
        code: "forbidden",
        message: "Not permitted.",
      };
    const { scopes: _, models: __, ...who } = fixture;
    return { allowed: true, who };
  };
