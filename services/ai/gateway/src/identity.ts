import type { TenantResource, Verdict } from "@bae6/authz/middleware";

export const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const AUDIENCE = "bae6-ai";

export interface Identity {
  subjectId: string;
  subjectType: "workload" | "user";
  organizationId: string;
  applicationId: string;
}

export type Decision =
  | { allowed: true; who: Identity }
  | { allowed: false; status: 401 | 403 | 503; code: string; message: string };

/** Never throws: an outage is a 503 decision. */
export type Authorize = (
  authorization: string | undefined,
  resource: TenantResource,
) => Promise<Decision>;

// Unverified, so it only refuses: authn would answer a foreign audience with invalid_client, which reads as an outage.
function forThisAudience(authorization: string | undefined) {
  const payload = /^Bearer [^.\s]+\.([^.\s]+)\.[^.\s]+$/.exec(
    authorization ?? "",
  )?.[1];
  if (payload === undefined) return false;
  try {
    return (
      JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).aud ===
      AUDIENCE
    );
  } catch {
    return false;
  }
}

export const fromGuard =
  (
    guard: (
      authorization: string | undefined,
      resource: TenantResource,
    ) => Promise<Verdict>,
  ): Authorize =>
  async (authorization, resource) => {
    if (!forThisAudience(authorization))
      return {
        allowed: false,
        status: 401,
        code: "unauthenticated",
        message: "A bae6-authn token for bae6-ai is required.",
      };
    const verdict = await guard(authorization, resource);
    if (!verdict.allowed) return verdict;
    const context = verdict.executionContext;
    if (!context)
      return {
        allowed: false,
        status: 503,
        code: "unavailable",
        message: "Authorization is unavailable.",
      };
    if (!context.applicationId)
      return {
        allowed: false,
        status: 403,
        code: "forbidden",
        message: "The token names no application.",
      };
    return {
      allowed: true,
      who: {
        subjectId: context.principalId,
        subjectType: context.principalType === "user" ? "user" : "workload",
        organizationId: context.tenantId,
        applicationId: context.applicationId,
      },
    };
  };
