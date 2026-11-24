import type { IncomingMessage, ServerResponse } from "node:http";
import { TENANT_SCOPE } from "../auth/bae6.js";
import type { Principal } from "../auth/index.js";
import { HttpError, readJson, requestIdOf, send } from "../http.js";
import type { createTenantService } from "./service.js";

type TenantService = ReturnType<typeof createTenantService>;

const PLACEMENT = /^\/v1\/tenant\/principals\/(prn_[0-9a-f]{32})\/unit$/;
const MAX_BODY_BYTES = 1024;
const PLACEABLE_TYPES = new Set(["user", "service", "agent", "application"]);

export function tenantRoutes(
  serviceFor: (organization: string) => Pick<TenantService, "placePrincipal">,
) {
  return async (
    req: IncomingMessage,
    res: ServerResponse,
    principal: Principal,
    url: URL,
  ): Promise<boolean> => {
    const principalId = PLACEMENT.exec(url.pathname)?.[1];
    if (!principalId) return false;
    if (req.method !== "PUT") {
      res.setHeader("allow", "PUT");
      throw new HttpError(405, "method_not_allowed", "Use PUT.");
    }
    if (!principal.scopes.includes(TENANT_SCOPE))
      throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
    const body = await readJson(req, MAX_BODY_BYTES);
    const { principalType, unit } = (
      typeof body === "object" && body !== null ? body : {}
    ) as Record<string, unknown>;
    if (
      typeof principalType !== "string" ||
      !PLACEABLE_TYPES.has(principalType) ||
      typeof unit !== "string"
    )
      throw new HttpError(
        400,
        "invalid_request",
        "principalType and unit are required.",
      );
    await serviceFor(principal.organization).placePrincipal(
      principal.subject,
      `${principalType}:${principalId}`,
      unit,
      requestIdOf(res),
    );
    send(res, 200, { principalId, principalType, unit });
    return true;
  };
}
