import type { IncomingMessage, ServerResponse } from "node:http";
import { TENANT_SCOPE } from "../auth/bae6.js";
import type { Principal } from "../auth/index.js";
import { HttpError, readJson, requestIdOf, send } from "../http.js";
import type { ResourceType, TenantService } from "./service.js";

const PLACEMENT = /^\/v1\/tenant\/principals\/(prn_[0-9a-f]{32})\/unit$/;
const RESOURCE_PLACEMENT = "/v1/tenant/resources/unit";
const CHECK = "/v1/tenant/check";
const EXT_AUTHZ = "/v1/tenant/ext-authz";
const RESOURCE_HEADER = "bae6-resource";
const GATEWAY_RESOURCE = /^([a-z_]{1,32}):([^:\s]{1,256})$/;
const MAX_BODY_BYTES = 1024;
const PLACEABLE_TYPES = new Set(["user", "service", "agent", "application"]);

const invalidRequest = (message: string) =>
  new HttpError(400, "invalid_request", message);

async function readObject(req: IncomingMessage) {
  const body = await readJson(req, MAX_BODY_BYTES);
  if (typeof body !== "object" || body === null || Array.isArray(body))
    throw invalidRequest("Expected a JSON object.");
  return body as Record<string, unknown>;
}

export function tenantRoutes(
  serviceFor: (
    organization: string,
  ) => Pick<TenantService, "placePrincipal" | "placeResource" | "check">,
) {
  return async (
    req: IncomingMessage,
    res: ServerResponse,
    principal: Principal,
    url: URL,
  ): Promise<boolean> => {
    if (
      url.pathname === EXT_AUTHZ ||
      url.pathname.startsWith(`${EXT_AUTHZ}/`)
    ) {
      if (!principal.scopes.includes(TENANT_SCOPE))
        throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
      const header = req.headers[RESOURCE_HEADER];
      const match =
        typeof header === "string" ? GATEWAY_RESOURCE.exec(header) : null;
      if (!match)
        throw invalidRequest(`${RESOURCE_HEADER} must be <type>:<id>.`);
      const allowed = await serviceFor(principal.organization).check(
        principal.subject,
        match[1] as Parameters<TenantService["check"]>[1],
        match[2] as string,
      );
      if (!allowed) throw new HttpError(403, "forbidden", "Not permitted.");
      res.writeHead(200).end();
      return true;
    }
    const principalId = PLACEMENT.exec(url.pathname)?.[1];
    const isCheck = url.pathname === CHECK;
    const isResourcePlacement = url.pathname === RESOURCE_PLACEMENT;
    if (!principalId && !isCheck && !isResourcePlacement) return false;
    const method = isCheck ? "POST" : "PUT";
    if (req.method !== method) {
      res.setHeader("allow", method);
      throw new HttpError(405, "method_not_allowed", `Use ${method}.`);
    }
    if (!principal.scopes.includes(TENANT_SCOPE))
      throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
    const service = serviceFor(principal.organization);
    const body = await readObject(req);
    if (isCheck) {
      const { resourceType, resourceId, includeExecutionContext } = body;
      if (typeof resourceType !== "string" || typeof resourceId !== "string")
        throw invalidRequest("resourceType and resourceId are required.");
      if (
        includeExecutionContext !== undefined &&
        typeof includeExecutionContext !== "boolean"
      )
        throw invalidRequest("includeExecutionContext must be a boolean.");
      if (includeExecutionContext && !principal.executionContext)
        throw new HttpError(
          403,
          "forbidden",
          "The token does not carry execution context.",
        );
      const allowed = await service.check(
        principal.subject,
        resourceType as Parameters<TenantService["check"]>[1],
        resourceId,
      );
      if (includeExecutionContext) res.setHeader("cache-control", "no-store");
      send(res, 200, {
        allowed,
        ...(allowed &&
          includeExecutionContext && {
            executionContext: principal.executionContext,
          }),
      });
      return true;
    }
    if (isResourcePlacement) {
      const { resourceType, resourceId, unit } = body;
      if (
        typeof resourceType !== "string" ||
        typeof resourceId !== "string" ||
        typeof unit !== "string"
      )
        throw invalidRequest("resourceType, resourceId and unit are required.");
      const auditEventId = await service.placeResource(
        principal.subject,
        resourceType as ResourceType,
        resourceId,
        unit,
        requestIdOf(res),
      );
      send(res, 200, { resourceType, resourceId, unit, auditEventId });
      return true;
    }
    const { principalType, unit } = body;
    if (
      typeof principalType !== "string" ||
      !PLACEABLE_TYPES.has(principalType) ||
      typeof unit !== "string"
    )
      throw invalidRequest("principalType and unit are required.");
    await service.placePrincipal(
      principal.subject,
      `${principalType}:${principalId}`,
      unit,
      requestIdOf(res),
    );
    send(res, 200, { principalId, principalType, unit });
    return true;
  };
}
