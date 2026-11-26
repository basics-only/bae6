import type { IncomingMessage, ServerResponse } from "node:http";
import { DELEGATED_SCOPE, TENANT_SCOPE } from "../auth/bae6.js";
import type { Principal } from "../auth/index.js";
import { HttpError, readJson, requestIdOf, send } from "../http.js";
import type {
  Action,
  Capability,
  GuardrailList,
  ResourceType,
  TenantService,
} from "./service.js";

const PLACEMENT = /^\/v1\/tenant\/principals\/(prn_[0-9a-f]{32})\/unit$/;
const UNITS = "/v1/tenant/units";
const UNIT_SETTING =
  /^\/v1\/tenant\/units\/([^/]+)\/(admins|ceilings|guardrails)\/(.+)$/;
const RESOURCE_ACCESS =
  /^\/v1\/tenant\/resources\/([^/]+)\/([^/]+)\/access\/([^/]+)$/;
const RESOURCE_PLACEMENT = "/v1/tenant/resources/unit";
const CHECK = "/v1/tenant/check";
const EXT_AUTHZ = "/v1/tenant/ext-authz";
const RESOURCE_HEADER = "bae6-resource";
const GATEWAY_RESOURCE = /^([a-z_]{1,32}):([^:\s]{1,256})$/;
const MAX_BODY_BYTES = 1024;
const PLACEABLE_TYPES = new Set(["user", "service", "agent", "application"]);

const mayCheck = (principal: Principal) =>
  principal.scopes.includes(
    principal.delegation ? DELEGATED_SCOPE : TENANT_SCOPE,
  );

const invalidRequest = (message: string) =>
  new HttpError(400, "invalid_request", message);

async function readObject(req: IncomingMessage) {
  const body = await readJson(req, MAX_BODY_BYTES);
  if (typeof body !== "object" || body === null || Array.isArray(body))
    throw invalidRequest("Expected a JSON object.");
  return body as Record<string, unknown>;
}

const decode = (segment: string) => {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw invalidRequest("Malformed path.");
  }
};

export function tenantRoutes(
  serviceFor: (
    organization: string,
  ) => Pick<
    TenantService,
    | "placePrincipal"
    | "placeResource"
    | "check"
    | "createUnit"
    | "grant"
    | "revoke"
    | "setCeiling"
    | "setGuardrail"
    | "setAccess"
  >,
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
      if (!mayCheck(principal))
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
        principal.delegation,
      );
      if (!allowed) throw new HttpError(403, "forbidden", "Not permitted.");
      res.writeHead(200).end();
      return true;
    }
    if (url.pathname === UNITS) {
      if (req.method !== "POST") {
        res.setHeader("allow", "POST");
        throw new HttpError(405, "method_not_allowed", "Use POST.");
      }
      if (!principal.scopes.includes(TENANT_SCOPE))
        throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
      const { unit, parent } = await readObject(req);
      if (typeof unit !== "string" || typeof parent !== "string")
        throw invalidRequest("unit and parent are required.");
      const auditEventId = await serviceFor(principal.organization).createUnit(
        principal.subject,
        unit,
        parent,
        requestIdOf(res),
      );
      send(res, 201, { unit, parent, auditEventId });
      return true;
    }
    const access = RESOURCE_ACCESS.exec(url.pathname);
    if (access) {
      if (req.method !== "PUT" && req.method !== "DELETE") {
        res.setHeader("allow", "PUT, DELETE");
        throw new HttpError(405, "method_not_allowed", "Use PUT or DELETE.");
      }
      if (!principal.scopes.includes(TENANT_SCOPE))
        throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
      const [type, id, subject] = access.slice(1).map(decode) as [
        ResourceType,
        string,
        string,
      ];
      const auditEventId = await serviceFor(principal.organization).setAccess(
        principal.subject,
        type,
        id,
        subject,
        req.method === "PUT",
        requestIdOf(res),
      );
      send(res, 200, { auditEventId });
      return true;
    }
    const setting = UNIT_SETTING.exec(url.pathname);
    if (setting) {
      const arity = { admins: 2, ceilings: 1, guardrails: 3 }[
        setting[2] as "admins" | "ceilings" | "guardrails"
      ];
      if ((setting[3] as string).split("/").length !== arity) return false;
      if (req.method !== "PUT" && req.method !== "DELETE") {
        res.setHeader("allow", "PUT, DELETE");
        throw new HttpError(405, "method_not_allowed", "Use PUT or DELETE.");
      }
      if (!principal.scopes.includes(TENANT_SCOPE))
        throw new HttpError(403, "forbidden", `Missing scope ${TENANT_SCOPE}.`);
      const service = serviceFor(principal.organization);
      const enable = req.method === "PUT";
      const unit = decode(setting[1] as string);
      const args = (setting[3] as string).split("/").map(decode);
      const actor = principal.subject;
      const requestId = requestIdOf(res);
      let auditEventId: string;
      if (setting[2] === "admins") {
        const [capability, subject] = args as [Capability, string];
        auditEventId = await (enable ? service.grant : service.revoke)(
          actor,
          capability,
          subject,
          unit,
          requestId,
        );
      } else if (setting[2] === "ceilings") {
        auditEventId = await service.setCeiling(
          actor,
          args[0] as Capability,
          unit,
          enable,
          requestId,
        );
      } else {
        const [action, list, subject] = args as [Action, GuardrailList, string];
        auditEventId = await service.setGuardrail(
          actor,
          unit,
          action,
          list,
          subject,
          enable,
          requestId,
        );
      }
      send(res, 200, { auditEventId });
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
    if (
      !(isCheck ? mayCheck(principal) : principal.scopes.includes(TENANT_SCOPE))
    )
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
          "execution_context_unavailable",
          "The token does not carry execution context.",
        );
      const allowed = await service.check(
        principal.subject,
        resourceType as Parameters<TenantService["check"]>[1],
        resourceId,
        principal.delegation,
      );
      if (includeExecutionContext) res.setHeader("cache-control", "no-store");
      send(res, 200, {
        allowed,
        ...(allowed &&
          includeExecutionContext && {
            executionContext: {
              ...principal.executionContext,
              requestId: requestIdOf(res),
            },
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
