import type { IncomingMessage, ServerResponse } from "node:http";
import type pg from "pg";
import { HttpError, send } from "./http.js";
import { PrincipalError, setPrincipalOrgPath } from "./principals.js";
import { clientAuthenticated, type TokenRouteDeps } from "./token-routes.js";

export const PLACEMENT_CLIENT = "placement";
const MAX_BODY_BYTES = 4096;
const PATH = /^\/admin\/principals\/(prn_[0-9a-f]{32})\/org-path$/;

const STATUS: Record<string, number> = {
  invalid_request: 400,
  unknown_principal: 404,
  invalid_transition: 409,
};

async function readJson(
  req: IncomingMessage,
): Promise<Record<string, unknown>> {
  const type = req.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json")
    throw new HttpError(400, "invalid_request", "Expected application/json.");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES)
      throw new HttpError(400, "invalid_request", "Body too large.");
    chunks.push(chunk);
  }
  let body: unknown;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    body = undefined;
  }
  if (typeof body !== "object" || body === null || Array.isArray(body))
    throw new HttpError(400, "invalid_request", "Expected a JSON object.");
  return body as Record<string, unknown>;
}

export function createPlacementRoutes(deps: {
  db: pg.Pool;
  clientSecret: TokenRouteDeps["clientSecret"];
}) {
  return async function route(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
  ): Promise<boolean> {
    const principalId = PATH.exec(url.pathname)?.[1];
    if (!principalId) return false;
    if (req.method !== "PUT") {
      res.setHeader("allow", "PUT");
      throw new HttpError(405, "method_not_allowed", "Use PUT.");
    }
    if (
      !(await clientAuthenticated(deps.clientSecret, req, [PLACEMENT_CLIENT]))
    ) {
      res.setHeader("www-authenticate", "Bearer");
      throw new HttpError(401, "unauthorized", "Invalid client credentials.");
    }
    const { tenantId, orgPath } = await readJson(req);
    if (typeof tenantId !== "string" || !Array.isArray(orgPath))
      throw new HttpError(
        400,
        "invalid_request",
        "tenantId and orgPath are required.",
      );
    try {
      await setPrincipalOrgPath(deps.db, {
        tenantId,
        principalId,
        orgPath,
        actor: `client:${PLACEMENT_CLIENT}`,
      });
    } catch (err) {
      if (err instanceof PrincipalError && STATUS[err.code])
        throw new HttpError(
          STATUS[err.code] as number,
          err.code,
          "Placement refused.",
        );
      throw err;
    }
    send(res, 200, { principalId, tenantId, orgPath });
    return true;
  };
}
