import { ORGANIZATION_ID } from "./principal.js";

const OPTIONAL = [
  ["application_id", "applicationId", ORGANIZATION_ID],
  ["session_id", "sessionId", /^ses_[0-9a-f]{32}$/],
  ["task_id", "taskId", /^[A-Za-z0-9._-]{1,128}$/],
  ["trace_id", "traceId", /^[0-9a-f]{32}$/],
  ["cost_center_id", "costCenterId", ORGANIZATION_ID],
] as const;

export function directExecutionContext(
  claims: Record<string, unknown>,
  tenantId: string,
  principalId: string,
  principalType: string,
) {
  const { org_path: orgPath } = claims;
  if (
    !Array.isArray(orgPath) ||
    orgPath.length < 1 ||
    orgPath.length > 32 ||
    orgPath[0] !== tenantId ||
    !orgPath.every(
      (unit) => typeof unit === "string" && ORGANIZATION_ID.test(unit),
    )
  )
    return undefined;

  const optional: Partial<Record<(typeof OPTIONAL)[number][1], string>> = {};
  for (const [claim, field, pattern] of OPTIONAL) {
    const value = claims[claim];
    if (value === undefined) continue;
    if (typeof value !== "string" || !pattern.test(value)) return undefined;
    optional[field] = value;
  }
  return {
    tenantId,
    orgPath: orgPath as string[],
    principalId,
    principalType,
    actorId: principalId,
    ...optional,
  };
}
