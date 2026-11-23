import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type {
  AuthorizationEvent,
  Bae6TokenClaims,
  Delegation,
  EventCorrelation,
  ExecutionContext,
  ExternalIdentity,
  Principal,
  QuotaDecision,
  Resource,
  UsageEvent,
} from "./identity.js";

// The compiler forces one entry per field with its optionality; the test compares that to the schema.
type Shape<T> = {
  [K in keyof T]-?: Record<never, never> extends Pick<T, K>
    ? "optional"
    : "required";
};

interface Schema {
  properties: Record<string, unknown>;
  required?: string[];
  allOf?: { $ref: string }[];
}

const load = (file: string): Schema =>
  JSON.parse(
    readFileSync(
      new URL(`../../../../contracts/schemas/${file}`, import.meta.url),
      "utf8",
    ),
  );

function schemaShape(file: string): Record<string, string> {
  const s = load(file);
  const parts = [...(s.allOf ?? []).map((r) => load(r.$ref)), s];
  const required = new Set(parts.flatMap((p) => p.required ?? []));
  const keys = new Set(parts.flatMap((p) => Object.keys(p.properties)));
  return Object.fromEntries(
    [...keys].map((k) => [k, required.has(k) ? "required" : "optional"]),
  );
}

const cases: [string, Record<string, string>][] = [
  [
    "principal.json",
    {
      id: "required",
      tenantId: "required",
      type: "required",
      status: "required",
      ownerApplicationId: "optional",
      createdAt: "required",
      updatedAt: "required",
    } satisfies Shape<Principal>,
  ],
  [
    "external-identity.json",
    {
      id: "required",
      principalId: "required",
      providerConnectionId: "required",
      issuer: "required",
      subject: "required",
      externalTenantId: "optional",
      externalObjectId: "optional",
      lastVerifiedAt: "required",
    } satisfies Shape<ExternalIdentity>,
  ],
  [
    "resource.json",
    {
      id: "required",
      tenantId: "required",
      type: "required",
      orgUnitId: "required",
      parent: "optional",
      ownerPrincipalId: "optional",
      applicationId: "optional",
      externalProvider: "optional",
      externalResourceId: "optional",
      classification: "required",
      status: "required",
      attributes: "optional",
      createdAt: "required",
      updatedAt: "required",
    } satisfies Shape<Resource>,
  ],
  [
    "delegation.json",
    {
      id: "required",
      tenantId: "required",
      initiatingPrincipalId: "required",
      actorPrincipalId: "required",
      applicationId: "required",
      taskId: "required",
      parentDelegationId: "optional",
      allowedResources: "required",
      allowedActions: "required",
      expiresAt: "required",
      revokedAt: "optional",
      policyVersion: "required",
      createdAt: "required",
    } satisfies Shape<Delegation>,
  ],
  [
    "execution-context.json",
    {
      tenantId: "required",
      orgPath: "required",
      principalId: "required",
      principalType: "required",
      actorId: "required",
      applicationId: "optional",
      sessionId: "optional",
      taskId: "optional",
      delegationId: "optional",
      traceId: "optional",
      requestId: "required",
      costCenterId: "optional",
    } satisfies Shape<ExecutionContext>,
  ],
  [
    "bae6-token-claims.json",
    {
      iss: "required",
      aud: "required",
      sub: "required",
      iat: "required",
      nbf: "optional",
      exp: "required",
      jti: "required",
      txn: "required",
      tenant_id: "required",
      org_path: "required",
      principal_type: "required",
      act: "optional",
      application_id: "optional",
      session_id: "optional",
      task_id: "optional",
      delegation_id: "optional",
      cost_center_id: "optional",
      trace_id: "optional",
    } satisfies Shape<Bae6TokenClaims>,
  ],
];

const correlation = {
  eventId: "required",
  eventType: "required",
  schemaVersion: "required",
  occurredAt: "required",
  tenantId: "required",
  principalId: "required",
  actorId: "required",
  applicationId: "optional",
  resource: "optional",
  taskId: "optional",
  delegationId: "optional",
  traceId: "optional",
  requestId: "required",
  costCenterId: "optional",
} as const;

cases.push(
  ["event-correlation.json", correlation satisfies Shape<EventCorrelation>],
  [
    "authorization-event.json",
    {
      ...correlation,
      resource: "required",
      action: "required",
      decision: "required",
      reasonCode: "required",
      policyVersion: "required",
      latencyMs: "required",
    } satisfies Shape<AuthorizationEvent>,
  ],
  [
    "usage-event.json",
    {
      ...correlation,
      resource: "required",
      provider: "required",
      modelId: "required",
      inputTokens: "required",
      outputTokens: "required",
      cachedInputTokens: "optional",
      usageUnits: "optional",
      billingAccount: "optional",
      currency: "optional",
      estimatedCost: "optional",
      pricingVersion: "optional",
    } satisfies Shape<UsageEvent>,
  ],
  [
    "quota-decision.json",
    {
      subjectType: "required",
      subjectId: "required",
      resource: "required",
      limitType: "required",
      outcome: "required",
      available: "required",
      reservationId: "optional",
      expiresAt: "optional",
    } satisfies Shape<QuotaDecision>,
  ],
);

for (const [file, shape] of cases) {
  test(`${file} fields and optionality match the TS type`, () => {
    assert.deepEqual(
      Object.fromEntries(Object.entries(shape).sort()),
      Object.fromEntries(Object.entries(schemaShape(file)).sort()),
    );
  });
}
