export type PrincipalType =
  | "user"
  | "group"
  | "service"
  | "application"
  | "agent";

export type ResourceType =
  | "application"
  | "api"
  | "model"
  | "agent"
  | "prompt"
  | "mcp_server"
  | "tool"
  | "dataset"
  | "document"
  | "service";

export interface Principal {
  id: string;
  tenantId: string;
  type: PrincipalType;
  status: "active" | "disabled" | "deprovisioned";
  /** Required when `type` is `agent`. */
  ownerApplicationId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ExternalIdentity {
  id: string;
  principalId: string;
  providerConnectionId: string;
  issuer: string;
  subject: string;
  externalTenantId?: string;
  externalObjectId?: string;
  lastVerifiedAt: string;
}

export interface Resource {
  id: string;
  tenantId: string;
  type: ResourceType;
  orgUnitId: string;
  /** `<type>:<id>` */
  parent?: string;
  ownerPrincipalId?: string;
  applicationId?: string;
  externalProvider?: string;
  externalResourceId?: string;
  classification: "public" | "internal" | "confidential" | "restricted";
  status: "active" | "disabled" | "deleted";
  attributes?: Record<string, string | number | boolean>;
  createdAt: string;
  updatedAt: string;
}

export interface Delegation {
  id: string;
  tenantId: string;
  initiatingPrincipalId: string;
  actorPrincipalId: string;
  applicationId: string;
  taskId: string;
  parentDelegationId?: string;
  allowedResources: string[];
  allowedActions: string[];
  expiresAt: string;
  revokedAt?: string;
  policyVersion: string;
  createdAt: string;
}

export interface ExecutionContext {
  tenantId: string;
  orgPath: string[];
  principalId: string;
  principalType: PrincipalType;
  actorId: string;
  applicationId?: string;
  sessionId?: string;
  /** Required when `delegationId` is set. */
  taskId?: string;
  delegationId?: string;
  traceId?: string;
  requestId: string;
  costCenterId?: string;
}

export interface Bae6TokenClaims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  nbf?: number;
  exp: number;
  jti: string;
  txn: string;
  tenant_id: string;
  org_path: string[];
  principal_type: PrincipalType;
  act?: { sub: string };
  application_id?: string;
  session_id?: string;
  task_id?: string;
  delegation_id?: string;
  delegated_resources?: string[];
  delegated_actions?: string[];
  cost_center_id?: string;
  trace_id?: string;
}

export interface EventCorrelation {
  eventId: string;
  eventType: string;
  schemaVersion: number;
  occurredAt: string;
  tenantId: string;
  principalId: string;
  actorId: string;
  applicationId?: string;
  resource?: string;
  taskId?: string;
  delegationId?: string;
  traceId?: string;
  requestId: string;
  costCenterId?: string;
}

export interface AuthorizationEvent extends EventCorrelation {
  eventType: "authorization.decision";
  resource: string;
  action: string;
  decision: "allow" | "deny" | "indeterminate";
  reasonCode:
    | "granted"
    | "no_relation"
    | "guardrail"
    | "delegation_scope"
    | "delegation_expired"
    | "delegation_revoked"
    | "principal_disabled"
    | "unavailable";
  policyVersion: string;
  latencyMs: number;
}

export interface UsageEvent extends EventCorrelation {
  eventType: "usage.recorded";
  resource: string;
  provider: string;
  modelId: string;
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens?: number;
  usageUnits?: number;
  billingAccount?: string;
  currency?: string;
  /** Decimal string; required with `currency` and `pricingVersion`. */
  estimatedCost?: string;
  pricingVersion?: string;
}

export interface QuotaDecision {
  subjectType: "principal" | "org_unit" | "application" | "cost_center";
  subjectId: string;
  resource: string;
  limitType: "tokens" | "cost" | "requests";
  outcome: "reserved" | "exhausted";
  available: number;
  /** Present exactly when `outcome` is `reserved`. */
  reservationId?: string;
  expiresAt?: string;
}
