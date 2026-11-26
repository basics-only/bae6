from typing import Literal, NotRequired, TypedDict

PrincipalType = Literal["user", "group", "service", "application", "agent"]
ResourceType = Literal[
    "application",
    "api",
    "model",
    "agent",
    "prompt",
    "mcp_server",
    "tool",
    "dataset",
    "document",
    "service",
]


class Principal(TypedDict):
    id: str
    tenantId: str
    type: PrincipalType
    status: Literal["active", "disabled", "deprovisioned"]
    ownerApplicationId: NotRequired[str]  # required when type is "agent"
    createdAt: str
    updatedAt: str


class ExternalIdentity(TypedDict):
    id: str
    principalId: str
    providerConnectionId: str
    issuer: str
    subject: str
    externalTenantId: NotRequired[str]
    externalObjectId: NotRequired[str]
    lastVerifiedAt: str


class Resource(TypedDict):
    id: str
    tenantId: str
    type: ResourceType
    orgUnitId: str
    parent: NotRequired[str]
    ownerPrincipalId: NotRequired[str]
    applicationId: NotRequired[str]
    externalProvider: NotRequired[str]
    externalResourceId: NotRequired[str]
    classification: Literal["public", "internal", "confidential", "restricted"]
    status: Literal["active", "disabled", "deleted"]
    attributes: NotRequired[dict[str, str | int | float | bool]]
    createdAt: str
    updatedAt: str


class Delegation(TypedDict):
    id: str
    tenantId: str
    initiatingPrincipalId: str
    actorPrincipalId: str
    applicationId: str
    taskId: str
    parentDelegationId: NotRequired[str]
    allowedResources: list[str]
    allowedActions: list[str]
    expiresAt: str
    revokedAt: NotRequired[str]
    policyVersion: str
    createdAt: str


class ExecutionContext(TypedDict):
    tenantId: str
    orgPath: list[str]
    principalId: str
    principalType: PrincipalType
    actorId: str
    applicationId: NotRequired[str]
    sessionId: NotRequired[str]
    taskId: NotRequired[str]  # required when delegationId is set
    delegationId: NotRequired[str]
    traceId: NotRequired[str]
    requestId: str
    costCenterId: NotRequired[str]


class Actor(TypedDict):
    sub: str


class Bae6TokenClaims(TypedDict):
    iss: str
    aud: str
    sub: str
    iat: int
    nbf: NotRequired[int]
    exp: int
    jti: str
    txn: str
    tenant_id: str
    org_path: list[str]
    principal_type: PrincipalType
    act: NotRequired[Actor]
    application_id: NotRequired[str]
    session_id: NotRequired[str]
    task_id: NotRequired[str]
    delegation_id: NotRequired[str]
    delegated_resources: NotRequired[list[str]]
    delegated_actions: NotRequired[list[str]]
    cost_center_id: NotRequired[str]
    trace_id: NotRequired[str]


# Without eventType and resource, which each event narrows; a TypedDict cannot redeclare a key.
class _Correlation(TypedDict):
    eventId: str
    schemaVersion: int
    occurredAt: str
    tenantId: str
    principalId: str
    actorId: str
    applicationId: NotRequired[str]
    taskId: NotRequired[str]
    delegationId: NotRequired[str]
    traceId: NotRequired[str]
    requestId: str
    costCenterId: NotRequired[str]


class EventCorrelation(_Correlation):
    eventType: str
    resource: NotRequired[str]


class AuthorizationEvent(_Correlation):
    eventType: Literal["authorization.decision"]
    resource: str
    action: str
    decision: Literal["allow", "deny", "indeterminate"]
    reasonCode: Literal[
        "granted",
        "no_relation",
        "guardrail",
        "delegation_scope",
        "delegation_expired",
        "delegation_revoked",
        "principal_disabled",
        "unavailable",
    ]
    policyVersion: str
    latencyMs: float


class UsageEvent(_Correlation):
    eventType: Literal["usage.recorded"]
    resource: str
    provider: str
    modelId: str
    inputTokens: int
    outputTokens: int
    cachedInputTokens: NotRequired[int]
    usageUnits: NotRequired[float]
    billingAccount: NotRequired[str]
    currency: NotRequired[str]
    estimatedCost: NotRequired[str]  # decimal string; needs currency and pricingVersion
    pricingVersion: NotRequired[str]


class QuotaDecision(TypedDict):
    subjectType: Literal["principal", "org_unit", "application", "cost_center"]
    subjectId: str
    resource: str
    limitType: Literal["tokens", "cost", "requests"]
    outcome: Literal["reserved", "exhausted"]
    available: float
    reservationId: NotRequired[str]  # present exactly when outcome is "reserved"
    expiresAt: NotRequired[str]
