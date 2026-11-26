# Changelog

## 0.2.0
- Identity foundation schemas (ADR-0018 to ADR-0022): `Principal`, `ExternalIdentity`,
  `Resource`, `Delegation`, `ExecutionContext`, `Bae6TokenClaims`, `EventCorrelation`,
  `AuthorizationEvent`, `UsageEvent`, `QuotaDecision`. Additive only.
- A delegated `Bae6TokenClaims` carries its scope as `delegated_resources` and `delegated_actions`.
  `Delegation` allows at most 16 resources and 16 actions so that scope fits in the token.

## 0.1.0
- First schemas: `IdentityContext`, `RequestContext`, `ErrorEnvelope`, `Page`, `AuditEvent`,
  `CapabilityDescriptor`, and the shared OpenAPI components in `openapi/common.yaml`.
- SDK transport conformance cases (`fixtures/transport`).
- ADR-0001 to ADR-0008 and the API style guide.
