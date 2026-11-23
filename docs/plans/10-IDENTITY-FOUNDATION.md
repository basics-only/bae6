# bae6 — Identity foundation (authn + authz first)
Baseline: 2026-11-22 | Status: accepted | Epic: `epic/identity-foundation`, milestone "Identity foundation"

## Goal
Every bae6 service, and any enterprise service, gets identity from `bae6-authn` and access decisions from `bae6-authz`. This is the foundation for the rest of the suite. New AI and context features wait until the first services are routed through it.

## Where we start
- Eight services each verify IdP tokens with their own copy of `identity.ts`, mapping issuer to org and app in config.
- No `bae6-authn`, no principal registry, no provider adapters, no shared middleware.
- `bae6-authz` has check, batch, list-objects, pinned models and audit, with one OpenFGA store per application. Its model is only `user`, `organization`, `application`. No service calls it.
- Delegation is limited to the `Bae6-End-User-Token` header. There is no task scope, expiry or revocation.
- Test infra exists: mock OIDC with per-org issuers, a 20-org compose stack, CI, a load harness and a live AWS job.

## Decisions
| ADR | Decision |
|---|---|
| [0018](../adr/0018-tenancy-and-delegated-administration.md) | The tenant is the enterprise. Org units form a tree, and each level can have delegated admins with ceilings set by its parent. |
| [0019](../adr/0019-authn-and-internal-tokens.md) | `bae6-authn` exchanges IdP tokens for short-lived, audience-bound bae6 tokens that services verify locally. |
| [0020](../adr/0020-tenant-store-and-guardrails.md) | One OpenFGA store per tenant. Org guardrails are inherited by every app below them; apps can only tighten. |
| [0021](../adr/0021-principals.md) | Stable principals keyed on issuer and subject, with external identities, groups and lifecycle. |
| [0022](../adr/0022-delegation-and-execution-context.md) | Task-scoped delegation that never amplifies, plus a trusted execution context carried in the bae6 token. |

Layout stays as in ADR-0016:
- `services/authn/api`
- `packages/authn/{ts,py}`
- shared enforcement middleware in `packages/core`
- tests in `e2e/`

Product names gain `bae6-authn`.

## Epics
Each is a milestone, or a block of feature PRs into `epic/identity-foundation`.

### E0 Contracts
- Schemas in `contracts/`:
  - `Principal`, `ExternalIdentity`, `ExecutionContext`, `Delegation`, `Resource`
  - `AuthorizationEvent`, plus correlation fields shared with `UsageEvent`
  - `QuotaDecision` (contract only)
- OpenAPI for authn. TS and Python types.
- Gate: schemas validate, and authz changes are additive.

### A `bae6-authn`
1. Skeleton:
   - Postgres schema for principals, external identities, provider connections, sessions and signing keys
   - probes, Dockerfile, compose profile
2. Mock IdPs that imitate the three providers, extending `deploy/dev/mock-oidc`:
   - Entra `tid`/`oid` and group overage
   - Okta custom authorization servers
   - Ping custom claims
   - key rotation
3. OIDC core on `openid-client`:
   - discovery, JWKS rotation, Authorization Code with PKCE
   - state, nonce and exact redirect URIs
   - ID tokens and access tokens kept separate
4. Principal resolution, group mapping, disable and deprovision.
5. Token exchange (RFC 8693) and JWKS publishing, with KMS-compatible signing keys that rotate with an overlap window.
6. Provider adapters, in this order:
   - PingFederate
   - Entra: tenant pinning, Graph group overage, on-behalf-of
   - Okta
7. Backend-for-frontend sessions in Postgres: secure cookies, CSRF, logout. The console moves onto them.
8. Endpoints:
   - `/auth/providers`, `/auth/login/{p}`, `/auth/callback/{p}`, `/auth/logout`, `/auth/me`
   - `/auth/token` (the exchange), `/.well-known/jwks.json`
   - `/auth/introspect`: internal and scope-gated
- Gate: the spec's acceptance criteria for authentication pass against all three mock IdPs.

### B `bae6-authz` on the tenant model
1. Core model:
   - org-unit tree
   - admin capabilities and their ceilings
   - guardrails
   - resource types: application, api, model, agent, prompt, mcp_server, tool, dataset, document, service
   - actions such as `model:invoke`, `tool:invoke`, `dataset:query`, `document:read`
   - model tests for inherited allow and inherited deny
2. Tenant stores, plus a migration from the existing per-app stores.
3. Resource registry in Postgres, synced to OpenFGA through an outbox, with a reconciler that finds and repairs drift.
4. Resource and relationship APIs, all with idempotency keys. Every mutation is authorized against the caller's admin capabilities and ceilings.
5. Authn principals and groups become OpenFGA subjects. A reconciler syncs group membership.
6. Enforcement points:
   - TS middleware for `node:http`, Fastify and Express
   - a FastAPI dependency
   - a generic HTTP ext-authz endpoint for gateways
   - All deny by default, bound the check time, and report an outage as 503, never as allow.
7. Revocation and cache tests.
- Gate: the spec's acceptance criteria for authorization pass, and every delegated-admin escalation attempt is denied.

### C Delegation, context, events, SDKs
1. Delegation API: create, validate, revoke, with nesting limits and approval hooks.
2. `ExecutionContext` built into the bae6 token, readable through the middleware.
3. Event outbox. Authorization events and usage events share correlation IDs but use separate pipelines.
4. SDKs, TS and Python at parity:
   - `authn.authenticate(request)`, `authz.require(...)`, `authz.batch(...)`, resource registration, delegation
5. Examples:
   - `fastapi-protected-api`
   - `node-protected-api`
   - `agent-delegation`
   - `sveltekit-oidc-app`, which becomes the chatbot example
- Gate: an agent runs with delegated scope. Expired, revoked and amplified delegations are rejected.

### D Route existing services through the foundation
One PR per service. Each:
- replaces `identity.ts` with the shared middleware
- trusts only authn's issuer
- adds resource checks

| Service | Checks |
|---|---|
| ai gateway | `model:invoke`. Budgets roll up along `org_path` from the token. |
| data-api | `dataset:query`, `document:read` |
| embed-api | `document:read` on retrieval |
| mcp-registry, mcp-gateway | `mcp_server:*`, `tool:invoke` |
| agent-worker, eval-worker | Run under a delegation; tools checked per call |
| console | Logs in through authn sessions |

- Gate: `make demo` passes with direct IdP trust removed from every service.

### E Pilot hardening
- Hand-run live suites against real Ping, Entra and Okta test tenants.
- Fault injection: OpenFGA, Postgres and the IdP down; slow network.
- A load test that includes an authz check scenario.
- SBOM, signed images, recovery and key-rotation runbooks.
- Gate: the definition of done below.

## Order
1. E0 comes first.
2. A1–A5 and B1–B4 then run in parallel.
3. B6 and C2 need both.
4. D needs B6.
5. E comes last.

First vertical slice:
1. A mock Ping login.
2. The authn token exchange.
3. The ai gateway verifies the bae6 token.
4. A `model:invoke` check on the tenant store.
5. An audit event and a usage event that join on `request_id` and `principal_id`.

## Paused until D lands
P11 doc render, new AI and context features, and the standalone chatbot repo (it becomes `examples/sveltekit-oidc-app`).

## Definition of done (enterprise pilot)
- PingFederate, Entra ID and Okta sign-in is tested against real provider tenants.
- Principals are stable and tenant-scoped.
- Token validation is tested against known attacks.
- OpenFGA covers users, groups, applications, services, agents and resources.
- TS and Python services both enforce authorization.
- Delegated admins cannot escalate beyond their ceiling or outside their subtree.
- Apps cannot loosen an inherited guardrail.
- An agent runs with limited delegated scope, and expired or revoked delegation is rejected.
- Every protected operation carries trusted correlation and attribution IDs. Authorization and usage events join without email.
- Provider or policy-store outages never produce an allow.
- Onboarding, deployment, recovery and security guides exist.

## Open risks
1. **OpenFGA resolution depth.** OpenFGA bounds how deep a check can recurse (believed default about 25). Admin capabilities that inherit up a 32-level tree, intersected with guardrails, may hit it. B1 measures this first. The depth max may drop, or the limit may be raised.
2. **Guardrail latency.** Every check intersects the app's relation with every ancestor's guardrails. p95 at depth 8 and 32 is unmeasured. B1 benchmarks it with the existing load harness.
3. **One model per tenant.** All apps in a tenant share one composed model, so one app's extension change produces a new tenant model. App types need a per-app prefix, and a broken extension must not block other apps' changes. B1 must validate each extension in isolation.
4. **authn's signing key.** Minting internal tokens makes it the most valuable secret in the suite. It needs KMS, an overlap-window rotation and a runbook before the pilot.
5. **authn availability.** Services verify tokens locally, but new sessions and token refreshes need authn. If it is down, issued tokens last at most 5 min. authn needs multiple replicas and a tested outage drill. This partly bends the master plan's "no runtime dependency on the control plane".
6. **Transaction Tokens draft.** ADR-0019 follows draft-ietf-oauth-transaction-tokens (latest seen: -06, July 2025). Status since then is unverified. If the claims change, ours may diverge.
7. **Real provider tenants.** Epic E needs Ping, Entra and Okta test tenants and credentials. Until then, the adapters are proven only against mocks.
8. **Group freshness.** Group claims in IdP tokens lag membership changes, and Entra group overage needs Microsoft Graph credentials. Effective staleness is at most the token TTL plus the sync interval, and only if the sync runs.
9. **Store migration.** Moving per-app stores into tenant stores is the only step that touches existing data. It needs `db-guardian`, a dry-run diff on a copy, and a rollback to the old pin.
10. **Not in v1.** Overridable "default" org rules (as opposed to mandatory guardrails) and a second approver for sensitive grants. Add them only if a pilot needs them.
