# 0022 — Delegation and execution context

Status: proposed
Date: 2026-11-22

## Context
Agents and services act for users on specific tasks. Each downstream call must name both the actor and the original initiator, carry only the scope the task needs, and carry attribution that can be trusted for audit and cost.

## Decision
- **Delegation:** `id`, `tenant_id`, `initiating_principal_id`, `actor_principal_id`, `application_id`, `task_id`, `allowed_resources`, `allowed_actions`, `expires_at`, `revoked_at`, `policy_version`.
  - It is created through `POST /v1/delegations` and revoked through `POST /v1/delegations/{id}/revoke`.
- **Scope rule.** At creation, and again on every check, a delegated action must pass all of:
  1. it is in the delegation
  2. the initiator is allowed to do it now
  3. the actor is allowed to do it now
- **Bounds.**
  - Every delegation expires, capped per tenant.
  - A nested delegation's scope must be a subset of its parent's, and its expiry no later.
  - Nesting depth is capped.
  - Revoking a delegation revokes everything nested under it.
- **Approval.** Actions marked high-impact in the core model need an explicit approval from the initiator before the delegation covers them.
- **ExecutionContext:** `tenant_id`, `principal_id`, `actor_id`, `application_id`, `session_id`, `task_id`, `delegation_id`, `trace_id`, `request_id`, `cost_center_id`.
  - It is built only from verified claims in the bae6 token (ADR-0019).
  - It is never read from public headers or request bodies.
  - `cost_center_id` is assigned by an admin, never supplied by the caller.
- **Events.** Authorization events and usage events share these correlation fields but go through separate pipelines. authz never emits consumption figures. The usage side comes from the service that did the work.
- **Quota** is a separate decision (`QuotaDecision`). In v1 only the contract and hooks exist, and budgets stay in the ai gateway.

## Consequences
- Revocation and the initiator losing access both take effect on the next check: at once with `higher_consistency`, within the cache window otherwise.
- Three checks per delegated action cost latency. They are batched into one OpenFGA call where possible.
- Required tests:
  - cross-task token reuse
  - nested amplification
  - expired and revoked delegations
  - user access revoked mid-task
