# 0020 — Tenant store and inherited guardrails

Status: proposed
Date: 2026-11-22

## Context
The org tree, delegated admins (ADR-0018) and resources shared across applications (models, MCP servers, tools) must be evaluated together. OpenFGA evaluates a check inside one store. Organizations also need rules that every application beneath them inherits, while app developers still decide access within their own context. Supersedes one store per application.

## Decision
- **One OpenFGA store per tenant and environment.** It holds the org tree, admin capabilities, guardrails, applications and resources. Store and model IDs are resolved server-side and never come from callers.
- **Tenant model = core + app extensions.**
  - bae6 owns the core: tree, capabilities, guardrails, resource types and actions.
  - Each application owns an extension.
  - Extension types are prefixed by application. Extensions cannot redeclare or change core types.
  - Each extension is validated in isolation before it is composed into the tenant model.
  - The composed model is immutable and pinned.
- **Guardrails.**
  - A node's `security_admin` can attach rules to that node: allow-lists such as "only `finance` members may invoke `model:finance-llm`" and exclusions such as "contractors may not invoke tool X".
  - A guardrail applies to every application and resource in the node's subtree.
  - A child node can add stricter guardrails but cannot remove or weaken an ancestor's.
- **Effective decision.** The relation authz checks for an action is defined in the core as the app's own relation AND every guardrail above the resource. Apps can add relations and conditions in their extensions, so they can tighten access, never loosen it.
- **Migration.** Existing per-application stores are copied into tenant stores:
  - by an idempotent, re-runnable migration
  - after a dry-run diff
  - with rollback by restoring the previous pin

## Consequences
- App developers inherit org policy by placing their app in the tree, then layer their own rules on top.
- One app's extension change produces a new tenant model. A broken extension must not block other apps.
- The tenant, not the application, is the store-level blast radius.
- Every check pays for the guardrail intersection. Latency at depth 8 and 32 is unmeasured (plan risk 2).
- Overridable "default" rules are not in v1. Every guardrail is mandatory.
