# 0018 — Tenancy, org hierarchy and delegated administration

Status: proposed
Date: 2026-11-22

## Context
An enterprise is one customer made of many organizations and teams (Finance, Software, Executives, and teams inside them). Each level may want its own decision-makers or IT staff to manage settings and access for its part of the tree, without touching anyone else's. Supersedes "the tenant is the organization" in ADR-0002.

## Decision
- **The tenant is the enterprise.** No data, decision or error crosses tenants. Another tenant's resource is a 404.
- **Org units form a tree inside the tenant.**
  - Organizations and teams are one node type, `org_unit`, with a `kind` label.
  - Every node except the root has exactly one parent.
  - Depth is capped per tenant: default 8, maximum 32. A write that would exceed the cap is rejected.
  - Applications and resources belong to exactly one node.
- **Admin capabilities are a fixed set defined in the core model.**

  | Capability | Can |
  |---|---|
  | `access_admin` | Grant and revoke access to resources in the subtree |
  | `settings_admin` | Change node settings and provider connections |
  | `app_admin` | Register and configure applications and resources |
  | `budget_admin` | Set budgets and quotas |
  | `security_admin` | Set guardrails (ADR-0020); read audit |

  A tenant groups capabilities into named roles, such as "IT admin" or "finance approver". Roles are data, not model changes.
- **Assignment.** A capability is granted to a principal or group at a node and covers that node's subtree. It never covers ancestors or siblings.
- **Ceilings.** For each child node, the parent decides which capabilities that child's admins may grant onward. Granting a capability at node N requires all of:
  1. the granter holds it at N or above
  2. it is delegable at N
  3. N is inside the granter's subtree

  No one can raise their own ceiling. The authz API enforces this on every grant. OpenFGA only evaluates the resulting tuples.
- **Ordinary access does not flow down the tree.** Only admin capabilities and guardrails (ADR-0020) are inherited.
- **Every grant, revoke and ceiling change is an audit event** that names the granter, the grantee, the node and the capability.
- **Platform operators** (cross-tenant tooling) are outside every tenant tree and audited separately.

## Consequences
- Each org and team can run its own access and IT administration within limits set from above.
- Escalation tests are mandatory:
  - grant above your ceiling
  - grant at an ancestor or sibling
  - grant to yourself beyond what you hold
  - raise a ceiling
- Deep trees cost check latency, and OpenFGA bounds recursion depth. The 32 max is unverified (plan risk 1).
- v1 has no second approver for sensitive grants.
