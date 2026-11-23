# 0017 — Check-path cache window

Status: accepted
Date: 2026-11-22

## Context
Each authz check reads the workload binding and the application's active model from
Postgres before asking OpenFGA. Without a cache, a Postgres failover makes every check
indeterminate. Caching those reads trades failover resilience for staleness on
revocation, which the security suite had assumed was immediate.

## Decision
- Found workload bindings and active-model lookups are cached per replica for
  `BAE6_LOOKUP_CACHE_MS` (default 5000). Empty results are never cached, so a workload's
  first binding or an application's first model applies on the next check. A binding
  added to a workload that already has others can take up to the window.
- Unbinding a workload and switching or rolling back a model take effect within the
  window, not on the next check.
- While Postgres is unreachable, a check whose lookups are cached is still answered; once
  the window passes, it is `indeterminate`. No uncached lookup is ever answered from
  anything but Postgres.
- OpenFGA is asked on every check, so tuple writes and deletes are never delayed by this
  cache.
- Operators who need immediate revocation set `BAE6_LOOKUP_CACHE_MS=0`.

## Consequences
- An unbound or compromised workload keeps check access for up to the window.
- The security suite runs with a 300 ms window and asserts each guarantee after it passes.
- Not verified: the window across several replicas under a real failover.
