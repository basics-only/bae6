# bae6 — Execution Plan and Progress
Baseline: 2026-11-17; monorepo since 2026-11-22 (ADR 0016). Companion to `00-MASTER-PLAN.md`; records how the plans are being built and where work stands.

## Decisions (maintainer)
- One public repository, `github.com/basics-only/bae6` (Apache-2.0). The five product repos and `bae6-console` were merged into it with history and are archived read-only.
- `authz` is `riz` (github.com/quentin-auster/riz) with full git history; riz takes no new work. History secret scan: 8 gitleaks hits, all dev fixture tokens (`dev-alice-token` etc.); no real secrets.
- Branches per AGENTS.md: `main` ← `dev` ← `epic/*` ← `feature/*`; each epic is a GitHub milestone.
- The agent merges green, reviewed PRs and pushes release tags. There is no CI yet: checks run locally (`make lint typecheck test`, `make integration`) and PRs say so.
- Cloud inference/query providers mocked; live Bedrock/Vertex/Databricks smoke tests stay **pending** until credentials exist.
- Deferred: SharePoint, FAISS, KEDA.

## Layout
- `contracts/` shared schemas, OpenAPI and transport fixtures, referenced in place.
- `packages/<product>/*` libraries and SDKs (`ts`, `py`); `packages/core` is the shared SDK transport (`@bae6/sdk-core`, `bae6-sdk-core`).
- `services/<product>/*` deployables, each with a Dockerfile; `services/console` is the operator console.
- `deploy/` compose stack (profiles `authz`, `ai`, `context`, `all`, `console`, `replicas`, `observability`), charts and Terraform.
- Tags are per unit, `<unit>-v<semver>`. Tags before 2026-11-22 are history from the old repos.

## Stack
- Services: TypeScript on Node 22, `node:http`, `pg`, `jose`, OpenTelemetry. pnpm workspace, biome, redocly, `tsx --test`.
- Python SDKs: uv workspace, httpx, ruff, mypy strict, pytest.
- Images: multi-stage Dockerfile, base pinned by digest, non-root.

## Mechanics
- **Contracts**: consumed in place; a contract change and its consumers land in one PR. `oasdiff breaking` against the previous `contracts-v*` tag is run by hand.
- **SDKs**: a shared transport (timeouts, bounded retries for idempotent calls only, credentials as string or function, `onRequest`/`onResponse` hooks, injectable fetch/httpx, no redirects) with per-product error classes. Conformance cases live in `contracts/fixtures/transport`.
- **Helm**: one generic chart `bae6-service` in `deploy/charts`; every runtime is its own release.
- **Publishing** (npm `@bae6/*`, PyPI `bae6-*`): not set up; needs the names claimed and tokens.

## Phases and status
| Phase | Area | Status |
|---|---|---|
| P0 Foundation | contracts, deploy | done. |
| P1 Authorization | authz | done. Not yet on main. |
| P2 AI core | ai | done; Bedrock/Vertex mocked. /v1/responses, /v1/decisions, /v1/generations and admin endpoints deferred. |
| P3 Context data | context | done; Databricks mocked. |
| P4 Context embed | context | done: core, pgvector index, job queue, embed-api, SDKs, benchmark. |
| P5 Context MCP | context | done: core, Postgres store, registry API, SDKs. Open: DB errors as 503, byte-bounded lists, shared identity/http package. |
| P6 AI extensions | ai | done: agents, evals, guardrails. Open: agent message-history bound, receipts echo blocked input, guard-per-run budget; never run against a real model. |
| P7 Integration | deploy | done: compose stack, 5-test demo, load, footprint, rollback drills, security review in `docs/platform/p7-gate.md`. Open: shared embed AI token, S3 allowlist, principal subject type, unlogged sync error, per-org in-flight limit. Pending: live smoke tests, kind/Helm run. |
| P8 Deferred components | ai, context | agent-worker, eval-worker, LangChain adapter and MCP gateway are in the tree. Workers and gateway run healthy in compose; no run, eval or MCP call has been exercised end to end. |
| P9 Terraform | deploy | EKS and GKE modules, mocked-provider tests only; never planned or applied against a real account. Open: GKE needs a SQL step to revoke PUBLIC CONNECT per database; EKS has one shared database. |
| P10 Console | services/console | SvelteKit over public APIs, in the monorepo with a Dockerfile and a `console` compose profile; login needs a real OIDC provider and has not been exercised. ADR 0010 is still proposed. No harness registry view (no API). |
| P11 Doc render | new product | plan in `09-DOC-RENDER.md`; Rust core + WASM; after the console ADR. |

## Monorepo follow-ups
- CI, release automation with `<unit>-v<semver>` tags, dependabot, and import-boundary checks are deferred until requested.
- Compatibility table across units is not written.
