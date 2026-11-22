# bae6 — Execution Plan and Progress
Baseline: 2026-11-17. Companion to `00-MASTER-PLAN.md`; records how the plans are being built and where work stands.

## Decisions (maintainer, 2026-11-17)
- Five public repos under `github.com/basics-only`, checked out as siblings of this folder.
- `bae6-authz` is `riz` (github.com/quentin-auster/riz) with full git history, starting from riz `dev`. Open riz PRs #82–#84 become feature branches in bae6-authz and are finished in P1; riz takes no new work. History secret scan: 8 gitleaks hits, all dev fixture tokens (`dev-alice-token` etc.); no real secrets.
- Branches per AGENTS.md: `main` ← `dev` ← `epic/<phase>` ← `feature/*`; each epic is a GitHub milestone. Each epic is reviewed by the `reviewer` agent, then PR'd into `dev`.
- The agent merges green, reviewed PRs and pushes release tags (maintainer allow rule, 2026-11-17).
- Cloud inference/query providers mocked; live Bedrock/Vertex/Databricks smoke tests stay **pending** until credentials exist.
- Deferred until core gates pass (already optional in the plans): SharePoint, FAISS, MCP gateway, agent-worker/eval-worker, LangChain adapter, KEDA, Terraform EKS/GKE modules.
- riz's SvelteKit console stays in history but is not released or deployed in v1 (master plan out-of-scope: admin portals).

## Stack (inherited from riz)
- Services: TypeScript on Node 22, `node:http` (no web framework), `pg`, `jose`, OpenTelemetry. pnpm workspace, biome, redocly, `tsx --test`.
- Python SDKs: uv workspace, httpx, ruff, mypy strict, pytest.
- Images: multi-stage Dockerfile, base pinned by digest, non-root; release via GHCR + cosign keyless + SBOM/provenance.

## Cross-repo mechanics (smallest workable)
- **Contracts distribution**: consumers vendor `bae6-contracts` schema files at a released tag into `contracts/vendor/` with a `contracts.lock` (tag + sha256). CI fails if vendored files differ from the lock. No package registry needed.
- **Compatibility checks**: `oasdiff breaking` against the previous tag, in contracts CI.
- **SDK transport**: each product SDK carries its own small transport (timeouts, bounded retries for idempotent calls only, `ErrorEnvelope` parsing, no redirects). Shared behavior is pinned by transport conformance cases published in contracts.
- **Helm**: one generic chart `bae6-service` in `bae6-platform`; every runtime is a separate Helm release with its own values file, image digest and chart version pin (ADR-008).
- **Package publishing** (npm `@bae6/*`, PyPI `bae6-*`): workflows written but unverified until the maintainer claims the names and adds tokens.

## Phases and status
| Phase | Repo(s) | Status |
|---|---|---|
| P0 Foundation | contracts, platform, scaffolds of all five | done: contracts v0.1.0 released; platform P0 merged to dev; all five repos have main+dev. |
| P1 Authorization | authz | done: epic/p1-authz merged to dev (authz PR #9). |
| P2 AI core | ai | done: epic/p2-ai-core merged to dev (ai PRs #8, #10); /v1/responses, /v1/decisions, /v1/generations and admin endpoints deferred (ai issue #9). |
| P3 Context data | context | done: epic/p3-context-data merged to dev (context PR #6). |
| P4 Context embed | context | built on epic/p4-context-embed (PRs #7-#13: core, pgvector index, job queue, embed-api, deploy, SDKs, benchmark); epic merged to dev (context PR #14); p95 and storage benchmarks recorded there. |
| P5 Context MCP | context | built on epic/p5-context-mcp (PRs #15-#19: core, Postgres store, registry API, SDKs, deploy); epic merged to dev (context PR #20). Gateway deferred. Open follow-ons: DB errors as 503, byte-bounded lists, shared identity/http package. |
| P6 AI extensions | ai | done: epic/p6-ai-extensions merged to dev (ai PRs #11-#13, epic #14): agents, evals, guardrails packages. Workers and LangChain adapter deferred. Open follow-ons: agent message-history bound, receipts echo blocked input, guard-per-run budget, never run against a real model. |
| P8 Deferred components (queued 2026-11-19) | ai, context | in order: agent-worker, eval-worker, LangChain adapter (ai, `epic/p8-ai-workers`); MCP gateway (context). Agent-worker also hosts MCP/harness feedback (ADR 0009). Worker run, eval and feedback data must be readable over public APIs for the console. |
| P9 Terraform | platform | built on epic/p9-terraform: EKS module (platform PR #13) and GKE module (PR #14), mocked-provider tests only, CI terraform job; never planned or applied against a real account. Open: GKE needs a SQL step to revoke PUBLIC CONNECT per runtime database; EKS has one shared database; setup-terraform unpinned. Enables live cloud smoke tests. |
| P10 Console | new repo `bae6-console` | after P9: SvelteKit over public APIs only; needs an ADR (admin portals are out of scope v1). Includes evals, feedback, MCP and agent registry views. Base on riz console in bae6-authz history. Built locally in `bae6-console` (not yet a GitHub repo); ADR 0010 proposed in contracts PR #7. Eval and agent views need the worker PRs merged. No harness registry view (no API). |
| P11 Doc render | new repo (name TBD) | plan in `09-DOC-RENDER.md`; Rust core + WASM; after console ADR. |
| P7 Integration | platform | done: epic/p7-integration merged to dev (platform PRs #2-#6, tag v0.1.0; ai #15-#18, tag v0.1.2). Podman compose stack, 5-test demo, load, footprint, rollback drills, security review in docs/p7-gate.md. Security review F1 fixed. Open: ai#19 (per-org in-flight limit), context#21 (unlogged sync error), context#22 (shared embed AI token, S3 allowlist, principal subject type). Mocks only; live smoke tests, authz and OpenFGA in the stack, and kind/Helm run pending. |
