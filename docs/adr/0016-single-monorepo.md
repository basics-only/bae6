# 0016 — Single monorepo

Status: accepted
Date: 2026-11-22

## Context
The master plan fixed five repos (`bae6-authz`, `bae6-ai`, `bae6-context`, `bae6-contracts`,
`bae6-platform`). Contracts changed in lockstep with their consumers across repos through
vendored copies and checksums, and a small team paid for five CI setups, five release flows
and cross-repo pull requests for one change.

## Decision
One public repository, `basics-only/bae6`, supersedes non-negotiable 1 of the master plan.
Independence is kept by structure, not by repository boundaries:

- `contracts/` is referenced in place; a contract change and its consumers land in one PR.
- `packages/<product>/{ts,py}` are the published SDKs and libraries; `packages/core` is the
  shared transport. `services/<product>/*` are the deployables. `deploy/` holds the compose
  stack, charts and Terraform.
- Per-unit versions and tags (`<unit>-v<semver>`) remain; there is no global release train.
- A product directory may be split into its own repository later with its history.

All other non-negotiables, including independent deployment and publishing, are unchanged.

## Consequences
Cross-cutting changes are atomic and one toolchain serves everything. Isolation between
products is no longer enforced by repository permissions, so it depends on review and on
import checks. Old repository tags remain as history only.
