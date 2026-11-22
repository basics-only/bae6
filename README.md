# bae6

Minimal, open-source primitives for authorization, AI execution and model context, each
usable on its own. Every product has TypeScript and Python SDKs and independently
deployable services.

| Product | SDKs | Services |
|---|---|---|
| authz (OpenFGA-backed authorization) | `packages/authz` | `services/authz/api` |
| ai (Bedrock/Vertex gateway, agents, evals, guardrails) | `packages/ai` | `services/ai/*` |
| context (data, embeddings, MCP registry) | `packages/context` | `services/context/*` |

`contracts/` holds the shared API schemas and conformance fixtures, `packages/core` the
shared SDK transport, `deploy/` the compose stack, charts and Terraform, and `docs/` the
plans and ADRs.

## Develop
```
make install
make test
make up PROFILE=authz   # authz | ai | context | all
```
Set `CONTAINER_RUNTIME=docker` to use Docker instead of Podman.

## License
Apache-2.0.
