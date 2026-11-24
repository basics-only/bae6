# Examples

One small service per integration path. Each asks bae6-authz whether the calling user may read a
document, and refuses when bae6-authz says no or cannot say.

| Example | Stack |
| --- | --- |
| [`fastapi`](fastapi/README.md) | Python SDK, FastAPI |
| [`express`](express/README.md) | TypeScript SDK, Express |
| [`databricks`](databricks/README.md) | Python SDK plus Unity Catalog (needs a real workspace) |

## Setup (fastapi and express)

Requires Docker, Node 22+, pnpm 10 and uv. From the repo root:

```sh
cp .env.example .env     # then replace the placeholder passwords
make up                  # postgres, openfga, api on :8080
export BAE6_API_URL=http://localhost:8080 BAE6_WORKLOAD_TOKEN=dev-check-token
export BAE6_APPLICATION=$(examples/seed.sh)
```

`seed.sh` registers an application in which the user behind `dev-alice-token` can read
`document:d1` and nothing else. The tokens are the dev-only fixtures in `deploy/fixtures`;
a real deployment uses real end-user tokens and a workload credential issued by bae6-authz.

Then run an example from its README. Stop the stack with `make down`.

## Smoke test

With the stack up (`make up`), `examples/smoke.sh` seeds an application, starts both
examples and checks four outcomes for each: allowed (200), denied (403), no token (401), unknown token (401). CI runs it in the
`examples` job. The Databricks example is not part of it.

## Tenant mode

Use an authz deployment pinned to a tenant model. Register `document:d1` in a
unit and grant the test principal its `reader` relation. In authn, configure
`node-protected-api` and `fastapi-protected-api` as audiences and add
`node-protected-api=bae6-authz,fastapi-protected-api=bae6-authz` to
`BAE6_AUTHN_TOKEN_TARGETS`. Give each service its corresponding
`token-client-<audience>` secret. To issue the initial bearer token, use your
authn session exchange client and request the audience of the example you are
calling.

Set `BAE6_AUTHN_URL`, `BAE6_API_URL`, and `BAE6_AUTHN_CLIENT_SECRET` in each
example's environment. Start the example from the repository root.

```sh
pnpm --filter '{./examples/authz/express}...' build
pnpm --filter @bae6/authz-example-express start:tenant
uv run --project examples/authz/fastapi uvicorn tenant:app --app-dir examples/authz/fastapi --port 8101
```

Call `GET /documents/d1` with `Authorization: Bearer <token>`. A successful
response contains the document ID and the request ID carried in the signed
token. A request without a bearer token returns 401. An unauthorized document
returns 403.
