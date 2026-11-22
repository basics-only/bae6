# Consuming contracts

Contracts live in `contracts/` and are referenced in place.

- Service OpenAPI documents `$ref` `../../../contracts/openapi/common.yaml` and
  `../../../contracts/schemas/*.json` by relative path.
- SDK and service tests load `contracts/schemas` and `contracts/fixtures/transport` directly.

A contract change and every consumer it affects land in one PR.

## Proposing a change
1. Change the schema in `contracts/` with fixtures for the new behavior, and an ADR if
   cross-product behavior changes.
2. Run `oasdiff breaking` against the previous `contracts-v*` tag. A breaking change
   needs a new major.
3. Consumers upgrade within the compatibility window (ADR-0001).
