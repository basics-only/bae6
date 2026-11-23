# 0019 — bae6-authn and internal tokens

Status: proposed
Date: 2026-11-22

## Context
Enterprises use PingFederate, Microsoft Entra ID or Okta, each with its own claim shapes, lifetimes and group handling. Services need a stable principal, a tenant and org path, and an actor and delegation, none of which IdP tokens carry. An IdP access token is issued for one API: RFC 9700 says to restrict audience, preferably to a single resource server. Supersedes ADR-0003's rule that bae6 never mints user tokens.

## Decision
- **Only `bae6-authn` talks to identity providers.**
  - It runs the OIDC flows: Authorization Code with PKCE, and client credentials.
  - It verifies IdP tokens: issuer allowlist, audience, signature, `exp` and `nbf` with at most 60 s skew, asymmetric algorithms only, and keys only from the configured JWKS.
  - It resolves the result to a principal (ADR-0021).
- **Token exchange.** A client presents a verified IdP token, a bae6 session, or a workload credential to `POST /auth/token` (RFC 8693). authn returns a bae6 token with these properties:
  - a signed JWT, lasting at most 5 minutes
  - one `aud`: the downstream service
  - claims `sub` (principal ID), `tenant_id`, `org_path`, `act` (actor), `delegation_id`, `session_id` and `txn` (request ID)
  - claim names follow draft-ietf-oauth-transaction-tokens where they fit
- **Services verify locally** against authn's published JWKS, using the shared middleware. authn is not called per request.
- **A service calling another service** exchanges again for the new audience. The actor and delegation carry over, and scope can only narrow.
- **No passthrough.**
  - A bae6 token is never sent outside bae6 services.
  - Systems that enforce their own ACLs as the user (Graph, SharePoint, Databricks) get a token from the provider for that audience, through on-behalf-of or token exchange at the provider.
- **Signing keys** live in a KMS-compatible store. Rotation publishes the new key before signing with it, and keeps the old key until its last token expires.
- **Rejected: services trusting IdP tokens directly.** Every service would need all three provider adapters. Tokens would need broad audiences or per-hop exchange anyway. Revocation would wait on IdP lifetimes, often about an hour.
- **Rejected: per-request introspection.** It puts authn on every call's hot path.

## Consequences
- Services trust one issuer. Provider quirks live in one place.
- Disabling a principal or revoking a delegation takes effect within 5 minutes, without a per-request lookup.
- authn's signing key becomes the suite's most valuable secret.
- authn must be highly available for new sessions and refreshes. Issued tokens survive an outage for at most 5 minutes.
- The draft could change. Our claim names may then diverge from the eventual RFC.
