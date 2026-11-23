# 0021 — Principals

Status: proposed
Date: 2026-11-22

## Context
Authorization, audit and usage need one stable ID per actor that survives repeated logins, provider changes and email changes. The actor may be a user, group, service, application or agent.

## Decision
- **Principal:** `id`, `tenant_id`, `type`, `status`, `created_at`, `updated_at`.
  - `type` is one of `user`, `group`, `service`, `application`, `agent`.
  - IDs are opaque and never reused.
- **ExternalIdentity:** `principal_id`, `provider_connection_id`, `issuer`, `subject`, `external_tenant_id`, `external_object_id`, `last_verified_at`.
  - It is unique on `(provider_connection_id, issuer, subject)`, plus `external_tenant_id` for multitenant issuers such as Entra.
  - Email and display name never identify anyone.
- **First login** creates a principal only if the provider connection allows just-in-time creation. Otherwise the login is rejected.
- **Linking.** A second external identity joins an existing principal only by admin action or a verified proof of ownership, and every link is audited. Matching emails never link identities.
- **Agents** are principals of their own, owned by an application. An agent never inherits its owner's or its service account's permissions.
- **Groups** come from IdP claims, provider sync, or both, mapped per provider connection. Mapped groups become OpenFGA subjects. Membership staleness is at most the token TTL plus the sync interval.
- **Lifecycle.** A `disabled` principal gets no new exchange or session at once. Existing bae6 tokens expire within 5 minutes. Deprovisioning removes its tuples through the reconciler.

## Consequences
- Every downstream record joins on `principal_id`, never on email.
- The principal registry is new state that needs backup and migration ownership in authn.
- Entra group overage needs Microsoft Graph credentials per connection.
