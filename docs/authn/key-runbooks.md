# authn signing-key runbooks

Statuses: `next` (published, not signing), `active` (signs), `retired` (still published for 360 s, then dropped), `revoked` (dropped at once, never restored). Replicas sync every 60 s.
`keys-cli` runs as `node dist/keys-cli.js <command> <kid>` with `BAE6_AUTHN_DATABASE_URL` set.

## Routine rotation

1. Add the new key to `BAE6_AUTHN_SIGNING_KEYS` on every replica, keeping the current active key and `BAE6_AUTHN_ACTIVE_SIGNING_KEY` unchanged. Roll out. The new key is registered as `next`.
2. Wait at least 360 s (`JWKS_MAX_AGE_SECONDS` + clock skew) so every verifier has cached a JWKS containing it.
3. Set `BAE6_AUTHN_ACTIVE_SIGNING_KEY` to the new key and roll out. The first replica to sync promotes it; the old key becomes `retired` and stays in the JWKS for 360 s.
4. Remove the old key from `BAE6_AUTHN_SIGNING_KEYS` after it has left the JWKS.

## Rollback to a retired key

1. Keep the current active key in `BAE6_AUTHN_SIGNING_KEYS`.
2. `keys-cli unretire <kid>` makes the retired key `next` again.
3. After 360 s, set `BAE6_AUTHN_ACTIVE_SIGNING_KEY` to it and roll out.

A revoked key cannot be unretired.

## Emergency rotation after a leak

1. Register a replacement as in step 1 of routine rotation, unless a `next` key already exists. Wait 360 s.
2. `keys-cli revoke <leaked-kid>`. Revoking the active key promotes the aged `next` key in the same transaction; the command refuses if there is none. The leaked key leaves the JWKS immediately.
3. Roll out `BAE6_AUTHN_ACTIVE_SIGNING_KEY` for the replacement and remove the leaked key from `BAE6_AUTHN_SIGNING_KEYS`.
4. Tokens signed by the leaked key stay valid at verifiers that cached the JWKS, for up to 300 s (`JWKS_MAX_AGE_SECONDS`), and a token lives at most 300 s (`TOKEN_TTL_SECONDS`). Assume forged tokens are accepted for up to 600 s after the revoke. Revoke sessions and delegations of affected principals if the leak window matters.

## KMS-backed signing

`kmsSigner(client)` in `keys.ts` takes a client with `publicKey()` (SPKI DER) and `sign(message)` (DER ECDSA over SHA-256 of the message) and returns an ES256 `Signer`. The key must be P-256. The `kid` matches what `localSigner` gives for the same key. The service does not yet construct KMS signers from configuration.
