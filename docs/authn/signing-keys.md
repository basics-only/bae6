# Authn signing keys

`BAE6_AUTHN_SIGNING_KEYS` lists key references. Use a PEM filename in
`BAE6_AUTHN_KEYS_DIR` or a Google Cloud KMS reference such as
`gcp-kms:projects/example/locations/us-central1/keyRings/authn/cryptoKeys/token/cryptoKeyVersions/1`.
Select the signing reference with `BAE6_AUTHN_ACTIVE_SIGNING_KEY`. KMS uses
`EC_SIGN_P256_SHA256` and the deployment's Google metadata service identity.
Grant that identity `cloudkms.cryptoKeyVersions.viewPublicKey` and
`cloudkms.cryptoKeyVersions.useToSign` on the configured keys.

## Routine rotation

1. Add the replacement to the list on every authn replica. Keep the current key
   selected. Confirm the replacement's `kid` appears in `/.well-known/jwks.json` on the issuer host.
2. Wait 360 seconds after publication. Select the replacement and roll the
   configuration out. Confirm newly issued tokens carry the replacement `kid`.
   Promotion retires the previous key and publishes it for another 360 seconds.
3. Remove the previous reference from the replicas after promotion is confirmed.

## Rollback

Add the previous key reference to every replica and keep the current key
selected. With `BAE6_AUTHN_DATABASE_URL` set, run
`node dist/keys-cli.js unretire <previous-kid>`. Confirm publication, wait 360
seconds, then select the previous key as in routine rotation.

## Suspected key compromise

Stage a replacement on every replica and confirm it has been published for at
least 360 seconds. Run `node dist/keys-cli.js revoke <compromised-kid>`.
Revocation of an active key promotes the staged replacement in the same
transaction. With no eligible replacement, the command fails. If compromise
requires immediate containment in that case, disable signing and block the
compromised `kid` at verifiers until replacement is possible.

Confirm the compromised key is absent from the issuer's JWKS and roll out the
replacement as the selected reference. Purge cached JWKS at verifiers where
possible. Authn advertises a 300-second cache lifetime. Verify the actual
cache configuration at proxies and clients during incident response. Remove
the compromised key reference from all replicas and disable the key in KMS if
applicable.
