import {
  createHash,
  createPrivateKey,
  createPublicKey,
  type JsonWebKey,
  type KeyObject,
  sign,
} from "node:crypto";
import type { Pool } from "pg";

export const TOKEN_TTL_SECONDS = 300;
export const CLOCK_SKEW_SECONDS = 60;
export const JWKS_MAX_AGE_SECONDS = 300;
export const MAX_PUBLISHED_KEYS = 10;

export type SigningAlg = "ES256" | "EdDSA";

export interface PublicJwk extends JsonWebKey {
  kid: string;
  alg: SigningAlg;
  use: "sig";
}

export interface Signer {
  readonly kid: string;
  readonly alg: SigningAlg;
  readonly publicJwk: PublicJwk;
  sign(input: Uint8Array): Promise<Uint8Array>;
}

export class KeyError extends Error {}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

function thumbprint(jwk: JsonWebKey): string {
  const members =
    jwk.kty === "EC"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return b64url(createHash("sha256").update(JSON.stringify(members)).digest());
}

function algFor(key: KeyObject): SigningAlg {
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === "ec" && details?.namedCurve === "prime256v1")
    return "ES256";
  if (key.asymmetricKeyType === "ed25519") return "EdDSA";
  throw new KeyError("signing keys must be P-256 or Ed25519");
}

export function localSigner(privateKeyPem: string): Signer {
  const privateKey = createPrivateKey(privateKeyPem);
  const alg = algFor(privateKey);
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  const kid = thumbprint(jwk);
  return {
    kid,
    alg,
    publicJwk: { ...jwk, kid, alg, use: "sig" },
    sign: async (input) =>
      alg === "ES256"
        ? sign("sha256", input, { key: privateKey, dsaEncoding: "ieee-p1363" })
        : sign(null, input, privateKey),
  };
}

export async function registerKey(db: Pool, signer: Signer): Promise<void> {
  if ("d" in signer.publicJwk) throw new KeyError("public JWK carries d");
  try {
    const { rows } = await db.query<{ status: string }>(
      `WITH ins AS (
         INSERT INTO signing_keys (kid, alg, public_jwk, status)
         VALUES ($1, $2, $3, 'next') ON CONFLICT (kid) DO NOTHING RETURNING status)
       SELECT status FROM ins
       UNION ALL SELECT status FROM signing_keys WHERE kid = $1 AND NOT EXISTS (SELECT 1 FROM ins)`,
      [signer.kid, signer.alg, signer.publicJwk],
    );
    if (rows[0]?.status !== "next")
      throw new KeyError(`key ${signer.kid} is already ${rows[0]?.status}`);
  } catch (err) {
    if ((err as { code?: string }).code === "23505")
      throw new KeyError("another next key is already published", {
        cause: err,
      });
    throw err;
  }
}

export async function promoteNextKey(
  db: Pool,
  signers: ReadonlyMap<string, Signer>,
): Promise<string> {
  const client = await db.connect();
  let broken: Error | undefined;
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ kid: string }>(
      `SELECT kid FROM signing_keys
        WHERE status = 'next' AND created_at <= now() - make_interval(secs => $1)
        FOR UPDATE`,
      [JWKS_MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS],
    );
    const next = rows[0];
    if (!next) throw new KeyError("no next key has been published long enough");
    if (!signers.has(next.kid))
      throw new KeyError(`no signer configured for next key ${next.kid}`);
    await client.query(
      "UPDATE signing_keys SET status = 'retired', retired_at = now() WHERE status = 'active'",
    );
    await client.query(
      "UPDATE signing_keys SET status = 'active' WHERE kid = $1",
      [next.kid],
    );
    await client.query("COMMIT");
    return next.kid;
  } catch (err) {
    await client.query("ROLLBACK").catch((rollbackErr: Error) => {
      broken = rollbackErr;
    });
    throw err;
  } finally {
    client.release(broken);
  }
}

export async function publishedKeys(db: Pool): Promise<PublicJwk[]> {
  const { rows } = await db.query<{ public_jwk: PublicJwk }>(
    `SELECT public_jwk FROM signing_keys
      WHERE status <> 'retired' OR retired_at > now() - make_interval(secs => $1)
      ORDER BY status = 'active' DESC, created_at DESC LIMIT $2`,
    [TOKEN_TTL_SECONDS + CLOCK_SKEW_SECONDS, MAX_PUBLISHED_KEYS],
  );
  return rows.map((r) => r.public_jwk);
}

export async function activeSigner(
  db: Pool,
  signers: ReadonlyMap<string, Signer>,
): Promise<Signer> {
  const { rows } = await db.query<{ kid: string }>(
    "SELECT kid FROM signing_keys WHERE status = 'active'",
  );
  const kid = rows[0]?.kid;
  if (!kid) throw new KeyError("no active signing key");
  const signer = signers.get(kid);
  if (!signer) throw new KeyError(`no signer configured for active key ${kid}`);
  return signer;
}
