import { createHash, createPublicKey, verify } from "node:crypto";
import { KeyError, type Signer, thumbprint } from "./keys.js";

const VERSION =
  /^projects\/[a-z0-9-]{1,63}\/locations\/[a-z0-9-]{1,63}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/[1-9][0-9]{0,18}$/;
const METADATA_TOKEN =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

async function json(
  request: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<Record<string, unknown>> {
  const response = await request(url, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(3000),
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new KeyError("Cloud KMS dependency returned an error");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 8192) {
      await reader.cancel();
      throw new KeyError("Cloud KMS response is too large");
    }
    chunks.push(value);
  }
  const payload: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new KeyError("Invalid Cloud KMS response");
  return payload as Record<string, unknown>;
}

export function metadataAccessToken(request: typeof fetch = fetch) {
  let current: { value: string; expires: number } | undefined;
  let pending: Promise<string> | undefined;
  return async () => {
    if (current && current.expires > Date.now()) return current.value;
    pending ??= (async () => {
      const started = Date.now();
      const { access_token: value, expires_in: ttl } = await json(
        request,
        METADATA_TOKEN,
        { headers: { "Metadata-Flavor": "Google" } },
      );
      if (
        typeof value !== "string" ||
        !/^[A-Za-z0-9._~+/-]+=*$/.test(value) ||
        typeof ttl !== "number" ||
        !Number.isSafeInteger(ttl) ||
        ttl < 1
      )
        throw new KeyError("Invalid metadata access token");
      current = {
        value,
        expires: started + Math.max(0, Math.min(ttl, 3600) - 60) * 1000,
      };
      return value;
    })().finally(() => {
      pending = undefined;
    });
    return pending;
  };
}

export async function cloudKmsSigner(
  version: string,
  accessToken: () => Promise<string>,
  request: typeof fetch = fetch,
): Promise<Signer> {
  if (!VERSION.test(version))
    throw new KeyError("Invalid Cloud KMS key version");
  const url = `https://cloudkms.googleapis.com/v1/${version}`;
  const authorization = async () => `Bearer ${await accessToken()}`;
  const { name, pem, algorithm } = await json(request, `${url}/publicKey`, {
    headers: { authorization: await authorization() },
  });
  if (
    name !== version ||
    algorithm !== "EC_SIGN_P256_SHA256" ||
    typeof pem !== "string"
  )
    throw new KeyError("Expected the configured Cloud KMS P-256 public key");
  const key = createPublicKey(pem);
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "EC" || jwk.crv !== "P-256")
    throw new KeyError("Expected a P-256 public key");
  const kid = thumbprint(jwk);

  return {
    kid,
    alg: "ES256",
    publicJwk: { ...jwk, kid, alg: "ES256", use: "sig" },
    async sign(input) {
      try {
        const digest = createHash("sha256").update(input).digest("base64");
        const result = await json(request, `${url}:asymmetricSign`, {
          method: "POST",
          headers: {
            authorization: await authorization(),
            "content-type": "application/json",
          },
          body: JSON.stringify({ digest: { sha256: digest } }),
        });
        if (result.name !== version || typeof result.signature !== "string")
          throw new KeyError("Invalid Cloud KMS signature response");
        const der = Buffer.from(result.signature, "base64");
        if (der.length > 72 || !verify("sha256", input, key, der))
          throw new KeyError("Cloud KMS signature verification failed");
        const rLength = der[3] as number;
        const r = der.subarray(4, 4 + rLength);
        const s = der.subarray(6 + rLength);
        const raw = Buffer.alloc(64);
        r.subarray(-32).copy(raw, 32 - Math.min(r.length, 32));
        s.subarray(-32).copy(raw, 64 - Math.min(s.length, 32));
        return raw;
      } catch (err) {
        throw new KeyError("Cloud KMS signing failed", { cause: err });
      }
    },
  };
}
