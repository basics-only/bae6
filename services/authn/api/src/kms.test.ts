import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { test } from "node:test";
import { cloudKmsSigner, metadataAccessToken } from "./kms.js";

test("Cloud KMS signs the digest and yields a verifiable ES256 signature", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const version =
    "projects/test/locations/global/keyRings/authn/cryptoKeys/token/cryptoKeyVersions/1";
  const input = Buffer.from("token signing input");
  let wrongMessage = false;
  const request: typeof fetch = async (url, init) => {
    assert.equal(
      new Headers(init?.headers).get("authorization"),
      "Bearer test-token",
    );
    if (String(url).endsWith("/publicKey")) {
      return Response.json({
        name: version,
        algorithm: "EC_SIGN_P256_SHA256",
        pem: publicKey.export({ type: "spki", format: "pem" }),
      });
    }
    assert.equal(
      url,
      `https://cloudkms.googleapis.com/v1/${version}:asymmetricSign`,
    );
    assert.deepEqual(JSON.parse(String(init?.body)), {
      digest: { sha256: createHash("sha256").update(input).digest("base64") },
    });
    return Response.json({
      name: version,
      signature: sign(
        "sha256",
        wrongMessage ? Buffer.from("different input") : input,
        privateKey,
      ).toString("base64"),
    });
  };
  const signer = await cloudKmsSigner(
    version,
    async () => "test-token",
    request,
  );
  const signature = await signer.sign(input);
  assert.equal(signer.publicJwk.alg, "ES256");
  assert.equal(signature.length, 64);
  assert.ok(
    verify(
      "sha256",
      input,
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    ),
  );
  wrongMessage = true;
  await assert.rejects(signer.sign(input), /Cloud KMS signing failed/);
});

test("concurrent signing requests share the cached metadata credential", async () => {
  let calls = 0;
  const getToken = metadataAccessToken(async (_url, init) => {
    assert.equal(new Headers(init?.headers).get("metadata-flavor"), "Google");
    calls++;
    return Response.json({ access_token: "test-token", expires_in: 3600 });
  });
  assert.deepEqual(await Promise.all([getToken(), getToken()]), [
    "test-token",
    "test-token",
  ]);
  assert.equal(await getToken(), "test-token");
  assert.equal(calls, 1);
});
