import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
  verify,
} from "node:crypto";
import { test } from "node:test";
import { KeyError, type KmsClient, kmsSigner, localSigner } from "./keys.js";

const pair = (namedCurve: string) => generateKeyPairSync("ec", { namedCurve });

const fakeKms = (
  privateKey: KeyObject,
  publicKey: KeyObject,
  signature: (message: Uint8Array) => Uint8Array = (message) =>
    sign("sha256", message, { key: privateKey, dsaEncoding: "der" }),
): KmsClient => ({
  publicKey: async () => publicKey.export({ type: "spki", format: "der" }),
  sign: async (message) => signature(message),
});

test("a KMS signer produces ES256 signatures that verify against its published key", async () => {
  const { privateKey, publicKey } = pair("P-256");
  const signer = await kmsSigner(fakeKms(privateKey, publicKey));
  const message = Buffer.from("header.payload");
  for (let i = 0; i < 50; i++) {
    const signature = await signer.sign(message);
    assert.equal(signature.length, 64);
    assert.ok(
      verify(
        "sha256",
        message,
        {
          key: createPublicKey({ key: signer.publicJwk, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        },
        signature,
      ),
    );
  }
});

test("a KMS signer has the same kid as a local signer over the same key", async () => {
  const { privateKey, publicKey } = pair("P-256");
  const local = localSigner(
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  );
  assert.equal(
    (await kmsSigner(fakeKms(privateKey, publicKey))).kid,
    local.kid,
  );
});

test("a KMS signer refuses keys that are not P-256", async () => {
  const { privateKey, publicKey } = pair("P-384");
  await assert.rejects(kmsSigner(fakeKms(privateKey, publicKey)), KeyError);
});

test("a KMS signer refuses malformed signatures from KMS", async () => {
  const { privateKey, publicKey } = pair("P-256");
  const good = sign("sha256", Buffer.from("m"), {
    key: privateKey,
    dsaEncoding: "der",
  });
  for (const bad of [
    new Uint8Array(),
    good.subarray(0, good.length - 1),
    Buffer.concat([good, Buffer.from([0])]),
    Buffer.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]),
    Buffer.from([0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01]),
  ]) {
    const signer = await kmsSigner(fakeKms(privateKey, publicKey, () => bad));
    await assert.rejects(signer.sign(Buffer.from("m")), KeyError);
  }
});
