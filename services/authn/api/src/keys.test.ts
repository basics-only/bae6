import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { after, before, test } from "node:test";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import {
  activeSigner,
  KeyError,
  localSigner,
  registerKey,
  type Signer,
  syncKeys,
} from "./keys.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
let db: pg.Pool;
let close: () => Promise<void>;

const p256 = () =>
  localSigner(
    generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString(),
  );

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_keys",
  ));
});

after(async () => {
  if (!skip) await close();
});

test(
  "a fresh install activates the named key even when another key is listed first",
  { skip },
  async () => {
    const keyA = p256();
    const keyB = p256();
    const signers = new Map<string, Signer>([
      [keyB.kid, keyB],
      [keyA.kid, keyA],
    ]);
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyB.kid]: "next",
      [keyA.kid]: "active",
    });
    assert.equal((await activeSigner(db, signers)).kid, keyA.kid);
  },
);

test(
  "an install left with only a stale next key activates the configured key",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyB = p256();
    await registerKey(db, keyB);
    const signers = new Map<string, Signer>([
      [keyB.kid, keyB],
      [keyA.kid, keyA],
    ]);
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyB.kid]: "next",
      [keyA.kid]: "active",
    });
  },
);

test(
  "sync fails loudly when the configured key cannot become active",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyB = p256();
    const keyC = p256();
    const signers = new Map<string, Signer>([
      [keyA.kid, keyA],
      [keyB.kid, keyB],
      [keyC.kid, keyC],
    ]);
    await syncKeys(db, new Map([[keyA.kid, keyA]]), keyA.kid);
    await registerKey(db, keyB);
    await assert.rejects(syncKeys(db, signers, keyC.kid), KeyError);
    assert.equal((await activeSigner(db, signers)).kid, keyA.kid);
  },
);
