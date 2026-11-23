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
  unretireKey,
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
  "sync fails loudly when another configured key holds the next slot",
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

test(
  "a next key nobody configures any more stops blocking the next one",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyB = p256();
    const keyC = p256();
    await syncKeys(db, new Map([[keyA.kid, keyA]]), keyA.kid);
    await registerKey(db, keyB);
    const signers = new Map<string, Signer>([
      [keyA.kid, keyA],
      [keyC.kid, keyC],
    ]);
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
      [keyC.kid]: "unpublished",
    });
    await db.query(
      "UPDATE signing_keys SET created_at = now() - interval '1 hour' WHERE kid = $1",
      [keyB.kid],
    );
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
      [keyC.kid]: "next",
    });
  },
);

test(
  "a replica on older config leaves a recently published next key alone",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyC = p256();
    const newer = new Map<string, Signer>([
      [keyA.kid, keyA],
      [keyC.kid, keyC],
    ]);
    await syncKeys(db, newer, keyA.kid);
    await syncKeys(db, new Map([[keyA.kid, keyA]]), keyA.kid);
    assert.deepEqual(await syncKeys(db, newer, keyA.kid), {
      [keyA.kid]: "active",
      [keyC.kid]: "next",
    });
  },
);

test(
  "a configured next key is kept while the active key stays active",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyB = p256();
    const signers = new Map<string, Signer>([
      [keyA.kid, keyA],
      [keyB.kid, keyB],
    ]);
    await syncKeys(db, signers, keyA.kid);
    assert.deepEqual(await syncKeys(db, signers, keyA.kid), {
      [keyA.kid]: "active",
      [keyB.kid]: "next",
    });
  },
);

test(
  "a retired key comes back only by an explicit unretire, then the usual promotion",
  { skip },
  async () => {
    await db.query("TRUNCATE signing_keys");
    const keyA = p256();
    const keyB = p256();
    const both = new Map<string, Signer>([
      [keyA.kid, keyA],
      [keyB.kid, keyB],
    ]);
    const age = () =>
      db.query(
        "UPDATE signing_keys SET created_at = now() - interval '1 hour'",
      );
    await syncKeys(db, both, keyA.kid);
    await age();
    await syncKeys(db, both, keyB.kid);

    await assert.rejects(syncKeys(db, both, keyA.kid), /unretire/);
    assert.equal((await activeSigner(db, both)).kid, keyB.kid);

    await assert.rejects(unretireKey(db, keyB.kid), KeyError);
    const keyC = p256();
    await registerKey(db, keyC);
    await assert.rejects(unretireKey(db, keyA.kid), /another next key/);
    await db.query("DELETE FROM signing_keys WHERE kid = $1", [keyC.kid]);
    await unretireKey(db, keyA.kid);
    assert.deepEqual(await syncKeys(db, both, keyA.kid), {
      [keyA.kid]: "next",
      [keyB.kid]: "active",
    });
    await age();
    assert.deepEqual(await syncKeys(db, both, keyA.kid), {
      [keyA.kid]: "active",
      [keyB.kid]: "retired",
    });
  },
);
