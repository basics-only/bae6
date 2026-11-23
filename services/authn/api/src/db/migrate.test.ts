import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import pg from "pg";
import { migrate } from "./migrate.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
const name = `authn_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
let admin: pg.Client;
let db: pg.Client;

const prn = (n: number) => `prn_${String(n).padStart(32, "0")}`;
const xid = (n: number) => `xid_${String(n).padStart(32, "0")}`;

before(async () => {
  if (skip) return;
  admin = new pg.Client({ connectionString: url });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  const target = new URL(url as string);
  target.pathname = `/${name}`;
  db = new pg.Client({ connectionString: target.toString() });
  await db.connect();
  await migrate(db);
  await db.query(
    `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
     VALUES ('acme', 'entra', 'entra', 'https://login.example/acme', 'c', 'acme-entra'),
            ('globex', 'entra', 'entra', 'https://login.example/globex', 'c', 'globex-entra')`,
  );
  await db.query(
    `INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'acme', 'user'), ($2, 'globex', 'user')`,
    [prn(1), prn(2)],
  );
});

after(async () => {
  if (skip) return;
  await db?.end();
  await admin?.query(`DROP DATABASE IF EXISTS ${name}`);
  await admin?.end();
});

const link = (
  id: number,
  tenant: string,
  principal: number,
  tid: string | null,
) =>
  db.query(
    `INSERT INTO external_identities
       (id, tenant_id, principal_id, provider_connection_id, issuer, subject, external_tenant_id, last_verified_at)
     VALUES ($1, $2, $3, 'entra', 'https://login.example/acme', 'sub-1', $4, now())`,
    [xid(id), tenant, prn(principal), tid],
  );

test("re-running migrations applies nothing", { skip }, async () => {
  assert.deepEqual(await migrate(db), []);
});

test(
  "one provider account links to one principal, even with no provider tenant",
  { skip },
  async () => {
    await link(1, "acme", 1, null);
    await assert.rejects(link(2, "acme", 1, null), { code: "23505" });
    await link(3, "acme", 1, "tid-a");
    await assert.rejects(link(4, "acme", 1, "tid-a"), { code: "23505" });
  },
);

test(
  "an identity cannot link to another tenant's principal",
  { skip },
  async () => {
    await assert.rejects(link(5, "acme", 2, "tid-x"), { code: "23503" });
  },
);

test("an agent needs an owning application", { skip }, async () => {
  await assert.rejects(
    db.query(
      `INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'acme', 'agent')`,
      [prn(9)],
    ),
    { code: "23514" },
  );
});

test(
  "a signing key row never holds private key material",
  { skip },
  async () => {
    await assert.rejects(
      db.query(
        `INSERT INTO signing_keys (kid, alg, public_jwk, status)
       VALUES ('k1', 'ES256', '{"kty":"EC","d":"secret"}', 'active')`,
      ),
      { code: "23514" },
    );
  },
);

test("sessions cannot outlive 24 hours", { skip }, async () => {
  await assert.rejects(
    db.query(
      `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash, provider_connection_id, expires_at)
       VALUES ($1, 'acme', $2, $3, $3, 'entra', now() + interval '25 hours')`,
      [`ses_${"0".repeat(32)}`, prn(1), Buffer.alloc(32)],
    ),
    { code: "23514" },
  );
});

test(
  "a writer cannot stretch a session by backdating created_at",
  { skip },
  async () => {
    await assert.rejects(
      db.query(
        `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash, provider_connection_id, created_at, expires_at)
       VALUES ($1, 'acme', $2, $3, $3, 'entra', now() + interval '30 days', now() + interval '30 days 1 hour')`,
        [`ses_${"2".repeat(32)}`, prn(1), Buffer.alloc(32)],
      ),
      { code: "23514" },
    );
  },
);

test(
  "a session cannot use another tenant's provider connection",
  { skip },
  async () => {
    await db.query(
      `INSERT INTO provider_connections (tenant_id, id, kind, issuer, client_id, client_secret_ref)
     VALUES ('globex', 'okta', 'okta', 'https://okta.example/globex', 'c', 'globex-okta')`,
    );
    await assert.rejects(
      db.query(
        `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash, provider_connection_id, expires_at)
       VALUES ($1, 'acme', $2, $3, $3, 'okta', now() + interval '1 hour')`,
        [`ses_${"1".repeat(32)}`, prn(1), Buffer.alloc(32)],
      ),
      { code: "23503" },
    );
  },
);

test(
  "a signing key's JWK must carry its own kid and alg",
  { skip },
  async () => {
    await assert.rejects(
      db.query(
        `INSERT INTO signing_keys (kid, alg, public_jwk, status)
       VALUES ('k2', 'ES256', '{"kty":"EC","kid":"other","alg":"ES256"}', 'active')`,
      ),
      { code: "23514" },
    );
  },
);
