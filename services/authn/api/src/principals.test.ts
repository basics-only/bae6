import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type pg from "pg";
import { migratedTestDatabase } from "./db/test-database.js";
import {
  type ConnectionPolicy,
  linkExternalIdentity,
  loadConnection,
  PrincipalError,
  resolvePrincipal,
  setPrincipalOrgPath,
  setPrincipalStatus,
} from "./principals.js";

const url = process.env.BAE6_DATABASE_URL;
const skip = url ? false : "BAE6_DATABASE_URL not set";
let db: pg.Pool;
let close: () => Promise<void>;

const TID = "11111111-1111-4111-8111-111111111111";
const GLOBEX_TID = "22222222-2222-4222-8222-222222222222";
const ENTRA_ISS = `https://login.example/${TID}/v2.0`;
const GLOBEX_ISS = `https://login.example/${GLOBEX_TID}/v2.0`;
const ENGINEERING = `prn_${"e".repeat(32)}`;
const RETIRED_GROUP = `prn_${"f".repeat(32)}`;
const GLOBEX_GROUP = `prn_${"9".repeat(32)}`;

before(async () => {
  if (skip) return;
  ({ pool: db, close } = await migratedTestDatabase(
    url as string,
    "authn_prn",
  ));
  await db.query(
    `INSERT INTO provider_connections
       (tenant_id, id, kind, issuer, client_id, client_secret_ref, jit_provisioning, group_claim, status)
     VALUES ('acme', 'entra', 'entra', $1, 'c', 's', true, 'groups', 'active'),
            ('acme', 'ping', 'pingfederate', 'https://ping.example/acme', 'c', 's', false, 'memberOf', 'active'),
            ('acme', 'okta', 'okta', 'https://okta.example/acme', 'c', 's', true, null, 'disabled'),
            ('globex', 'entra', 'entra', $2, 'c', 's', true, 'groups', 'active'),
            ('globex', 'gping', 'pingfederate', 'https://ping.example/globex', 'c', 's', false, null, 'active')`,
    [ENTRA_ISS, GLOBEX_ISS],
  );
  await db.query(
    `INSERT INTO principals (id, tenant_id, type, status)
     VALUES ($1, 'acme', 'group', 'active'), ($2, 'acme', 'group', 'disabled'), ($3, 'globex', 'group', 'active')`,
    [ENGINEERING, RETIRED_GROUP, GLOBEX_GROUP],
  );
  await db.query(
    `INSERT INTO group_mappings (tenant_id, provider_connection_id, external_group, group_principal_id)
     VALUES ('acme', 'entra', 'g-eng', $1), ('acme', 'entra', 'g-retired', $2), ('globex', 'entra', 'g-eng', $3)`,
    [ENGINEERING, RETIRED_GROUP, GLOBEX_GROUP],
  );
});

after(async () => {
  if (!skip) await close?.();
});

const connection = async (tenant: string, id: string) =>
  (await loadConnection(db, tenant, id)) as ConnectionPolicy;

const entraLogin = (sub: string, claims: Record<string, unknown> = {}) => ({
  issuer: ENTRA_ISS,
  subject: sub,
  claims: { tid: TID, oid: `oid-${sub}`, ...claims },
});

const rejectsWith = (p: Promise<unknown>, code: string) =>
  assert.rejects(
    p,
    (e: unknown) => e instanceof PrincipalError && e.code === code,
  );

const events = async (principalId: string) =>
  (
    await db.query<{ type: string; actor: string }>(
      "SELECT type, actor FROM principal_events WHERE principal_id = $1 ORDER BY id",
      [principalId],
    )
  ).rows;

test(
  "first login creates a user principal; later logins return the same one",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const first = await resolvePrincipal(db, entra, entraLogin("alice"));
    assert.equal(first.created, true);
    assert.match(first.principalId, /^prn_[0-9a-f]{32}$/);
    const again = await resolvePrincipal(db, entra, entraLogin("alice"));
    assert.deepEqual({ ...again, created: true }, first);
    assert.equal(again.created, false);
    assert.deepEqual(await events(first.principalId), [
      { type: "created", actor: "jit:entra" },
    ]);
    const { rows } = await db.query(
      "SELECT external_tenant_id, external_object_id FROM external_identities WHERE principal_id = $1",
      [first.principalId],
    );
    assert.deepEqual(rows, [
      { external_tenant_id: TID, external_object_id: "oid-alice" },
    ]);
  },
);

test(
  "an identity linked to a non-user principal is refused, not provisioned",
  { skip },
  async () => {
    const service = `prn_${"5".repeat(32)}`;
    await db.query(
      "INSERT INTO principals (id, tenant_id, type) VALUES ($1, 'acme', 'service')",
      [service],
    );
    await db.query(
      `INSERT INTO external_identities
         (id, tenant_id, principal_id, provider_connection_id, issuer, subject, external_tenant_id, external_object_id, last_verified_at)
       VALUES ($1, 'acme', $2, 'entra', $3, 'svc-1', $4, 'oid-svc-1', now() - interval '1 day')`,
      [`xid_${"5".repeat(32)}`, service, ENTRA_ISS, TID],
    );
    const snapshot = async () =>
      (
        await db.query(
          `SELECT (SELECT count(*)::int FROM principals) AS principals,
                  (SELECT count(*)::int FROM external_identities WHERE subject = 'svc-1') AS links,
                  (SELECT last_verified_at FROM external_identities WHERE subject = 'svc-1') AS verified`,
        )
      ).rows[0];
    const before = await snapshot();
    await rejectsWith(
      resolvePrincipal(
        db,
        await connection("acme", "entra"),
        entraLogin("svc-1"),
      ),
      "principal_not_user",
    );
    assert.deepEqual(await snapshot(), before);
  },
);

test(
  "without just-in-time provisioning an unknown identity is refused and nothing is created",
  { skip },
  async () => {
    const before = (await db.query("SELECT count(*)::int AS n FROM principals"))
      .rows[0].n;
    await rejectsWith(
      resolvePrincipal(db, await connection("acme", "ping"), {
        issuer: "https://ping.example/acme",
        subject: "dave",
        claims: {},
      }),
      "unknown_identity",
    );
    assert.equal(
      (await db.query("SELECT count(*)::int AS n FROM principals")).rows[0].n,
      before,
    );
  },
);

test(
  "a matching email never links two provider accounts",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const a = await resolvePrincipal(
      db,
      entra,
      entraLogin("e-1", { email: "same@acme.example" }),
    );
    const b = await resolvePrincipal(
      db,
      entra,
      entraLogin("e-2", { email: "same@acme.example" }),
    );
    assert.notEqual(a.principalId, b.principalId);
  },
);

test(
  "the same subject from another Entra tenant is a different identity",
  { skip },
  async () => {
    const home = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("shared-sub"),
    );
    const guest = await resolvePrincipal(
      db,
      await connection("globex", "entra"),
      {
        issuer: GLOBEX_ISS,
        subject: "shared-sub",
        claims: { tid: GLOBEX_TID, oid: "o" },
      },
    );
    assert.notEqual(home.principalId, guest.principalId);
  },
);

test(
  "a token whose issuer or tid does not match the connection is refused",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    await rejectsWith(
      resolvePrincipal(db, entra, {
        ...entraLogin("wrong-iss"),
        issuer: GLOBEX_ISS,
      }),
      "invalid_identity",
    );
    await rejectsWith(
      resolvePrincipal(db, entra, entraLogin("wrong-tid", { tid: GLOBEX_TID })),
      "invalid_identity",
    );
  },
);

test(
  "a group claim named like an Object member reads only the token's own claims",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    for (const groupClaim of ["constructor", "__proto__"]) {
      const resolved = await resolvePrincipal(
        db,
        { ...entra, groupClaim },
        entraLogin("proto-claim", { _claim_names: {} }),
      );
      assert.deepEqual(resolved.groupPrincipalIds, []);
    }
  },
);

test("Entra logins without tid and oid are refused", { skip }, async () => {
  await rejectsWith(
    resolvePrincipal(db, await connection("acme", "entra"), {
      issuer: ENTRA_ISS,
      subject: "no-tid",
      claims: {},
    }),
    "invalid_identity",
  );
});

test(
  "concurrent first logins for one identity create exactly one principal",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        resolvePrincipal(db, entra, entraLogin("racer")),
      ),
    );
    assert.equal(new Set(results.map((r) => r.principalId)).size, 1);
    assert.equal(results.filter((r) => r.created).length, 1);
  },
);

test(
  "only mapped, active groups of the connection's own tenant come back",
  { skip },
  async () => {
    const resolved = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("grouped", {
        groups: ["g-eng", "g-retired", "g-unmapped", "g-eng"],
      }),
    );
    assert.deepEqual(resolved.groupPrincipalIds, [ENGINEERING]);
  },
);

test(
  "group overage uses the groups the adapter fetched, and is refused without them",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const overage = entraLogin("overage", {
      _claim_names: { groups: "src1" },
      groups: ["g-retired"],
    });
    await rejectsWith(
      resolvePrincipal(db, entra, overage),
      "group_overage_unresolved",
    );
    const resolved = await resolvePrincipal(db, entra, overage, ["g-eng"]);
    assert.deepEqual(resolved.groupPrincipalIds, [ENGINEERING]);
    await rejectsWith(
      resolvePrincipal(db, entra, overage, [1]),
      "invalid_groups",
    );
    const many = Array.from({ length: 5000 }, (_, i) => `g-${i}`);
    assert.deepEqual(
      (await resolvePrincipal(db, entra, overage, [...many, "g-eng"]))
        .groupPrincipalIds,
      [ENGINEERING],
    );
    await rejectsWith(
      resolvePrincipal(
        db,
        entra,
        overage,
        Array.from({ length: 20_001 }, (_, i) => `g-${i}`),
      ),
      "invalid_groups",
    );
    const inToken = await resolvePrincipal(
      db,
      entra,
      entraLogin("overage", { groups: [] }),
      ["g-eng"],
    );
    assert.deepEqual(inToken.groupPrincipalIds, []);
  },
);

test("malformed or oversized group claims are refused", { skip }, async () => {
  const entra = await connection("acme", "entra");
  for (const groups of [
    "g-eng",
    [1],
    [""],
    Array.from({ length: 1001 }, (_, i) => `g${i}`),
  ]) {
    await rejectsWith(
      resolvePrincipal(db, entra, entraLogin("bad-groups", { groups })),
      "invalid_groups",
    );
  }
});

test("a disabled connection signs no one in", { skip }, async () => {
  await rejectsWith(
    resolvePrincipal(db, await connection("acme", "okta"), {
      issuer: "https://okta.example/acme",
      subject: "carol",
      claims: {},
    }),
    "connection_unavailable",
  );
});

test(
  "disabling revokes sessions and blocks login; deprovisioning is final",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const { principalId } = await resolvePrincipal(
      db,
      entra,
      entraLogin("leaver"),
    );
    await db.query(
      `INSERT INTO sessions (id, tenant_id, principal_id, secret_hash, csrf_hash, provider_connection_id, expires_at)
     VALUES ($1, 'acme', $2, $3, $3, 'entra', now() + interval '1 hour')`,
      [`ses_${"3".repeat(32)}`, principalId, Buffer.alloc(32)],
    );
    const change = { tenantId: "acme", principalId, actor: "prn_admin" };
    await setPrincipalStatus(db, { ...change, status: "disabled" });
    const { rows } = await db.query(
      "SELECT revoked_at FROM sessions WHERE principal_id = $1",
      [principalId],
    );
    assert.ok(rows[0].revoked_at);
    await rejectsWith(
      resolvePrincipal(db, entra, entraLogin("leaver")),
      "principal_inactive",
    );

    await setPrincipalStatus(db, { ...change, status: "active" });
    assert.equal(
      (await resolvePrincipal(db, entra, entraLogin("leaver"))).principalId,
      principalId,
    );

    await setPrincipalStatus(db, { ...change, status: "deprovisioned" });
    await rejectsWith(
      resolvePrincipal(db, entra, entraLogin("leaver")),
      "principal_inactive",
    );
    await rejectsWith(
      setPrincipalStatus(db, { ...change, status: "active" }),
      "invalid_transition",
    );
    assert.deepEqual(
      (await events(principalId)).map((e) => e.type),
      ["created", "disabled", "enabled", "deprovisioned"],
    );
  },
);

test(
  "a status change cannot reach another tenant's principal",
  { skip },
  async () => {
    const { principalId } = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("tenant-bound"),
    );
    await rejectsWith(
      setPrincipalStatus(db, {
        tenantId: "globex",
        principalId,
        status: "disabled",
        actor: "prn_admin",
      }),
      "unknown_principal",
    );
  },
);

test(
  "linking adds an audited identity, and an identity links to one principal only",
  { skip },
  async () => {
    const { principalId } = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("linker"),
    );
    const link = {
      tenantId: "acme",
      principalId,
      connectionId: "ping",
      subject: "linker-ping",
      actor: "prn_admin",
      proof: "admin" as const,
    };
    await linkExternalIdentity(db, link);
    const ping = await connection("acme", "ping");
    const viaPing = await resolvePrincipal(db, ping, {
      issuer: ping.issuer,
      subject: link.subject,
      claims: {},
    });
    assert.equal(viaPing.principalId, principalId);
    assert.deepEqual((await events(principalId)).at(-1), {
      type: "linked",
      actor: "prn_admin",
    });

    const { principalId: other } = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("thief"),
    );
    await rejectsWith(
      linkExternalIdentity(db, { ...link, principalId: other }),
      "identity_already_linked",
    );
  },
);

test(
  "linking refuses unsafe targets and incomplete identities",
  { skip },
  async () => {
    const { principalId } = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("cross-link"),
    );
    const base = {
      tenantId: "acme",
      principalId,
      connectionId: "ping",
      subject: "x",
      actor: "prn_admin",
      proof: "admin" as const,
    };
    const cases: [Partial<typeof base> & Record<string, unknown>, string][] = [
      [{ connectionId: "gping" }, "unknown_connection"],
      [{ connectionId: "okta" }, "connection_unavailable"],
      [{ connectionId: "entra" }, "invalid_identity"],
      [{ externalTenantId: TID }, "invalid_identity"],
      [{ principalId: ENGINEERING }, "principal_not_user"],
      [{ actor: "" }, "invalid_request"],
    ];
    for (const [override, code] of cases)
      await rejectsWith(
        linkExternalIdentity(db, { ...base, ...override }),
        code,
      );
  },
);

test("the lifecycle log cannot be edited or deleted", { skip }, async () => {
  await assert.rejects(
    db.query("UPDATE principal_events SET actor = 'forged'"),
    /append-only/,
  );
  await assert.rejects(db.query("DELETE FROM principal_events"), /append-only/);
});

test(
  "a group mapping can only point at a group principal",
  { skip },
  async () => {
    const { principalId } = await resolvePrincipal(
      db,
      await connection("acme", "entra"),
      entraLogin("not-a-group"),
    );
    await assert.rejects(
      db.query(
        `INSERT INTO group_mappings (tenant_id, provider_connection_id, external_group, group_principal_id)
       VALUES ('acme', 'entra', 'g-user', $1)`,
        [principalId],
      ),
      { code: "23503" },
    );
  },
);

test(
  "placing a principal in an org unit records the move; paths outside the tenant or tree are refused",
  { skip },
  async () => {
    const entra = await connection("acme", "entra");
    const { principalId } = await resolvePrincipal(
      db,
      entra,
      entraLogin("mover"),
    );
    const place = (orgPath: string[], id = principalId) =>
      setPrincipalOrgPath(db, {
        tenantId: "acme",
        principalId: id,
        principalType: "user",
        orgPath,
        actor: "authz",
      });
    const orgPath = async () =>
      (
        await db.query("SELECT org_path FROM principals WHERE id = $1", [
          principalId,
        ])
      ).rows[0].org_path;
    assert.deepEqual(await orgPath(), ["acme"]);
    await place(["acme", "finance", "ap"]);
    await place(["acme", "finance", "ap"]);
    assert.deepEqual(await orgPath(), ["acme", "finance", "ap"]);
    const { rows } = await db.query(
      "SELECT detail FROM principal_events WHERE principal_id = $1 AND type = 'placed'",
      [principalId],
    );
    assert.deepEqual(
      rows.map((r) => r.detail),
      [{ from: ["acme"], to: ["acme", "finance", "ap"] }],
    );
    for (const bad of [
      [],
      ["globex", "finance"],
      ["finance"],
      ["acme", "Finance"],
      ["acme", "a,b"],
      ["acme", ""],
      ["acme", ...Array.from({ length: 32 }, (_, i) => `u${i}`)],
    ])
      await rejectsWith(place(bad), "invalid_request");
    await rejectsWith(
      place(["acme", "x"], `prn_${"0".repeat(32)}`),
      "unknown_principal",
    );
    await rejectsWith(
      setPrincipalOrgPath(db, {
        tenantId: "globex",
        principalId,
        principalType: "user",
        orgPath: ["globex"],
        actor: "authz",
      }),
      "unknown_principal",
    );
    assert.deepEqual(await orgPath(), ["acme", "finance", "ap"]);
    await setPrincipalStatus(db, {
      tenantId: "acme",
      principalId,
      status: "deprovisioned",
      actor: "authz",
    });
    await rejectsWith(place(["acme", "legal"]), "invalid_transition");
  },
);
