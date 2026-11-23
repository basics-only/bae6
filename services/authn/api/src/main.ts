import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import pg from "pg";
import { createBffRoutes } from "./bff.js";
import { migrate } from "./db/migrate.js";
import {
  activeSigner,
  localSigner,
  MAX_PUBLISHED_KEYS,
  type Signer,
  syncKeys,
} from "./keys.js";
import { OidcError, OidcProvider } from "./oidc.js";
import type { ConnectionPolicy } from "./principals.js";
import { createAuthnApi } from "./server.js";
import { MAX_SESSION_TTL_SECONDS } from "./sessions.js";
import { createTokenRoutes } from "./token-routes.js";

const env = process.env;
const log = (e: Record<string, unknown>) => console.log(JSON.stringify(e));

function int(name: string, fallback: number, min: number, max: number) {
  const v = Number(env[name] ?? fallback);
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return v;
}

function required(name: string) {
  const v = env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const port = int("PORT", 8080, 1, 65535);
const poolMax = int("BAE6_AUTHN_DB_POOL_MAX", 10, 1, 100);
const shutdownDelayMs = int("BAE6_SHUTDOWN_DELAY_MS", 0, 0, 15_000);
// Capped so delay + drain + 5 s stays under the 60 s termination grace period.
const requestTimeoutMs = int("BAE6_REQUEST_TIMEOUT_MS", 30_000, 1000, 30_000);
const databaseUrl = required("BAE6_AUTHN_DATABASE_URL");
const secretsDir = required("BAE6_AUTHN_SECRETS_DIR");
const sessionTtlSeconds = int(
  "BAE6_AUTHN_SESSION_TTL_SECONDS",
  28_800,
  300,
  MAX_SESSION_TTL_SECONDS,
);
const HOST =
  /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const tenantsByHost = new Map(
  required("BAE6_AUTHN_TENANT_HOSTS")
    .split(",")
    .map((pair) => {
      const [host = "", tenant = "", ...rest] = pair.trim().split("=");
      if (rest.length || !HOST.test(host) || !SLUG.test(tenant))
        throw new Error(
          "BAE6_AUTHN_TENANT_HOSTS must be host=tenant pairs, e.g. console.acme.example=acme",
        );
      return [host, tenant] as const;
    }),
);
const issuer = required("BAE6_AUTHN_ISSUER");
if (!/^https?:\/\/[^\s/?#]+(\/[^\s/?#]+)*$/.test(issuer))
  throw new Error(
    "BAE6_AUTHN_ISSUER must be an http(s) URL without a trailing slash",
  );
const audiences = new Set(
  required("BAE6_AUTHN_AUDIENCES")
    .split(",")
    .map((a) => a.trim()),
);
if (audiences.size > 64 || ![...audiences].every((a) => SLUG.test(a)))
  throw new Error("BAE6_AUTHN_AUDIENCES must be up to 64 service slugs");

const SECRET_REF = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const MAX_SECRET_BYTES = 8192;
const MIN_CLIENT_SECRET_LENGTH = 32;

const keysDir = required("BAE6_AUTHN_KEYS_DIR");
if (resolve(keysDir) === resolve(secretsDir))
  throw new Error(
    "BAE6_AUTHN_KEYS_DIR must differ from BAE6_AUTHN_SECRETS_DIR",
  );

async function readSecret(ref: string, dir = secretsDir): Promise<string> {
  if (!SECRET_REF.test(ref)) throw new Error("invalid secret name");
  const path = join(dir, ref);
  if ((await stat(path)).size > MAX_SECRET_BYTES)
    throw new Error("secret file too large");
  return (await readFile(path, "utf8")).trim();
}

const keyRefs = required("BAE6_AUTHN_SIGNING_KEYS").split(",");
if (keyRefs.length > MAX_PUBLISHED_KEYS)
  throw new Error(
    `BAE6_AUTHN_SIGNING_KEYS takes at most ${MAX_PUBLISHED_KEYS} keys`,
  );
const activeRef =
  env.BAE6_AUTHN_ACTIVE_SIGNING_KEY ||
  (keyRefs.length === 1 ? keyRefs[0]?.trim() : undefined);
if (!activeRef || !keyRefs.map((r) => r.trim()).includes(activeRef))
  throw new Error(
    "BAE6_AUTHN_ACTIVE_SIGNING_KEY must name one of BAE6_AUTHN_SIGNING_KEYS",
  );
const signers = new Map<string, Signer>();
let activeKid = "";
for (const ref of keyRefs.map((r) => r.trim())) {
  const signer = localSigner(await readSecret(ref, keysDir));
  signers.set(signer.kid, signer);
  if (ref === activeRef) activeKid = signer.kid;
}

const sessionClients = (env.BAE6_AUTHN_SESSION_CLIENTS ?? "")
  .split(",")
  .map((c) => c.trim())
  .filter(Boolean);
if (sessionClients.length > 16 || !sessionClients.every((c) => SLUG.test(c)))
  throw new Error("BAE6_AUTHN_SESSION_CLIENTS must be up to 16 client slugs");

async function clientSecret(client: string): Promise<string | undefined> {
  let secret: string;
  try {
    secret = await readSecret(`token-client-${client}`, keysDir);
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return undefined;
    throw err;
  }
  if (secret.length < MIN_CLIENT_SECRET_LENGTH)
    throw new Error(`token client secret for ${client} is too short`);
  return secret;
}

// Waiting on another replica's migration lock or building an index can exceed the request timeout.
const migrator = new pg.Client({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 5000,
  statement_timeout: 300_000,
});
await migrator.connect();
try {
  log({ msg: "migrations applied", applied: await migrate(migrator) });
} finally {
  await migrator.end();
}

const pool = new pg.Pool({
  connectionString: databaseUrl,
  max: poolMax,
  connectionTimeoutMillis: 5000,
  statement_timeout: 15_000,
});
pool.on("error", (err) => log({ msg: "pool_error", error: err.name }));

const MAX_CACHED_PROVIDERS = 256;
const providers = new Map<string, OidcProvider>();

async function provider(
  connection: ConnectionPolicy,
  redirectUri: string,
): Promise<OidcProvider> {
  const { rows } = await pool.query<{ clientId: string; secretRef: string }>(
    `SELECT client_id AS "clientId", client_secret_ref AS "secretRef"
       FROM provider_connections WHERE tenant_id = $1 AND id = $2`,
    [connection.tenantId, connection.id],
  );
  const row = rows[0];
  if (!row) throw new OidcError("provider_misconfigured");
  const clientSecret = await readSecret(row.secretRef).catch((err) => {
    throw new OidcError("provider_misconfigured", { cause: err });
  });
  const key = JSON.stringify([
    connection.tenantId,
    connection.id,
    connection.issuer,
    row.clientId,
    createHash("sha256").update(clientSecret).digest("base64url"),
    redirectUri,
  ]);
  const cached = providers.get(key);
  if (cached) return cached;
  const discovered = await OidcProvider.discover({
    issuer: connection.issuer,
    clientId: row.clientId,
    clientSecret,
    redirectUri,
  });
  if (providers.size >= MAX_CACHED_PROVIDERS)
    providers.delete(providers.keys().next().value as string);
  providers.set(key, discovered);
  return discovered;
}

let keyState = "";
async function rotateKeys() {
  try {
    const keys = await syncKeys(pool, signers, activeKid);
    const state = JSON.stringify(keys);
    if (state !== keyState) log({ msg: "signing_keys", keys });
    keyState = state;
  } catch (err) {
    log({ msg: "signing_keys_error", error: (err as Error).name });
  }
}
await rotateKeys();
const rotation = setInterval(rotateKeys, 60_000);
rotation.unref();

const bff = createBffRoutes({
  db: pool,
  provider,
  tenantsByHost,
  sessionTtlSeconds,
});
const tokens = createTokenRoutes({
  db: pool,
  signers,
  issuer,
  audiences,
  sessionClients,
  clientSecret,
});
const server = createAuthnApi({
  ping: async () => void (await activeSigner(pool, signers)),
  requestTimeoutMs,
  log,
  routes: async (req, res, url) =>
    (await tokens(req, res, url)) || bff(req, res, url),
});
server.listen(port, "0.0.0.0", () => log({ msg: "listening", port }));

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  clearInterval(rotation);
  server.drain();
  setTimeout(() => {
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    server.closeIdleConnections();
    setTimeout(() => process.exit(1), requestTimeoutMs + 5000).unref();
  }, shutdownDelayMs).unref();
};
process.once("SIGTERM", stop);
process.once("SIGINT", stop);
