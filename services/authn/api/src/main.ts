import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import pg from "pg";
import { createBffRoutes } from "./bff.js";
import { migrate } from "./db/migrate.js";
import { OidcError, OidcProvider } from "./oidc.js";
import type { ConnectionPolicy } from "./principals.js";
import { createAuthnApi } from "./server.js";
import { MAX_SESSION_TTL_SECONDS } from "./sessions.js";

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

const SECRET_REF = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const MAX_SECRET_BYTES = 8192;
const MAX_CACHED_PROVIDERS = 256;
const providers = new Map<string, OidcProvider>();

async function readSecret(ref: string): Promise<string> {
  const path = join(secretsDir, ref);
  try {
    if ((await stat(path)).size > MAX_SECRET_BYTES)
      throw new Error("client secret file too large");
    return (await readFile(path, "utf8")).trim();
  } catch (err) {
    throw new OidcError("provider_misconfigured", { cause: err });
  }
}

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
  if (!row || !SECRET_REF.test(row.secretRef))
    throw new OidcError("provider_misconfigured");
  const clientSecret = await readSecret(row.secretRef);
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

const server = createAuthnApi({
  ping: async () => void (await pool.query("SELECT 1")),
  requestTimeoutMs,
  log,
  routes: createBffRoutes({
    db: pool,
    provider,
    tenantsByHost,
    sessionTtlSeconds,
  }),
});
server.listen(port, "0.0.0.0", () => log({ msg: "listening", port }));

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
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
