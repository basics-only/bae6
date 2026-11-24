import pg from "pg";
import {
  JWKS_MAX_AGE_SECONDS,
  KeyError,
  revokeKey,
  unretireKey,
} from "./keys.js";

const [command, kid] = process.argv.slice(2);
const databaseUrl = process.env.BAE6_AUTHN_DATABASE_URL;
if (
  (command !== "unretire" && command !== "revoke") ||
  !kid ||
  !/^[A-Za-z0-9_-]{43}$/.test(kid)
) {
  console.error("usage: node dist/keys-cli.js unretire|revoke <kid>");
  process.exit(2);
}
if (!databaseUrl) {
  console.error("BAE6_AUTHN_DATABASE_URL is required");
  process.exit(2);
}

const pool = new pg.Pool({
  connectionString: databaseUrl,
  max: 1,
  connectionTimeoutMillis: 5000,
  statement_timeout: 15_000,
});
try {
  if (command === "revoke") {
    await revokeKey(pool, kid);
    console.log(
      `key ${kid} is revoked and left the JWKS now; verifiers may serve a cached JWKS for up to ${JWKS_MAX_AGE_SECONDS} seconds`,
    );
  } else {
    await unretireKey(pool, kid);
    console.log(
      `key ${kid} is next again; replicas with it as BAE6_AUTHN_ACTIVE_SIGNING_KEY promote it after the promotion delay`,
    );
  }
} catch (err) {
  if (!(err instanceof KeyError)) throw err;
  console.error(err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
