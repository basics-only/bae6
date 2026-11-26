import { parseArgs } from "node:util";
import pg from "pg";
import { migrate } from "../db/migrate.js";
import { createTenantService, tenantClient } from "./service.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const { values } = parseArgs({
  options: {
    operator: { type: "string" },
    admin: { type: "string" },
  },
});
if (!values.operator || !values.admin) {
  console.error(
    "usage: node dist/tenant/bootstrap-root.js --operator <user|service>:<id> --admin <user|service>:<id>",
  );
  process.exit(2);
}

const organization = required("BAE6_TENANT_ORGANIZATION");
const pool = new pg.Pool({
  connectionString: required("BAE6_DATABASE_URL"),
  connectionTimeoutMillis: 5000,
});
try {
  const migrator = await pool.connect();
  try {
    await migrate(migrator);
  } finally {
    migrator.release();
  }
  const service = createTenantService({
    pool,
    organization,
    client: tenantClient({
      apiUrl: required("OPENFGA_API_URL"),
      storeId: required("BAE6_TENANT_STORE_ID"),
      authorizationModelId: required("BAE6_TENANT_MODEL_ID"),
    }),
  });
  const auditEventId = await service.bootstrap(
    values.operator,
    organization,
    values.admin,
  );
  console.log(
    JSON.stringify({ organization, admin: values.admin, auditEventId }),
  );
} finally {
  await pool.end();
}
