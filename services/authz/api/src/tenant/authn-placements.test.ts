import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { authnPlacements } from "./authn-placements.js";

const ALICE = `prn_${"a".repeat(32)}`;

async function withAuthn(
  status: number,
  run: (placements: ReturnType<typeof authnPlacements>) => Promise<void>,
) {
  const seen: Record<string, string | undefined>[] = [];
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    seen.push({
      method: req.method,
      url: req.url,
      auth: req.headers.authorization,
      body,
    });
    res.writeHead(status).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run(authnPlacements({ baseUrl, secret: "s".repeat(40) }));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
  return seen;
}

test("a placement is pushed to authn with the placement secret", async () => {
  const seen = await withAuthn(200, (p) =>
    p.place({
      tenantId: "acme",
      principalId: ALICE,
      orgPath: ["acme", "finance"],
    }),
  );
  assert.deepEqual(seen, [
    {
      method: "PUT",
      url: `/admin/principals/${ALICE}/org-path`,
      auth: `Bearer ${"s".repeat(40)}`,
      body: JSON.stringify({ tenantId: "acme", orgPath: ["acme", "finance"] }),
    },
  ]);
});

test("an authn refusal is raised with its status", async () => {
  await withAuthn(409, async (p) => {
    await assert.rejects(
      p.place({ tenantId: "acme", principalId: ALICE, orgPath: ["acme"] }),
      { status: 409 },
    );
  });
});
