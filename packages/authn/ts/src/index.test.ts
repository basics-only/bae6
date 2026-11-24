import assert from "node:assert/strict";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import {
  Authn,
  AuthnApiError,
  AuthnAuthError,
  AuthnTimeoutError,
  AuthnValidationError,
} from "./index.js";

const SECRET = "client-secret-xxxxxxxxxxxxxxxxxxxxxxxx";
const SESSION = `ses_${"a".repeat(32)}.${"b".repeat(43)}`;

type Seen = {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingHttpHeaders;
  body: string;
};

async function serve(
  status: number,
  body: unknown,
  delayMs = 0,
): Promise<{ authn: Authn; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    seen.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString(),
    });
    const timer = setTimeout(() => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    }, delayMs);
    res.on("close", () => clearTimeout(timer));
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const authn = new Authn({
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    credentials: SECRET,
    timeoutMs: 200,
  });
  return {
    authn,
    seen,
    close: async () => {
      server.closeAllConnections();
      await new Promise((ok) => server.close(ok));
    },
  };
}

const exchange = (authn: Authn) =>
  authn.exchangeToken({
    subjectToken: SESSION,
    subjectTokenType: "session",
    audience: "bae6-ai",
  });

test("exchangeToken posts an RFC 8693 form with the client secret as bearer", async () => {
  const s = await serve(200, {
    access_token: "tok",
    issued_token_type: "urn:ietf:params:oauth:token-type:jwt",
    token_type: "Bearer",
    expires_in: 300,
  });
  try {
    assert.deepEqual(await exchange(s.authn), {
      accessToken: "tok",
      expiresIn: 300,
    });
    const [req] = s.seen;
    assert.equal(s.seen.length, 1);
    assert.equal(req?.method, "POST");
    assert.equal(req?.url, "/auth/token");
    assert.equal(req?.headers.authorization, `Bearer ${SECRET}`);
    assert.equal(
      req?.headers["content-type"],
      "application/x-www-form-urlencoded",
    );
    assert.deepEqual(Object.fromEntries(new URLSearchParams(req?.body)), {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: SESSION,
      subject_token_type: "urn:bae6:params:oauth:token-type:session",
      audience: "bae6-ai",
    });
  } finally {
    await s.close();
  }
});

test("exchangeToken maps OAuth errors without leaking tokens and never retries", async () => {
  for (const [status, error, Err] of [
    [401, "invalid_client", AuthnAuthError],
    [400, "invalid_target", AuthnValidationError],
  ] as const) {
    const s = await serve(status, { error });
    try {
      const err = await exchange(s.authn).catch((e: unknown) => e);
      assert.ok(err instanceof Err);
      assert.equal(err.status, status);
      assert.equal(err.code, error);
      assert.ok(
        !err.message.includes(SECRET) && !err.message.includes(SESSION),
      );
      assert.equal(s.seen.length, 1);
    } finally {
      await s.close();
    }
  }
});

test("exchangeToken rejects a success response that is not a bearer token", async () => {
  const s = await serve(200, {
    access_token: "tok",
    token_type: "DPoP",
    expires_in: 300,
  });
  try {
    const err = await exchange(s.authn).catch((e: unknown) => e);
    assert.ok(err instanceof AuthnApiError);
    assert.equal(err.code, "invalid_response");
  } finally {
    await s.close();
  }
});

test("me sends the bae6 token, not the client secret", async () => {
  const principal = {
    id: `prn_${"c".repeat(32)}`,
    tenantId: "acme",
    type: "user",
    status: "active",
  };
  const s = await serve(200, { principal, orgPath: ["acme", "eng"] });
  try {
    const me = await s.authn.me("user-token");
    assert.deepEqual(me, { principal, orgPath: ["acme", "eng"] });
    assert.equal(s.seen[0]?.method, "GET");
    assert.equal(s.seen[0]?.url, "/auth/me");
    assert.equal(s.seen[0]?.headers.authorization, "Bearer user-token");
  } finally {
    await s.close();
  }
});

test("me rejects a partial principal or an empty orgPath", async () => {
  const principal = {
    id: "prn_x",
    tenantId: "acme",
    type: "user",
    status: "active",
  };
  for (const body of [
    { principal: { id: "prn_x" }, orgPath: ["acme"] },
    { principal: { ...principal, type: "root" }, orgPath: ["acme"] },
    { principal, orgPath: [] },
  ]) {
    const s = await serve(200, body);
    try {
      const err = await s.authn.me("user-token").catch((e: unknown) => e);
      assert.ok(err instanceof AuthnApiError);
      assert.equal(err.code, "invalid_response");
    } finally {
      await s.close();
    }
  }
});

test("exchangeToken refuses an unknown subject token type before sending", async () => {
  const s = await serve(200, {});
  try {
    await assert.rejects(
      s.authn.exchangeToken({
        subjectToken: SESSION,
        subjectTokenType: "access_token" as "jwt",
        audience: "bae6-ai",
      }),
      TypeError,
    );
    assert.equal(s.seen.length, 0);
  } finally {
    await s.close();
  }
});

test("me maps 401 and times out", async () => {
  const s = await serve(401, { code: "unauthenticated", message: "no" });
  try {
    await assert.rejects(s.authn.me("user-token"), AuthnAuthError);
  } finally {
    await s.close();
  }
  const slow = await serve(200, {}, 1000);
  try {
    await assert.rejects(slow.authn.me("user-token"), AuthnTimeoutError);
  } finally {
    await slow.close();
  }
});

test("placePrincipal puts the tenant and path as JSON and returns the stored path", async () => {
  const s = await serve(200, { orgPath: ["acme", "finance"] });
  try {
    const path = await s.authn.placePrincipal({
      tenantId: "acme",
      principalId: "prn_x",
      principalType: "user",
      orgPath: ["acme", "finance"],
    });
    assert.deepEqual(path, ["acme", "finance"]);
    const [req] = s.seen;
    assert.equal(req?.method, "PUT");
    assert.equal(req?.url, "/admin/principals/prn_x/org-path");
    assert.equal(req?.headers.authorization, `Bearer ${SECRET}`);
    assert.deepEqual(JSON.parse(req?.body ?? ""), {
      tenantId: "acme",
      principalType: "user",
      orgPath: ["acme", "finance"],
    });
  } finally {
    await s.close();
  }
});

test("placePrincipal maps refusals to typed errors", async () => {
  for (const [status, Err] of [
    [401, AuthnAuthError],
    [400, AuthnValidationError],
    [404, AuthnApiError],
  ] as const) {
    const s = await serve(status, { code: "refused" });
    try {
      const err = await s.authn
        .placePrincipal({
          tenantId: "acme",
          principalId: "prn_x",
          principalType: "user",
          orgPath: ["acme"],
        })
        .catch((e: unknown) => e);
      assert.ok(err instanceof Err);
      assert.equal((err as AuthnApiError).status, status);
    } finally {
      await s.close();
    }
  }
});

test("revokeDelegation uses the initiating principal bearer and expects no content", async () => {
  const s = await serve(204, null);
  const id = `dlg_${"a".repeat(32)}`;
  try {
    await s.authn.revokeDelegation(id, "initiator-token");
    const [req] = s.seen;
    assert.equal(req?.method, "POST");
    assert.equal(req?.url, `/v1/delegations/${id}/revoke`);
    assert.equal(req?.headers.authorization, "Bearer initiator-token");
    assert.equal(req?.body, "");
  } finally {
    await s.close();
  }
});
