import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createIdp, type MockIdpConfig } from "@bae6/mock-oidc/idp.mjs";
import { decodeJwt } from "jose";
import {
  checkConnection,
  entraOnBehalfOf,
  graphMemberGroups,
  overageGroups,
} from "./adapters.js";
import { OidcError, OidcProvider } from "./oidc.js";

const require = createRequire(import.meta.url);
const config: MockIdpConfig = JSON.parse(
  readFileSync(require.resolve("@bae6/mock-oidc/providers.json"), "utf8"),
);
const ACME = "11111111-1111-4111-8111-111111111111";
const GLOBEX = "22222222-2222-4222-8222-222222222222";
const BOB_OID = "b2b2b2b2-0000-4000-8000-000000000002";
const client = config.clients[0] as MockIdpConfig["clients"][number];
let idpServer: Server;
let base: string;
let stub: Server;
let stubBase: string;
let stubReply: (res: import("node:http").ServerResponse) => void = (res) =>
  res.writeHead(503).end();

const listen = async (server: Server) => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

before(async () => {
  let idp: Awaited<ReturnType<typeof createIdp>>;
  idpServer = createServer(async (req, res) => {
    if (!(await idp.handle(req, res, new URL(req.url ?? "/", "http://mock"))))
      res.writeHead(404).end();
  });
  base = await listen(idpServer);
  idp = await createIdp({ baseUrl: base, config });
  stub = createServer((req, res) => {
    req.resume();
    stubReply(res);
  });
  stubBase = await listen(stub);
});

after(async () => {
  for (const s of [idpServer, stub]) {
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }
});

const misconfigured = (fn: () => unknown) =>
  assert.throws(
    fn,
    (e: unknown) =>
      e instanceof OidcError && e.code === "provider_misconfigured",
  );
const rejectsWith = (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e: unknown) => e instanceof OidcError && e.code === code);

async function signIn(
  kind: "entra" | "okta" | "ping",
  issuer: string,
  login?: string,
  scopes?: string[],
) {
  const provider = await OidcProvider.discover(
    {
      issuer,
      clientId: client.id,
      clientSecret: client.secret,
      redirectUri: `http://localhost:8092/auth/callback/${kind}`,
      ...(scopes ? { scopes } : {}),
    },
    { allowHttp: true },
  );
  const { url, pending } = await provider.beginLogin(
    login ? { loginHint: login } : {},
  );
  const res = await fetch(url, { redirect: "manual" });
  const back = new URL(res.headers.get("location") as string).searchParams;
  return { provider, login: await provider.completeLogin(back, pending) };
}

const GRAPH_SCOPE = "https://graph.microsoft.com/.default";

const graph = () => ({ baseUrl: `${base}/entra/graph`, allowHttp: true });
const entra = { kind: "entra" as const, groupClaim: "groups" };

test("Entra connections must be pinned to one tenant and Okta to a custom authorization server", () => {
  checkConnection({
    kind: "entra",
    issuer: `https://login.microsoftonline.com/${ACME}/v2.0`,
  });
  checkConnection({
    kind: "okta",
    issuer: "https://acme.okta.com/oauth2/default",
  });
  checkConnection({
    kind: "okta",
    issuer: "https://acme.okta.com/oauth2/aus1bae6default",
  });
  checkConnection({ kind: "pingfederate", issuer: "https://sso.acme.example" });
  for (const tenant of ["common", "organizations", "consumers", "ACME-TENANT"])
    misconfigured(() =>
      checkConnection({
        kind: "entra",
        issuer: `https://login.microsoftonline.com/${tenant}/v2.0`,
      }),
    );
  misconfigured(() =>
    checkConnection({
      kind: "entra",
      issuer: `https://login.microsoftonline.com/${ACME}`,
    }),
  );
  misconfigured(() =>
    checkConnection({ kind: "okta", issuer: "https://acme.okta.com" }),
  );
  misconfigured(() =>
    checkConnection({
      kind: "okta",
      issuer: "https://acme.okta.com/oauth2/../x",
    }),
  );
  misconfigured(() => checkConnection({ kind: "oidc", issuer: "not a url" }));
  misconfigured(() =>
    checkConnection({
      kind: "pingfederate",
      issuer: "http://sso.acme.example",
    }),
  );
  checkConnection(
    { kind: "pingfederate", issuer: "http://sso.acme.example" },
    { allowHttp: true },
  );
  for (const issuer of [
    `https://login.microsoftonline.com/${ACME}/v2.0?x=1`,
    `https://login.microsoftonline.com/${ACME}/v2.0#x`,
    "https://login.microsoftonline.com/AAAABBBB-1111-4111-8111-111111111111/v2.0",
  ])
    misconfigured(() => checkConnection({ kind: "entra", issuer }));
});

test("an Entra user over the group limit gets every group from Graph with an app-only token", async () => {
  const bob = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "bob@acme.example",
  );
  assert.equal(bob.login.identity.claims.groups, undefined);
  const groups = await overageGroups(entra, bob.provider, bob.login, graph());
  assert.equal((groups as string[]).length, 6);
  const alice = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "alice@acme.example",
  );
  assert.equal(
    await overageGroups(entra, alice.provider, alice.login, graph()),
    undefined,
  );
  const carol = await signIn("okta", `${base}/okta/oauth2/aus1bae6default`);
  assert.equal(
    await overageGroups(
      { kind: "okta", groupClaim: "groups" },
      carol.provider,
      carol.login,
      graph(),
    ),
    undefined,
  );
});

test("Graph refuses the user's own delegated token", async () => {
  const bob = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "bob@acme.example",
  );
  await rejectsWith(
    graphMemberGroups(bob.login.providerAccessToken, BOB_OID, graph()),
    "provider_misconfigured",
  );
});

test("Graph is called at the configured base URL, never the endpoint the token names", async () => {
  const bob = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "bob@acme.example",
  );
  stubReply = (res) => res.writeHead(503).end();
  await rejectsWith(
    overageGroups(entra, bob.provider, bob.login, {
      baseUrl: stubBase,
      allowHttp: true,
    }),
    "provider_unavailable",
  );
  const slashed = { baseUrl: `${base}/entra/graph/`, allowHttp: true };
  assert.equal(
    ((await overageGroups(entra, bob.provider, bob.login, slashed)) as string[])
      .length,
    6,
  );
});

test("another tenant's token cannot read a user's groups", async () => {
  const erin = await signIn("entra", `${base}/entra/${GLOBEX}/v2.0`);
  await rejectsWith(
    graphMemberGroups(
      await erin.provider.clientCredentials(GRAPH_SCOPE),
      BOB_OID,
      graph(),
    ),
    "provider_misconfigured",
  );
  await rejectsWith(
    graphMemberGroups("not-a-token", BOB_OID, graph()),
    "provider_misconfigured",
  );
});

test("Graph failures never yield a group list", async () => {
  const at = { baseUrl: stubBase, allowHttp: true };
  for (const [reply, code] of [
    [(res) => res.writeHead(503).end(), "provider_unavailable"],
    [(res) => res.writeHead(429).end(), "provider_unavailable"],
    [(res) => res.writeHead(403).end(), "provider_misconfigured"],
    [(res) => res.writeHead(200).end("not json"), "provider_unavailable"],
    [(res) => res.writeHead(200).end('{"value":"x"}'), "provider_unavailable"],
    [
      (res) => res.writeHead(302, { location: "https://evil.example" }).end(),
      "provider_unavailable",
    ],
    [
      (res) =>
        res
          .writeHead(200)
          .end(JSON.stringify({ value: ["g".repeat(1_100_000)] })),
      "provider_unavailable",
    ],
  ] as [(res: import("node:http").ServerResponse) => void, string][]) {
    stubReply = reply;
    await rejectsWith(graphMemberGroups("t", BOB_OID, at), code);
  }
  stubReply = () => {};
  await rejectsWith(
    graphMemberGroups("t", BOB_OID, { ...at, timeoutMs: 100 }),
    "provider_unavailable",
  );
  await rejectsWith(graphMemberGroups("t", "../../me", at), "invalid_callback");
  await rejectsWith(
    graphMemberGroups("t", BOB_OID, { baseUrl: stubBase }),
    "provider_misconfigured",
  );
});

const SHAREPOINT = "https://acme.sharepoint.com";
const appScopes = () => [
  "openid",
  "profile",
  "email",
  `api://${client.id}/access_as_user`,
];

test("on-behalf-of trades the user's token for one scoped to an allowed downstream resource", async () => {
  const alice = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "alice@acme.example",
    appScopes(),
  );
  const { accessToken, expiresAt } = await entraOnBehalfOf(
    entra,
    alice.provider,
    alice.login.providerAccessToken,
    SHAREPOINT,
    [SHAREPOINT],
  );
  const claims = decodeJwt(accessToken);
  assert.equal(claims.aud, SHAREPOINT);
  assert.equal(claims.oid, alice.login.identity.claims.oid);
  assert.ok(expiresAt);
});

test("on-behalf-of refuses resources off the allowlist, malformed assertions and non-Entra connections", async () => {
  const alice = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "alice@acme.example",
    appScopes(),
  );
  const token = alice.login.providerAccessToken;
  const call = (resource: string, assertion = token) =>
    entraOnBehalfOf(entra, alice.provider, assertion, resource, [SHAREPOINT]);
  await rejectsWith(call("https://graph.microsoft.com"), "invalid_request");
  await rejectsWith(call(`${SHAREPOINT}/sites`), "invalid_request");
  await rejectsWith(call(SHAREPOINT, "not-a-jwt"), "invalid_request");
  await rejectsWith(
    call(SHAREPOINT, `a.${"b".repeat(17_000)}.c`),
    "invalid_request",
  );
  await rejectsWith(
    entraOnBehalfOf({ kind: "okta" }, alice.provider, token, SHAREPOINT, [
      SHAREPOINT,
    ]),
    "provider_misconfigured",
  );
  for (const bad of [`${SHAREPOINT}/`, `${SHAREPOINT} openid`, "acme"])
    await rejectsWith(
      entraOnBehalfOf(entra, alice.provider, token, SHAREPOINT, [
        SHAREPOINT,
        bad,
      ]),
      "provider_misconfigured",
    );
});

test("on-behalf-of is denied for tokens not issued to this app in this tenant", async () => {
  const acme = await signIn(
    "entra",
    `${base}/entra/${ACME}/v2.0`,
    "alice@acme.example",
  );
  assert.equal(
    decodeJwt(acme.login.providerAccessToken).aud,
    "https://graph.microsoft.com",
  );
  const globex = await signIn(
    "entra",
    `${base}/entra/${GLOBEX}/v2.0`,
    undefined,
    appScopes(),
  );
  for (const assertion of [
    acme.login.providerAccessToken,
    globex.login.providerAccessToken,
    await acme.provider.clientCredentials(`${client.id}/.default`),
  ])
    await rejectsWith(
      entraOnBehalfOf(entra, acme.provider, assertion, SHAREPOINT, [
        SHAREPOINT,
      ]),
      "provider_denied",
    );
});
