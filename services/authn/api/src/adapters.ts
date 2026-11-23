import { OidcError, type OidcProvider, type VerifiedLogin } from "./oidc.js";
import { type ConnectionPolicy, hasGroupOverage } from "./principals.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const OKTA_SERVER_ID = /^[A-Za-z0-9]{1,64}$/;
const GRAPH_BASE_URL = "https://graph.microsoft.com";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const GRAPH_TIMEOUT_MS = 5000;
const MAX_GRAPH_BYTES = 1024 * 1024;

export interface GraphOptions {
  baseUrl?: string;
  timeoutMs?: number;
  allowHttp?: boolean;
}

export function checkConnection(
  { kind, issuer }: Pick<ConnectionPolicy, "kind" | "issuer">,
  { allowHttp = false }: { allowHttp?: boolean } = {},
): void {
  if (!URL.canParse(issuer)) throw new OidcError("provider_misconfigured");
  const url = new URL(issuer);
  const segments = url.pathname.split("/").filter(Boolean);
  const [secondLast = "", last = ""] = segments.slice(-2);
  const pinned =
    kind === "entra"
      ? last === "v2.0" && UUID.test(secondLast)
      : kind === "okta"
        ? secondLast === "oauth2" && OKTA_SERVER_ID.test(last)
        : true;
  if (
    !pinned ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:"))
  )
    throw new OidcError("provider_misconfigured");
}

async function readLimited(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_GRAPH_BYTES) {
      await reader.cancel().catch(() => {});
      throw new OidcError("provider_unavailable");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function graphMemberGroups(
  appToken: string,
  oid: string,
  {
    baseUrl = GRAPH_BASE_URL,
    timeoutMs = GRAPH_TIMEOUT_MS,
    allowHttp = false,
  }: GraphOptions = {},
): Promise<unknown> {
  if (!UUID.test(oid)) throw new OidcError("invalid_callback");
  const url = new URL(
    `${baseUrl.replace(/\/+$/, "")}/v1.0/users/${oid}/getMemberObjects`,
  );
  if (url.protocol !== "https:" && !allowHttp)
    throw new OidcError("provider_misconfigured");
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${appToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ securityEnabledOnly: true }),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new OidcError("provider_unavailable", { cause: err });
  }
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => {});
    throw new OidcError(
      res.status === 429 || res.status >= 500
        ? "provider_unavailable"
        : "provider_misconfigured",
    );
  }
  let body: unknown;
  try {
    body = JSON.parse(await readLimited(res));
  } catch (err) {
    if (err instanceof OidcError) throw err;
    throw new OidcError("provider_unavailable", { cause: err });
  }
  const value = (body as { value?: unknown } | null)?.value;
  if (!Array.isArray(value)) throw new OidcError("provider_unavailable");
  return value;
}

const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_ASSERTION_LENGTH = 16 * 1024;
const ENTRA_RESOURCE = /^(https|api):\/\/[^\s/]+(\/[^\s/]+)*$/;

export async function entraOnBehalfOf(
  connection: Pick<ConnectionPolicy, "kind">,
  provider: Pick<OidcProvider, "onBehalfOf">,
  userAssertion: string,
  resource: string,
  allowedResources: readonly string[],
): Promise<{ accessToken: string; expiresAt: Date | undefined }> {
  if (
    connection.kind !== "entra" ||
    !allowedResources.every((r) => ENTRA_RESOURCE.test(r))
  )
    throw new OidcError("provider_misconfigured");
  if (
    !allowedResources.includes(resource) ||
    userAssertion.length > MAX_ASSERTION_LENGTH ||
    !JWT.test(userAssertion)
  )
    throw new OidcError("invalid_request");
  return provider.onBehalfOf(userAssertion, `${resource}/.default`);
}

export async function overageGroups(
  connection: Pick<ConnectionPolicy, "kind" | "groupClaim">,
  provider: Pick<OidcProvider, "clientCredentials">,
  login: VerifiedLogin,
  graph: GraphOptions = {},
): Promise<unknown> {
  const { claims } = login.identity;
  if (connection.kind !== "entra" || !hasGroupOverage(connection, claims))
    return undefined;
  if (typeof claims.oid !== "string") throw new OidcError("invalid_callback");
  const appToken = await provider.clientCredentials(GRAPH_SCOPE);
  return graphMemberGroups(appToken, claims.oid, graph);
}
