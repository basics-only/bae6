import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { decodeJwt } from "jose";
import {
  type ExchangeDeps,
  exchangeSession,
  exchangeToken,
  OAuthError,
  parseExchangeRequest,
  SESSION_TOKEN_TYPE,
} from "./exchange.js";
import { HttpError, send } from "./http.js";
import { JWKS_MAX_AGE_SECONDS, KeyError, publishedKeys } from "./keys.js";

const MAX_FORM_BYTES = 20_480;
const BEARER = /^Bearer ([\x21-\x7e]{1,512})$/;

export interface TokenRouteDeps extends ExchangeDeps {
  sessionClients: readonly string[];
  clientSecret(client: string): Promise<string | undefined>;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest();

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const type = req.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded")
    throw new OAuthError("invalid_request");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_FORM_BYTES) throw new OAuthError("invalid_request");
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

export async function clientAuthenticated(
  clientSecret: TokenRouteDeps["clientSecret"],
  req: IncomingMessage,
  clients: readonly string[],
): Promise<boolean> {
  const supplied = BEARER.exec(req.headers.authorization ?? "")?.[1];
  if (!supplied) return false;
  for (const client of clients) {
    const expected = await clientSecret(client);
    if (expected && timingSafeEqual(sha256(supplied), sha256(expected)))
      return true;
  }
  return false;
}

export function createTokenRoutes(deps: TokenRouteDeps) {
  async function authenticate(req: IncomingMessage, clients: string[]) {
    if (!(await clientAuthenticated(deps.clientSecret, req, clients)))
      throw new OAuthError("invalid_client");
  }

  async function callerAudience(req: IncomingMessage, subjectToken: string) {
    let aud: unknown;
    try {
      aud = decodeJwt(subjectToken).aud;
    } catch (err) {
      throw new OAuthError("invalid_request", { cause: err });
    }
    if (typeof aud !== "string" || !deps.audiences.has(aud))
      throw new OAuthError("invalid_request");
    await authenticate(req, [aud]);
    return aud;
  }

  async function token(req: IncomingMessage, res: ServerResponse) {
    const request = parseExchangeRequest(await readForm(req));
    if (request.subjectTokenType === SESSION_TOKEN_TYPE)
      await authenticate(req, [...deps.sessionClients]);
    const out =
      request.subjectTokenType === SESSION_TOKEN_TYPE
        ? await exchangeSession(
            deps,
            request,
            String(res.getHeader("x-request-id")),
          )
        : await exchangeToken(
            deps,
            { audience: await callerAudience(req, request.subjectToken) },
            request,
          );
    send(res, 200, out);
  }

  async function jwks(res: ServerResponse) {
    const keys = await publishedKeys(deps.db);
    res.writeHead(200, {
      "content-type": "application/json",
      "cache-control": `public, max-age=${JWKS_MAX_AGE_SECONDS}`,
    });
    res.end(JSON.stringify({ keys }));
  }

  return async function route(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
  ): Promise<boolean> {
    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") {
      await jwks(res);
      return true;
    }
    if (req.method !== "POST" || url.pathname !== "/auth/token") return false;
    try {
      await token(req, res);
    } catch (err) {
      if (err instanceof KeyError)
        throw new HttpError(503, "unavailable", "Token signing unavailable.");
      if (!(err instanceof OAuthError)) throw err;
      if (err.status === 401) res.setHeader("www-authenticate", "Bearer");
      send(res, err.status, { error: err.error });
    }
    return true;
  };
}
