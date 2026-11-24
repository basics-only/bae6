import { createHash } from "node:crypto";
import { type Authn, AuthnValidationError } from "@bae6/authn";
import { decodeJwt } from "jose";

export interface Session {
  cookie: string;
  subject: string;
}

const AUTHN_AUDIENCE = "bae6-authn";

export async function tokenFor(
  authn: Authn,
  cookie: string,
  audience: string,
): Promise<string | null> {
  try {
    const { accessToken } = await authn.exchangeToken({
      subjectToken: cookie,
      subjectTokenType: "session",
      audience,
    });
    return accessToken;
  } catch (err) {
    if (err instanceof AuthnValidationError && err.code === "invalid_request")
      return null;
    throw err;
  }
}

const CACHE_MAX_ENTRIES = 1000;
const CACHE_MARGIN_SECONDS = 30;

export function tokenCache(authn: Authn, now: () => number = Date.now) {
  const entries = new Map<string, { token: string; expiresAt: number }>();
  return async (cookie: string, audience: string): Promise<string | null> => {
    const key = `${createHash("sha256").update(cookie).digest("base64url")}:${audience}`;
    const hit = entries.get(key);
    if (hit && hit.expiresAt > now()) return hit.token;
    entries.delete(key);
    const token = await tokenFor(authn, cookie, audience);
    const exp = token ? decodeJwt(token).exp : undefined;
    if (token && exp !== undefined) {
      if (entries.size >= CACHE_MAX_ENTRIES)
        entries.delete(entries.keys().next().value as string);
      entries.set(key, {
        token,
        expiresAt: (exp - CACHE_MARGIN_SECONDS) * 1000,
      });
    }
    return token;
  };
}

export async function resolveSession(
  authn: Authn,
  cookie: string | undefined,
): Promise<Session | null> {
  if (!cookie) return null;
  const token = await tokenFor(authn, cookie, AUTHN_AUDIENCE);
  if (!token) return null;
  const { sub } = decodeJwt(token);
  if (!sub) throw new Error("authn issued a token without a subject");
  return { cookie, subject: sub };
}
