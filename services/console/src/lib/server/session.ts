import { createHash } from "node:crypto";
import { type Authn, AuthnValidationError } from "@bae6/authn";
import { decodeJwt } from "jose";

/** The console keeps no sessions: the authn session cookie is the session. */
export interface Session {
  /** Never sent to the page; exchanged at authn for per-service tokens. */
  cookie: string;
  subject: string;
}

const AUTHN_AUDIENCE = "bae6-authn";

/** A token for `audience` on behalf of the session, or null once authn no longer honours it. */
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

/**
 * Caches per-service tokens until shortly before they expire, so one page costs one exchange
 * per service rather than one per API call. Entries are keyed on a hash of the cookie. The
 * session itself is never cached (see resolveSession), so a logged-out or revoked session
 * stops reaching any service on its next request.
 */
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
  // Read, not verified: the token came straight from authn's token endpoint.
  const { sub } = decodeJwt(token);
  if (!sub) throw new Error("authn issued a token without a subject");
  return { cookie, subject: sub };
}
