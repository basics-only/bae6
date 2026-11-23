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

// shortcut: one exchange per request to validate the session, and one per API call;
// cache tokens per session until near expiry if authn load becomes a problem.
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
