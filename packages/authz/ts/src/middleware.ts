import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  Authz,
  AuthzAuthError,
  type AuthzOptions,
  type ExecutionContext,
} from "./index.js";

export interface TenantResource {
  resourceType: string;
  resourceId: string;
}

export interface ExchangedToken {
  accessToken: string;
  expiresIn: number;
}

export type Verdict =
  | { allowed: true; executionContext?: ExecutionContext }
  | { allowed: false; status: 401 | 403 | 503; code: string; message: string };

const BEARER = /^Bearer ([\x21-\x7e]{1,4096})$/;
const MAX_CACHED_TOKENS = 1000;
const REUSE_MARGIN_SECONDS = 30;
const MAX_REUSE_SECONDS = 60;

const deny = (
  status: 401 | 403 | 503,
  code: string,
  message: string,
): Verdict => ({ allowed: false, status, code, message });

/**
 * `exchange` turns the caller's token into one for the `bae6-authz` audience, and a
 * 400 from it means the caller's token was refused. Only an explicit allow lets a
 * request through; every failure denies.
 */
export function tenantGuard(options: {
  authz: Omit<AuthzOptions, "credentials">;
  includeExecutionContext?: boolean;
  exchange(subjectToken: string): Promise<ExchangedToken>;
}) {
  const exchanged = new Map<string, { accessToken: string; until: number }>();

  async function authzTokenFor(subjectToken: string) {
    const key = createHash("sha256").update(subjectToken).digest("hex");
    const hit = exchanged.get(key);
    if (hit && hit.until > Date.now()) return hit.accessToken;
    const { accessToken, expiresIn } = await options.exchange(subjectToken);
    const reuseSeconds = Math.min(
      expiresIn - REUSE_MARGIN_SECONDS,
      MAX_REUSE_SECONDS,
    );
    exchanged.delete(key);
    exchanged.set(key, {
      accessToken,
      until: Date.now() + reuseSeconds * 1000,
    });
    if (exchanged.size > MAX_CACHED_TOKENS)
      exchanged.delete(exchanged.keys().next().value as string);
    return accessToken;
  }

  return async (
    authorization: string | undefined,
    resource: TenantResource | undefined,
  ): Promise<Verdict> => {
    const subjectToken = BEARER.exec(authorization ?? "")?.[1];
    if (!subjectToken)
      return deny(401, "unauthenticated", "A bearer token is required.");
    if (!resource)
      return deny(403, "forbidden", "No tenant resource maps to this request.");
    let accessToken: string;
    try {
      accessToken = await authzTokenFor(subjectToken);
    } catch (err) {
      return (err as { status?: unknown }).status === 400
        ? deny(401, "unauthenticated", "The bearer token was refused.")
        : deny(503, "unavailable", "Authorization is unavailable.");
    }
    try {
      const authz = new Authz({
        ...options.authz,
        credentials: accessToken,
      });
      if (options.includeExecutionContext) {
        return {
          allowed: true,
          executionContext: await authz.require(resource),
        };
      } else if (await authz.tenantCheck(resource)) {
        return { allowed: true };
      }
      return deny(403, "forbidden", "Not permitted.");
    } catch (err) {
      return err instanceof AuthzAuthError
        ? deny(403, "forbidden", "Not permitted.")
        : deny(503, "unavailable", "Authorization is unavailable.");
    }
  };
}

const contextKey = Symbol("bae6ExecutionContext");
type GuardedRequest = { [contextKey]?: ExecutionContext | undefined };

export const executionContextOf = (
  request: object,
): ExecutionContext | undefined => (request as GuardedRequest)[contextKey];

type Guard = ReturnType<typeof tenantGuard>;
type ResourceOf<Req> = (
  req: Req,
) => TenantResource | undefined | Promise<TenantResource | undefined>;

/**
 * Connect-style middleware for `node:http` (pass your handler as `next`) and Express.
 * An error from `resourceOf` goes to `next(err)` and never lets the request through.
 */
export const nodeMiddleware =
  <Req extends IncomingMessage>(guard: Guard, resourceOf: ResourceOf<Req>) =>
  async (req: Req, res: ServerResponse, next: (err?: unknown) => void) => {
    const target = req as GuardedRequest;
    delete target[contextKey];
    let verdict: Verdict;
    try {
      verdict = await guard(req.headers.authorization, await resourceOf(req));
    } catch (err) {
      return next(err);
    }
    if (verdict.allowed) {
      if (verdict.executionContext)
        target[contextKey] = verdict.executionContext;
      return next();
    }
    if (verdict.status === 401) res.setHeader("www-authenticate", "Bearer");
    res.writeHead(verdict.status, { "content-type": "application/json" });
    res.end(JSON.stringify({ code: verdict.code, message: verdict.message }));
  };

interface ReplyLike {
  code(status: number): ReplyLike;
  header(name: string, value: string): ReplyLike;
  send(body: unknown): unknown;
}

/** Fastify `preHandler` hook (or `onRequest`). */
export const fastifyHook =
  <Req extends { headers: IncomingMessage["headers"] }>(
    guard: Guard,
    resourceOf: ResourceOf<Req>,
  ) =>
  async (request: Req, reply: ReplyLike) => {
    const target = request as GuardedRequest;
    delete target[contextKey];
    const verdict = await guard(
      request.headers.authorization,
      await resourceOf(request),
    );
    if (verdict.allowed) {
      if (verdict.executionContext)
        target[contextKey] = verdict.executionContext;
      return;
    }
    if (verdict.status === 401) reply.header("www-authenticate", "Bearer");
    return reply
      .code(verdict.status)
      .send({ code: verdict.code, message: verdict.message });
  };
