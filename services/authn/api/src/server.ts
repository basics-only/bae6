import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { envelope, HttpError, send } from "./http.js";

export interface AuthnApiDeps {
  ping(): Promise<void>;
  requestTimeoutMs: number;
  log?: (event: Record<string, unknown>) => void;
}

const WRITE_DEADLINE_MS = 30_000;
const MAX_CONNECTIONS = 256;
const REQUEST_ID = /^[A-Za-z0-9._-]{1,64}$/;
const PING_TIMEOUT_MS = 2000;

export function createAuthnApi(deps: AuthnApiDeps) {
  const { log = () => {} } = deps;
  let draining = false;

  async function ready() {
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        deps.ping(),
        new Promise<never>((_, bad) => {
          timer = setTimeout(() => bad(new Error("timeout")), PING_TIMEOUT_MS);
        }),
      ]);
    } catch {
      throw new HttpError(503, "unavailable", "Not ready.");
    } finally {
      clearTimeout(timer);
    }
  }

  async function route(req: IncomingMessage, res: ServerResponse, url: URL) {
    const { pathname: path } = url;
    if (req.method === "GET" && path === "/health/live") {
      return send(res, 200, { status: "ok" });
    }
    if (req.method === "GET" && path === "/health/ready") {
      if (draining) throw new HttpError(503, "unavailable", "Not ready.");
      await ready();
      return send(res, 200, { status: "ok" });
    }
    throw new HttpError(404, "not_found", "Not found.");
  }

  const server = createServer(async (req, res) => {
    const supplied = req.headers["x-request-id"];
    const requestId =
      typeof supplied === "string" && REQUEST_ID.test(supplied)
        ? supplied
        : `req_${randomUUID()}`;
    res.setHeader("x-request-id", requestId);
    const started = performance.now();
    let url: URL;
    try {
      url = new URL(req.url ?? "/", "http://authn");
    } catch {
      url = new URL("http://authn/");
    }
    res.once("close", () =>
      log({
        msg: "request",
        requestId,
        method: req.method,
        path: url.pathname,
        status: res.statusCode,
        durationMs: Math.round(performance.now() - started),
      }),
    );
    try {
      await route(req, res, url);
    } catch (err) {
      let e: HttpError;
      if (err instanceof HttpError) {
        e = err;
      } else {
        log({ msg: "internal_error", requestId, error: (err as Error).name });
        e = new HttpError(500, "internal", "Internal error.");
      }
      if (res.headersSent) {
        res.end();
      } else {
        if (e.retryAfterSeconds !== undefined) {
          res.setHeader("retry-after", String(e.retryAfterSeconds));
        }
        send(res, e.status, envelope(e, requestId));
      }
    }
    if (!res.writableFinished && !res.closed) {
      const t = setTimeout(() => res.destroy(), WRITE_DEADLINE_MS).unref();
      res.once("close", () => clearTimeout(t));
    }
  });
  server.headersTimeout = Math.min(10_000, deps.requestTimeoutMs);
  server.maxConnections = MAX_CONNECTIONS;
  server.requestTimeout = deps.requestTimeoutMs;

  return Object.assign(server, {
    drain() {
      draining = true;
      server.closeIdleConnections();
    },
  });
}
