import type { ServerResponse } from "node:http";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

export function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body));
}

export function envelope(err: HttpError, requestId: string) {
  return {
    code: err.code,
    message: err.message,
    requestId,
    ...(err.retryAfterSeconds === undefined
      ? {}
      : { retryAfterSeconds: err.retryAfterSeconds }),
  };
}
