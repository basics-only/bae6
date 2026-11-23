export type * from "./identity.js";

export type Credentials = string | (() => string | Promise<string>);

export interface RequestInfo {
  method: string;
  url: string;
  attempt: number;
  /** Mutable: add headers before the request is sent. */
  headers: Record<string, string>;
}

export interface ResponseInfo {
  method: string;
  url: string;
  attempt: number;
  status: number;
  headers: Headers;
  durationMs: number;
}

export interface ClientOptions {
  baseUrl: string;
  /** A bearer token, or a function called before every attempt so tokens can rotate. */
  credentials: Credentials;
  /** Replaces the global fetch, for proxies, mTLS agents or tests. */
  fetch?: typeof fetch;
  /** Per attempt. */
  timeoutMs?: number;
  /** Retries after the first attempt, for idempotent requests only. Defaults to 2; 0 disables. */
  maxRetries?: number;
  onRequest?: (request: RequestInfo) => void | Promise<void>;
  onResponse?: (response: ResponseInfo) => void | Promise<void>;
}

/** How a product SDK reports failures in its own error classes. */
export interface TransportErrors {
  timeout(timeoutMs: number): Error;
  unreachable(causeName: string): Error;
  tooLarge(): Error;
  api(
    status: number,
    body: Uint8Array,
  ): Error & { retryAfterSeconds?: number | undefined };
}

export interface Raw {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

export interface Send {
  body?: unknown;
  /** Sent as application/x-www-form-urlencoded instead of a JSON `body`. */
  form?: Record<string, string>;
  headers?: Record<string, string>;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_RETRIES = 5;
const RETRYABLE = new Set([502, 503, 504]);

const backoff = (attempt: number) =>
  new Promise((ok) => setTimeout(ok, Math.random() * 40 * attempt));

export function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return undefined;
  }
}

export class Transport {
  readonly #baseUrl: string;
  readonly #credentials: Credentials;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #errors: TransportErrors;
  readonly #network = new WeakSet<Error>();
  readonly #onRequest: ClientOptions["onRequest"];
  readonly #onResponse: ClientOptions["onResponse"];

  constructor(
    options: ClientOptions,
    defaults: { timeoutMs: number; errors: TransportErrors },
  ) {
    const retries = options.maxRetries ?? 2;
    if (!Number.isInteger(retries) || retries < 0 || retries > MAX_RETRIES) {
      throw new RangeError(
        `maxRetries must be an integer from 0 to ${MAX_RETRIES}`,
      );
    }
    if (typeof options.credentials === "string" && options.credentials === "") {
      throw new TypeError("credentials must not be empty");
    }
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? defaults.timeoutMs;
    this.#maxRetries = retries;
    this.#errors = defaults.errors;
    this.#onRequest = options.onRequest;
    this.#onResponse = options.onResponse;
  }

  /** The parsed JSON of a 2xx response, or undefined when the body is not JSON. */
  async json(method: string, path: string, opts: Send = {}) {
    return parseJson((await this.raw(method, path, opts)).body);
  }

  /** Any 2xx response; retries idempotent requests on 502/503/504, timeouts and dropped connections. */
  async raw(method: string, path: string, opts: Send = {}): Promise<Raw> {
    const idempotent = method === "GET" || opts.idempotencyKey !== undefined;
    const attempts = idempotent ? this.#maxRetries + 1 : 1;
    for (let attempt = 1; ; attempt++) {
      const last = attempt === attempts;
      let res: Raw;
      try {
        res = await this.#once(method, path, opts, attempt);
      } catch (err) {
        if (last || opts.signal?.aborted || !this.#network.has(err as Error)) {
          throw err;
        }
        await backoff(attempt);
        continue;
      }
      if (res.status >= 200 && res.status < 300) return res;
      const err = this.#errors.api(res.status, res.body);
      if (
        last ||
        !RETRYABLE.has(res.status) ||
        (err.retryAfterSeconds ?? 0) > 1
      ) {
        throw err;
      }
      await backoff(attempt);
    }
  }

  /**
   * The response as soon as headers arrive, for the caller to read and bound itself: no
   * retries, no timeout (the caller's `signal` ends it), any status.
   */
  async stream(
    method: string,
    path: string,
    opts: Send = {},
  ): Promise<Response> {
    const sent = await this.#prepare(method, path, opts, 1);
    try {
      return await this.#send(sent, method, opts, opts.signal);
    } catch (cause) {
      throw this.#fail(
        cause,
        cause instanceof Error && cause.name === "TimeoutError",
      );
    }
  }

  async #once(
    method: string,
    path: string,
    opts: Send,
    attempt: number,
  ): Promise<Raw> {
    const sent = await this.#prepare(method, path, opts, attempt);
    const timeout = AbortSignal.timeout(this.#timeoutMs);
    const signal = opts.signal
      ? AbortSignal.any([opts.signal, timeout])
      : timeout;
    try {
      const res = await this.#send(sent, method, opts, signal);
      const chunks: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of res.body ?? []) {
        size += chunk.byteLength;
        if (size > MAX_RESPONSE_BYTES) throw new TooLarge();
        chunks.push(chunk);
      }
      return {
        status: res.status,
        headers: res.headers,
        body: Buffer.concat(chunks),
      };
    } catch (cause) {
      throw this.#fail(cause, timeout.aborted);
    }
  }

  async #prepare(method: string, path: string, opts: Send, attempt: number) {
    const url = this.#baseUrl + path;
    const token =
      typeof this.#credentials === "function"
        ? await this.#credentials()
        : this.#credentials;
    if (token === "") throw new TypeError("credentials must not be empty");
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      ...(opts.idempotencyKey
        ? { "idempotency-key": opts.idempotencyKey }
        : {}),
      ...(opts.form !== undefined
        ? { "content-type": "application/x-www-form-urlencoded" }
        : opts.body === undefined
          ? {}
          : { "content-type": "application/json" }),
      ...opts.headers,
    };
    await this.#onRequest?.({ method, url, attempt, headers });
    return { url, headers, attempt };
  }

  async #send(
    sent: { url: string; headers: Record<string, string>; attempt: number },
    method: string,
    opts: Send,
    signal: AbortSignal | undefined,
  ): Promise<Response> {
    const started = performance.now();
    const res = await this.#fetch(sent.url, {
      method,
      // Credentials must not follow a redirect to another host.
      redirect: "manual",
      ...(signal ? { signal } : {}),
      headers: sent.headers,
      ...(opts.form !== undefined
        ? { body: new URLSearchParams(opts.form).toString() }
        : opts.body === undefined
          ? {}
          : { body: JSON.stringify(opts.body) }),
    });
    await this.#onResponse?.({
      method,
      url: sent.url,
      attempt: sent.attempt,
      status: res.status,
      headers: res.headers,
      durationMs: performance.now() - started,
    });
    return res;
  }

  #fail(cause: unknown, timedOut: boolean): Error {
    // No `cause`: fetch's error can quote a header value, i.e. a token.
    const err =
      cause instanceof TooLarge
        ? this.#errors.tooLarge()
        : timedOut
          ? this.#errors.timeout(this.#timeoutMs)
          : this.#errors.unreachable(
              cause instanceof Error ? cause.name : "error",
            );
    this.#network.add(err);
    return err;
  }
}

class TooLarge extends Error {}
