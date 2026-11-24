import {
  type ClientOptions,
  type Principal,
  parseJson,
  Transport,
} from "@bae6/sdk-core";

export type AuthnOptions = ClientOptions;

const SUBJECT_TYPES = {
  session: "urn:bae6:params:oauth:token-type:session",
  jwt: "urn:ietf:params:oauth:token-type:jwt",
} as const;

export interface Token {
  accessToken: string;
  expiresIn: number;
}

export interface Me {
  principal: Principal;
  orgPath: string[];
}

export class AuthnError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class AuthnApiError extends AuthnError {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
  }
}

export class AuthnAuthError extends AuthnApiError {}

export class AuthnValidationError extends AuthnApiError {}

export class AuthnTransportError extends AuthnError {}

export class AuthnTimeoutError extends AuthnTransportError {}

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);

function httpError(status: number, bytes: Uint8Array): AuthnApiError {
  const parsed = parseJson(bytes);
  const body = isObject(parsed) ? parsed : {};
  const code = str(body.error) ?? str(body.code);
  const Err =
    status === 400
      ? AuthnValidationError
      : status === 401 || status === 403
        ? AuthnAuthError
        : AuthnApiError;
  return new Err(
    status,
    code,
    `authn returned HTTP ${status}${code ? ` (${code})` : ""}`,
  );
}

const PRINCIPAL_TYPES = new Set([
  "user",
  "group",
  "service",
  "application",
  "agent",
]);
const PRINCIPAL_STATUSES = new Set(["active", "disabled", "deprovisioned"]);

const isPrincipal = (v: unknown): v is Json =>
  isObject(v) &&
  typeof v.id === "string" &&
  typeof v.tenantId === "string" &&
  PRINCIPAL_TYPES.has(v.type as string) &&
  PRINCIPAL_STATUSES.has(v.status as string);

const invalidResponse = () =>
  new AuthnApiError(
    200,
    "invalid_response",
    "authn returned an unusable response",
  );

export class Authn {
  readonly #http: Transport;

  constructor(options: AuthnOptions) {
    this.#http = new Transport(options, {
      timeoutMs: 5000,
      errors: {
        timeout: (ms) =>
          new AuthnTimeoutError(`authn did not answer within ${ms} ms`),
        unreachable: (name) =>
          new AuthnTransportError(`could not reach authn (${name})`),
        tooLarge: () =>
          new AuthnTransportError("the authn response is too large"),
        api: httpError,
      },
    });
  }

  async exchangeToken(input: {
    subjectToken: string;
    subjectTokenType: keyof typeof SUBJECT_TYPES;
    audience: string;
  }): Promise<Token> {
    if (!Object.hasOwn(SUBJECT_TYPES, input.subjectTokenType)) {
      throw new TypeError('subjectTokenType must be "session" or "jwt"');
    }
    const body = await this.#http.json("POST", "/auth/token", {
      form: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: input.subjectToken,
        subject_token_type: SUBJECT_TYPES[input.subjectTokenType],
        audience: input.audience,
      },
    });
    if (
      !isObject(body) ||
      typeof body.access_token !== "string" ||
      body.token_type !== "Bearer" ||
      !Number.isInteger(body.expires_in) ||
      (body.expires_in as number) < 1
    ) {
      throw invalidResponse();
    }
    return {
      accessToken: body.access_token,
      expiresIn: body.expires_in as number,
    };
  }

  async me(token: string): Promise<Me> {
    if (token === "") throw new TypeError("token must not be empty");
    const body = await this.#http.json("GET", "/auth/me", {
      headers: { authorization: `Bearer ${token}` },
    });
    if (
      !isObject(body) ||
      !isPrincipal(body.principal) ||
      !Array.isArray(body.orgPath) ||
      body.orgPath.length < 1 ||
      body.orgPath.length > 32 ||
      !body.orgPath.every((p) => typeof p === "string")
    ) {
      throw invalidResponse();
    }
    return {
      principal: body.principal as unknown as Principal,
      orgPath: body.orgPath,
    };
  }

  async placePrincipal(input: {
    tenantId: string;
    principalId: string;
    orgPath: string[];
  }): Promise<string[]> {
    const body = await this.#http.json(
      "PUT",
      `/admin/principals/${encodeURIComponent(input.principalId)}/org-path`,
      { body: { tenantId: input.tenantId, orgPath: input.orgPath } },
    );
    if (
      !isObject(body) ||
      !Array.isArray(body.orgPath) ||
      !body.orgPath.every((p) => typeof p === "string")
    ) {
      throw invalidResponse();
    }
    return body.orgPath;
  }
}
