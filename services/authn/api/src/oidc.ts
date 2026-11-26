import * as oidc from "openid-client";

const TIMEOUT_SECONDS = 5;
const DEFAULT_SCOPES = ["openid", "profile", "email"];
const LOGIN_HINT = /^[^\p{Cc}]{1,256}$/u;

export interface ProviderConnection {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

export interface PendingLogin {
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface VerifiedLogin {
  identity: {
    issuer: string;
    subject: string;
    claims: Readonly<Record<string, unknown>>;
  };
  providerAccessToken: string;
  providerAccessTokenExpiresAt: Date | undefined;
}

export type OidcErrorCode =
  | "invalid_request"
  | "discovery_failed"
  | "provider_denied"
  | "provider_unavailable"
  | "provider_misconfigured"
  | "invalid_callback";

function classify(err: unknown): OidcErrorCode {
  if (err instanceof oidc.AuthorizationResponseError) return "provider_denied";
  if (err instanceof oidc.WWWAuthenticateChallengeError)
    return err.status >= 500
      ? "provider_unavailable"
      : "provider_misconfigured";
  if (err instanceof oidc.ResponseBodyError) {
    if (err.error === "invalid_client" || err.error === "unauthorized_client")
      return "provider_misconfigured";
    if (err.status >= 500) return "provider_unavailable";
    return "invalid_callback";
  }
  const status = (err as { cause?: { status?: unknown } }).cause?.status;
  if (typeof status === "number" && status >= 500)
    return "provider_unavailable";
  const name = (err as Error).name;
  if (
    err instanceof TypeError ||
    name === "AbortError" ||
    name === "TimeoutError"
  )
    return "provider_unavailable";
  return "invalid_callback";
}

const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

function oboFailure(err: unknown): OidcErrorCode {
  const code = classify(err);
  return code === "invalid_callback" ? "provider_misconfigured" : code;
}

export class OidcError extends Error {
  constructor(
    readonly code: OidcErrorCode,
    options?: ErrorOptions,
  ) {
    super(code, options);
  }
}

export class OidcProvider {
  private constructor(
    private readonly config: oidc.Configuration,
    private readonly connection: ProviderConnection,
  ) {}

  static async discover(
    connection: ProviderConnection,
    { allowHttp = false }: { allowHttp?: boolean } = {},
  ): Promise<OidcProvider> {
    let config: oidc.Configuration;
    try {
      config = await oidc.discovery(
        new URL(connection.issuer),
        connection.clientId,
        undefined,
        oidc.ClientSecretBasic(connection.clientSecret),
        {
          timeout: TIMEOUT_SECONDS,
          // Without non-repudiation checks openid-client never verifies the ID token's signature.
          execute: [
            oidc.enableNonRepudiationChecks,
            ...(allowHttp ? [oidc.allowInsecureRequests] : []),
          ],
        },
      );
    } catch (err) {
      throw new OidcError("discovery_failed", { cause: err });
    }
    return new OidcProvider(config, connection);
  }

  get jwksUri(): string | undefined {
    return this.config.serverMetadata().jwks_uri;
  }

  async beginLogin(
    options: { loginHint?: string } = {},
  ): Promise<{ url: URL; pending: PendingLogin }> {
    if (options.loginHint !== undefined && !LOGIN_HINT.test(options.loginHint))
      throw new OidcError("invalid_request");
    const scopes = new Set([
      "openid",
      ...(this.connection.scopes ?? DEFAULT_SCOPES),
    ]);
    const pending = {
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      codeVerifier: oidc.randomPKCECodeVerifier(),
    };
    const url = oidc.buildAuthorizationUrl(this.config, {
      redirect_uri: this.connection.redirectUri,
      response_type: "code",
      scope: [...scopes].join(" "),
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(
        pending.codeVerifier,
      ),
      code_challenge_method: "S256",
      ...(options.loginHint ? { login_hint: options.loginHint } : {}),
    });
    return { url, pending };
  }

  async clientCredentials(scope: string): Promise<string> {
    try {
      return (await oidc.clientCredentialsGrant(this.config, { scope }))
        .access_token;
    } catch (err) {
      throw new OidcError(classify(err), { cause: err });
    }
  }

  async onBehalfOf(
    assertion: string,
    scope: string,
  ): Promise<{ accessToken: string; expiresAt: Date | undefined }> {
    let tokens: oidc.TokenEndpointResponse;
    try {
      tokens = await oidc.genericGrantRequest(this.config, JWT_BEARER, {
        assertion,
        scope,
        requested_token_use: "on_behalf_of",
      });
    } catch (err) {
      const denied =
        err instanceof oidc.ResponseBodyError &&
        err.status < 500 &&
        [
          "invalid_grant",
          "invalid_request",
          "interaction_required",
          "consent_required",
        ].includes(err.error);
      throw new OidcError(denied ? "provider_denied" : oboFailure(err), {
        cause: err,
      });
    }
    return {
      accessToken: tokens.access_token,
      expiresAt:
        tokens.expires_in === undefined
          ? undefined
          : new Date(Date.now() + tokens.expires_in * 1000),
    };
  }

  // The callback URL is rebuilt from the configured redirect URI, never the request's Host.
  async completeLogin(
    query: URLSearchParams,
    pending: PendingLogin,
  ): Promise<VerifiedLogin> {
    const callback = new URL(this.connection.redirectUri);
    callback.search = query.toString();
    let tokens: Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>;
    try {
      tokens = await oidc.authorizationCodeGrant(this.config, callback, {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
        idTokenExpected: true,
      });
    } catch (err) {
      throw new OidcError(classify(err), { cause: err });
    }
    const claims = tokens.claims();
    if (!claims) throw new OidcError("invalid_callback");
    return {
      identity: { issuer: claims.iss, subject: claims.sub, claims },
      providerAccessToken: tokens.access_token,
      providerAccessTokenExpiresAt:
        tokens.expires_in === undefined
          ? undefined
          : new Date(Date.now() + tokens.expires_in * 1000),
    };
  }
}
