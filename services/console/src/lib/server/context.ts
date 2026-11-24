import { readFile, stat } from "node:fs/promises";
import { Authn } from "@bae6/authn";
import { env } from "$env/dynamic/private";
import { tokenCache } from "./session";

function required(name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

/** Set by authn, which serves `/auth/*` on the console's own host. */
export const SESSION_COOKIE = "__Host-bae6-session";

export const SERVICES = {
  authz: "BAE6_AUTHZ_URL",
  ai: "BAE6_AI_URL",
  evals: "BAE6_EVAL_URL",
  agents: "BAE6_AGENT_URL",
  mcp: "BAE6_MCP_REGISTRY_URL",
} as const;
export type Service = keyof typeof SERVICES;

/** The audience authn mints each service's tokens for. */
export const AUDIENCES: Record<Service, string> = {
  authz: "bae6-authz",
  ai: "bae6-ai",
  evals: "eval-worker",
  agents: "agent-worker",
  mcp: "mcp-registry",
};

/** The base URL of a service, or null when this console is not set up for it. */
export const serviceUrl = (service: Service): string | null =>
  env[SERVICES[service]]?.replace(/\/$/, "") || null;

export const configuredServices = () =>
  (Object.keys(SERVICES) as Service[]).filter((s) => serviceUrl(s));

let serviceTokens: ReturnType<typeof tokenCache> | undefined;
export function serviceToken(cookie: string, audience: string) {
  serviceTokens ??= tokenCache(authn());
  return serviceTokens(cookie, audience);
}

let client: Authn | undefined;
export function authn(): Authn {
  client ??= new Authn({
    baseUrl: required("BAE6_AUTHN_URL"),
    // Read on every call so a rotated secret is picked up without a restart.
    credentials: async () => {
      const path = required("BAE6_AUTHN_CLIENT_SECRET_FILE");
      if ((await stat(path)).size > 8192)
        throw new Error("BAE6_AUTHN_CLIENT_SECRET_FILE is too large");
      return (await readFile(path, "utf8")).trim();
    },
  });
  return client;
}
