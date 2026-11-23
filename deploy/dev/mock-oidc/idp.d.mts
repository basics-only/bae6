import type { IncomingMessage, ServerResponse } from "node:http";

export declare const GRAPH_AUDIENCE: string;
export interface MockIdpConfig {
  clients: { id: string; secret: string; redirectUris: string[] }[];
  realms: {
    kind: "entra" | "okta" | "ping";
    id: string;
    audience?: string;
    groupOverageLimit?: number;
    users: { login: string; sub: string; claims: Record<string, unknown> }[];
  }[];
}
export declare function validateConfig(config: MockIdpConfig): MockIdpConfig;
export declare function createIdp(options: {
  baseUrl: string;
  publicUrl?: string;
  config: MockIdpConfig;
}): Promise<{
  handle(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean>;
}>;
