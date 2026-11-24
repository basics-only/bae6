import type { Session } from "./session.js";

const PUBLIC_PATHS = new Set(["/login", "/signed-out", "/healthz"]);

export const isPublic = (pathname: string) => PUBLIC_PATHS.has(pathname);

export function loginRedirect(
  pathname: string,
  session: Session | null,
): string | null {
  return session || isPublic(pathname) ? null : "/login";
}

export function crossSiteMutation(
  method: string,
  origin: string | null,
  ownOrigin: string,
): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(method)) return false;
  return origin !== ownOrigin;
}
