import { error, redirect } from "@sveltejs/kit";
import { ApiError, apiJson, apiMutation } from "./api";
import { AUDIENCES, type Service, serviceToken, serviceUrl } from "./context";
import type { Session } from "./session";

function baseOf(service: Service): string {
  const url = serviceUrl(service);
  if (!url) error(404, "Not found.");
  return url;
}

async function bearer(
  locals: { session: Session | null },
  service: Service,
): Promise<{ accessToken: string }> {
  if (!locals.session) redirect(303, "/login");
  const token = await serviceToken(locals.session.cookie, AUDIENCES[service]);
  if (!token) redirect(303, "/login");
  return { accessToken: token };
}

export async function callApi<T>(
  locals: { session: Session | null },
  path: string,
  init?: { method?: string; body?: unknown },
  service: Service = "authz",
): Promise<T> {
  const base = baseOf(service);
  const token = await bearer(locals, service);
  try {
    return await apiJson<T>(base, token, path, init);
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) redirect(303, "/login");
      error(err.status, err.message);
    }
    throw err;
  }
}

export async function mutate(
  locals: { session: Session | null },
  path: string,
  init: { method: string; body?: unknown },
  service: Service = "authz",
): Promise<
  | { ok: true; auditEventId: string | null; body: unknown }
  | { ok: false; status: number; message: string }
> {
  const base = baseOf(service);
  const token = await bearer(locals, service);
  try {
    return {
      ok: true,
      ...(await apiMutation(base, token, path, init)),
    };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) redirect(303, "/login");
      return { ok: false, status: err.status, message: err.message };
    }
    throw err;
  }
}
