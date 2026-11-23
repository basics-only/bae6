import { error, redirect } from "@sveltejs/kit";
import { ApiError, apiJson, apiMutation } from "./api";
import { AUDIENCES, authn, type Service, serviceUrl } from "./context";
import { type Session, tokenFor } from "./session";

function baseOf(service: Service): string {
  const url = serviceUrl(service);
  // A service this console is not set up for has no pages.
  if (!url) error(404, "Not found.");
  return url;
}

/** The user's token for one service; an ended session sends the user back to login. */
async function bearer(
  locals: { session: Session | null },
  service: Service,
): Promise<{ accessToken: string }> {
  if (!locals.session) redirect(303, "/login");
  const token = await tokenFor(
    authn(),
    locals.session.cookie,
    AUDIENCES[service],
  );
  if (!token) redirect(303, "/login");
  return { accessToken: token };
}

/**
 * Calls a service as the logged-in user. A rejected token sends the user back to login;
 * any other API refusal (403, 404, 409 ...) is shown with its own status.
 */
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

/**
 * Makes a change as the logged-in user. A refusal is returned, not thrown, so the form
 * can show it next to the input; the API decides, the console only reports.
 */
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
