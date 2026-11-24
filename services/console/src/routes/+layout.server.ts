import { configuredServices } from "$lib/server/context";
import type { LayoutServerLoad } from "./$types";

export const load: LayoutServerLoad = ({ locals }) => ({
  subject: locals.session?.subject ?? null,
  services: configuredServices(),
});
