import { render, screen } from "@testing-library/svelte";
import { afterEach, expect, test, vi } from "vitest";
import Page from "./+page.svelte";

afterEach(() => vi.unstubAllGlobals());

test("each of the tenant's providers starts an authn login", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({
        providers: [{ id: "entra/main", kind: "entra", displayName: "Entra" }],
      }),
    ),
  );
  render(Page);
  expect(
    await screen.findByRole("link", { name: "Continue with Entra" }),
  ).toHaveAttribute("href", "/auth/login/entra%2Fmain?returnTo=/");
});

test("an authn outage says sign-in is unavailable", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(null, { status: 503 })),
  );
  render(Page);
  expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
});
