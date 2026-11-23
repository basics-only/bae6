<script lang="ts">
  import { page } from "$app/state";
  import "../app.css";

  let { data, children } = $props();
  const here = (href: string) => page.url.pathname === href || page.url.pathname.startsWith(`${href}/`);
  const has = (service: string) => (data.services as string[]).includes(service);
  const groups = $derived(
    [
      {
        name: "Access",
        show: has("authz"),
        links: [
          ["/applications", "Applications"],
          ["/models", "Models"],
          ["/audit", "Audit log"],
          ["/explorer", "Access explorer"],
        ],
      },
      {
        name: "AI platform",
        show: ["ai", "evals", "agents", "mcp"].some(has),
        links: [
          has("ai") && ["/usage", "Usage"],
          has("ai") && ["/tags", "Task types"],
          has("ai") && ["/feedback", "Feedback"],
          has("evals") && ["/evals", "Eval runs"],
          has("agents") && ["/agents", "Agent runs"],
          has("mcp") && ["/mcp", "MCP servers"],
        ].filter(Boolean) as string[][],
      },
    ].filter((g) => g.show),
  );

  let signOutFailed = $state(false);
  async function signOut() {
    const csrf = document.cookie
      .split("; ")
      .find((c) => c.startsWith("__Host-bae6-csrf="))
      ?.slice("__Host-bae6-csrf=".length);
    const res = await fetch("/auth/logout", {
      method: "POST",
      headers: { "x-csrf-token": csrf ?? "" },
    }).catch(() => null);
    // 401: the session had already ended, which is the outcome asked for.
    if (res && (res.ok || res.status === 401)) location.assign("/signed-out");
    else signOutFailed = true;
  }
</script>

<svelte:head><title>bae6 console</title></svelte:head>

{#if data.subject}
  <div class="shell">
    <aside class="sidebar">
      <a class="brand" href="/">
        <img class="logo" src="/logo-square.jpg" alt="bae6 logo" />
        <span class="wordmark">bae6<span>.</span>console</span>
      </a>
      <nav aria-label="Main">
        {#each groups as group (group.name)}
          <div class="nav-group">{group.name}</div>
          {#each group.links as [href, label] (href)}
            <a class="nav" {href} aria-current={here(href) ? "page" : undefined}>{label}</a>
          {/each}
        {/each}
      </nav>
      <div class="account">
        <span class="who">{data.subject}</span>
        <button type="button" onclick={signOut}>Sign out</button>
        {#if signOutFailed}<span role="alert">Sign-out failed. Try again.</span>{/if}
      </div>
    </aside>
    <main class="content">{@render children()}</main>
  </div>
{:else}
  <main class="centered">{@render children()}</main>
{/if}
