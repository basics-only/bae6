<script lang="ts">
  import { onMount } from "svelte";

  type Provider = { id: string; displayName: string };
  let providers = $state<Provider[] | null>(null);
  let failed = $state(false);

  onMount(async () => {
    try {
      const res = await fetch("/auth/providers");
      if (!res.ok) throw new Error(`authn returned ${res.status}`);
      providers = ((await res.json()) as { providers: Provider[] }).providers;
    } catch {
      failed = true;
    }
  });
</script>

<div class="page-head">
  <h1>Sign in</h1>
</div>
{#if failed}
  <p role="alert">Sign-in is unavailable right now. Try again shortly.</p>
{:else if providers?.length === 0}
  <p>No identity provider is set up for this organization.</p>
{:else if providers}
  <ul>
    {#each providers as p (p.id)}
      <li>
        <a href={`/auth/login/${encodeURIComponent(p.id)}?returnTo=/`} data-sveltekit-reload>
          Continue with {p.displayName}
        </a>
      </li>
    {/each}
  </ul>
{/if}
