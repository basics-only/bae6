const TIMEOUT_MS = 5000;

export function authnPlacements(config: { baseUrl: string; secret: string }) {
  const base = new URL(config.baseUrl);
  return {
    async place(input: {
      tenantId: string;
      principalId: string;
      orgPath: string[];
    }) {
      const res = await fetch(
        new URL(
          `/admin/principals/${encodeURIComponent(input.principalId)}/org-path`,
          base,
        ),
        {
          method: "PUT",
          headers: {
            authorization: `Bearer ${config.secret}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            tenantId: input.tenantId,
            orgPath: input.orgPath,
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        },
      );
      await res.body?.cancel();
      if (!res.ok)
        throw Object.assign(new Error(`authn answered ${res.status}`), {
          status: res.status,
        });
    },
  };
}
