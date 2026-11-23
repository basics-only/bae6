import { appendFileSync } from "node:fs";
import { ORGS, orgIssuer } from "../orgs/orgs.mjs";

// spike runs low, very high, then low again, so the last row shows recovery.
const PROFILES = {
  smoke: { levels: [1, 4], seconds: 10 },
  average: { levels: [16, 64], seconds: 30 },
  stress: { levels: [64, 256, 512], seconds: 30 },
  spike: { levels: [4, 1024, 4], seconds: 15 },
  soak: { levels: [64], seconds: 600 },
};
const profileName = process.env.LOAD_PROFILE ?? "smoke";
const profile = PROFILES[profileName];
if (!profile) {
  throw new Error(`LOAD_PROFILE must be one of ${Object.keys(PROFILES)}`);
}
const seconds = Number(process.env.LOAD_SECONDS || profile.seconds);
if (!(seconds > 0 && seconds <= 600)) {
  throw new Error("LOAD_SECONDS must be between 1 and 600");
}
const levels = process.env.LOAD_CONCURRENCY
  ? process.env.LOAD_CONCURRENCY.split(",").map(Number)
  : profile.levels;
if (levels.some((n) => !Number.isInteger(n) || n < 1 || n > 1024)) {
  throw new Error("LOAD_CONCURRENCY must be integers between 1 and 1024");
}
const orgCount = Number(process.env.LOAD_ORGS ?? ORGS.length);
if (!Number.isInteger(orgCount) || orgCount < 1 || orgCount > ORGS.length) {
  throw new Error(`LOAD_ORGS must be between 1 and ${ORGS.length}`);
}
const orgs = ORGS.slice(0, orgCount);
const requestTimeoutMs = 10_000;
const oidc = "http://127.0.0.1:8085";

async function token(issuer, sub, aud, scope) {
  const res = await fetch(`${issuer}/token`, {
    method: "POST",
    body: JSON.stringify({ sub, aud, scope, ttlSeconds: 3600 }),
  });
  if (!res.ok) throw new Error(`token ${aud}: ${res.status}`);
  return (await res.json()).access_token;
}

// Users are spread round-robin over the organizations. Search stays on the example
// organization because each embed deployment serves exactly one organization.
const userTokens = async (i) => {
  const org = orgs[i % orgs.length];
  const issuer = orgIssuer(oidc, org);
  return {
    org,
    data: await token(issuer, `load-${i}`, "bae6-context-data", "data:read"),
    ai: await token(issuer, `load-${i}`, "bae6-ai", "ai:invoke"),
    embed: await token(oidc, `load-${i}`, "bae6-context-embed", "embed:read"),
  };
};
const endUser = await token(oidc, "alice", "bae6-context-embed", "");

const json = { "content-type": "application/json" };
const signal = () => AbortSignal.timeout(requestTimeoutMs);
const scenarios = {
  chat: (t) =>
    fetch("http://127.0.0.1:8081/v1/chat/completions", {
      method: "POST",
      headers: { authorization: `Bearer ${t.ai}`, ...json },
      body: JSON.stringify({
        model: "chat-mock",
        messages: [{ role: "user", content: "hello" }],
      }),
      signal: signal(),
    }),
  search: (t) =>
    fetch("http://127.0.0.1:8083/v1/collections/kb/search", {
      method: "POST",
      headers: {
        authorization: `Bearer ${t.embed}`,
        "bae6-end-user-token": endUser,
        ...json,
      },
      body: JSON.stringify({ query: "expense reimbursement", limit: 5 }),
      signal: signal(),
    }),
  read: (t) =>
    fetch(
      `http://127.0.0.1:8082/v1/sources/docs/objects/content?key=${t.org}/handbook.txt`,
      {
        headers: { authorization: `Bearer ${t.data}` },
        signal: signal(),
      },
    ),
};

const pct = (sorted, p) =>
  sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] ?? null;

async function once(run, t) {
  const start = performance.now();
  try {
    const res = await run(t);
    await res.arrayBuffer();
    return { status: res.status, ms: performance.now() - start };
  } catch (e) {
    return { status: `error:${e.name}`, ms: performance.now() - start };
  }
}

const users = [];
for (let i = 0; i < Math.max(...levels); i += 64) {
  const batch = Array.from(
    { length: Math.min(64, Math.max(...levels) - i) },
    (_, j) => userTokens(i + j),
  );
  users.push(...(await Promise.all(batch)));
}

const results = [];
for (const concurrency of levels) {
  for (const [name, run] of Object.entries(scenarios)) {
    const ok = [];
    let requests = 0;
    const statuses = {};
    const started = performance.now();
    const end = Date.now() + seconds * 1000;
    await Promise.all(
      users.slice(0, concurrency).map(async (t) => {
        while (Date.now() < end) {
          const { status, ms } = await once(run, t);
          requests++;
          statuses[status] = (statuses[status] ?? 0) + 1;
          if (status === 200) ok.push(ms);
        }
      }),
    );
    const elapsed = (performance.now() - started) / 1000;
    ok.sort((a, b) => a - b);
    const result = {
      profile: profileName,
      scenario: name,
      orgs: name === "search" ? 1 : orgs.length,
      concurrency,
      requests,
      rps: Math.round(requests / elapsed),
      okRps: Math.round(ok.length / elapsed),
      okP50ms: Math.round(pct(ok, 0.5)),
      okP95ms: Math.round(pct(ok, 0.95)),
      okP99ms: Math.round(pct(ok, 0.99)),
      statuses,
    };
    results.push(result);
    console.log(JSON.stringify(result));
  }
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const rows = results.map(
    (r) =>
      `| ${r.scenario} | ${r.orgs} | ${r.concurrency} | ${r.requests} | ${r.okRps} | ${r.okP50ms} / ${r.okP95ms} / ${r.okP99ms} | ${Object.entries(
        r.statuses,
      )
        .map(([s, n]) => `${n} x ${s}`)
        .join(", ")} |`,
  );
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    [
      `### Load profile ${profileName}: ${seconds}s per row, latency of 200s only`,
      "| Scenario | Orgs | Users | Requests | ok rps | p50 / p95 / p99 ms | Statuses |",
      "|---|---|---|---|---|---|---|",
      ...rows,
      "",
    ].join("\n"),
  );
}
