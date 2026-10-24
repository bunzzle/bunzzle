import { describe, expect, test } from "bun:test";

const TABLES = [
  "api_keys",
  "domains",
  "messages",
  "jobs",
  "email_index",
  "stats_daily",
  "webhooks",
  "routes",
  "templates",
  "suppressions",
];

const REVIEWED: Record<string, { count: number; why: string }> = {
  "src/core/jobs.ts jobs": {
    count: 18,
    why: "queue engine: claims, settles, checks leases, sweeps by job id and wakes mail waiting on a node",
  },
  "src/core/jobs.ts messages": { count: 1, why: "claim loads the messages of jobs it leased" },
  "src/delivery/queue.ts jobs": {
    count: 7,
    why: "by message id after a project check, or retention and recipients of one job",
  },
  "src/delivery/queue.ts messages": { count: 3, why: "id lookups for intake and retention" },
  "src/queue/control.ts jobs": {
    count: 4,
    why: "suspensions of destinations; removal adds the project filter separately",
  },
  "src/queue/control.ts messages": {
    count: 1,
    why: "removal joins messages; the project filter is added separately",
  },
  "src/guards/guards.ts jobs": { count: 1, why: "bulk volume of one API key" },
  "src/guards/guards.ts messages": { count: 1, why: "bulk volume of one API key" },
  "src/webhooks/store.ts webhooks": {
    count: 2,
    why: "delivery of an already projected webhook; the resend worker runs queued jobs of every project",
  },
  "src/tracking/store.ts domains": {
    count: 3,
    why: "tracking of a domain after a project check, and the host list",
  },
  "src/inbound/routes.ts routes": { count: 2, why: "inbound mail finds its route by address" },
  "src/inbound/apply.ts jobs": { count: 1, why: "bounce and complaint of one sent message" },
  "src/accounts/api-keys.ts api_keys": { count: 3, why: "lookup by token hash or new key id" },
  "src/accounts/purge.ts jobs": {
    count: 2,
    why: "deletes children of the removed project's own messages",
  },
  "src/accounts/purge.ts email_index": {
    count: 1,
    why: "deletes children of the removed project's own messages",
  },
  "src/accounts/purge.ts messages": { count: 1, why: "deletes the removed project's own messages" },
  "src/emails/search.ts jobs": { count: 4, why: "search builds its project filter separately" },
  "src/emails/search.ts email_index": { count: 2, why: "search and stats of one message" },
  "src/emails/search.ts messages": { count: 2, why: "search builds its project filter separately" },
  "src/domains/domains.ts domains": {
    count: 4,
    why: "lookup by name for signing and inbound; the server-wide zone and its mode and slot flags by name",
  },
};

async function unscoped(): Promise<Record<string, number>> {
  const re = new RegExp(String.raw`\b(FROM|UPDATE|INTO|JOIN)\s+"?(${TABLES.join("|")})\b`, "g");
  const found: Record<string, number> = {};
  for (const file of [...new Bun.Glob("src/**/*.ts").scanSync(".")].sort()) {
    const text = await Bun.file(file).text();
    for (const lit of text.match(/`[^`]*`|"(?:[^"\\\n]|\\.)*"/g) ?? []) {
      if (!/\b(SELECT|UPDATE|INSERT|DELETE)\b/.test(lit) || lit.includes("project_id")) continue;
      for (const t of new Set([...lit.matchAll(re)].map((m) => m[2]))) {
        const k = `${file} ${t}`;
        found[k] = (found[k] ?? 0) + 1;
      }
    }
  }
  return found;
}

describe("project scope", () => {
  test("every query on a project table names project_id or is reviewed", async () => {
    const reviewed = Object.fromEntries(Object.entries(REVIEWED).map(([k, v]) => [k, v.count]));
    expect(await unscoped()).toEqual(reviewed);
  });
});
