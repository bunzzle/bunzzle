import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { rotation } from "./core-rotation.ts";

const HOUR = 3_600_000;
const DOMAIN_EVERY_MS = 6 * HOUR;
const DOMAIN_RETRY_MS = HOUR;
const RUNS_TO_CHANGE = 2;

type Raise = (kind: string, data: Record<string, unknown>) => Promise<void>;

export interface ListingView {
  ip: string;
  list: string;
  listed: boolean;
}

export interface DomainView {
  domain: string;
  problems: string[];
  alerted: boolean;
  checkedAt: number;
}

export interface WatchView {
  listings: ListingView[];
  domains: DomainView[];
}

interface IpListings {
  ip: string;
  listings?: { list: string; name: string; status: string; removal: string | null }[] | null;
}

function lastEvents(
  db: Database,
  kinds: [string, string],
  key: (d: Record<string, unknown>) => string,
) {
  const out = new Map<string, boolean>();
  const rows = db
    .query<{ kind: string; data: string }, [string, string]>(
      "SELECT kind, data FROM admin_events WHERE kind IN (?, ?) ORDER BY id",
    )
    .all(...kinds);
  for (const r of rows)
    out.set(key(JSON.parse(r.data) as Record<string, unknown>), r.kind === kinds[0]);
  return out;
}

export function listingWatch(deps: { db: Database; raise: Raise; log: Logger }) {
  let known: Map<string, boolean> | null = null;
  let view: ListingView[] = [];
  const keyOf = (ip: string, list: string) => `${ip} ${list}`;
  const update = async (ips: IpListings[]) => {
    known ??= lastEvents(deps.db, ["ip.listed", "ip.delisted"], (d) =>
      keyOf(String(d["ip"]), String(d["list"])),
    );
    const next: ListingView[] = [];
    for (const { ip, listings } of ips) {
      for (const l of listings ?? []) {
        const key = keyOf(ip, l.list);
        const was = known.get(key) ?? false;
        if (l.status === "unusable") {
          next.push({ ip, list: l.list, listed: was });
          continue;
        }
        const listed = l.status === "listed";
        next.push({ ip, list: l.list, listed });
        if (listed === was) continue;
        known.set(key, listed);
        const data = { ip, list: l.list, name: l.name, removal: l.removal };
        if (listed) deps.log.warn("a sending IP was listed", data);
        else deps.log.info("a sending IP is no longer listed", data);
        await deps.raise(listed ? "ip.listed" : "ip.delisted", data);
      }
    }
    view = next;
  };
  return { update, view: () => view };
}

export interface DomainWatchDeps {
  db: Database;
  domains: () => string[];
  problems: (domain: string) => Promise<string[] | null>;
  raise: Raise;
  log: Logger;
  now?: () => number;
}

export function domainWatch(deps: DomainWatchDeps) {
  const now = deps.now ?? Date.now;
  let alerted: Map<string, boolean> | null = null;
  const state = new Map<
    string,
    { problems: string[]; bad: number; good: number; checkedAt: number }
  >();
  const tick = async () => {
    alerted ??= lastEvents(deps.db, ["domain.dns_problem", "domain.dns_ok"], (d) =>
      String(d["domain"]),
    );
    const names = deps.domains();
    for (const name of state.keys()) if (!names.includes(name)) state.delete(name);
    for (const domain of names) {
      const s = state.get(domain);
      const at = now();
      const due = !s || at - s.checkedAt >= (s.bad > 0 ? DOMAIN_RETRY_MS : DOMAIN_EVERY_MS);
      if (!due) continue;
      const problems = await deps.problems(domain).catch(() => null);
      if (problems === null) continue;
      const bad = problems.length > 0;
      const next = {
        problems,
        bad: bad ? (s?.bad ?? 0) + 1 : 0,
        good: bad ? 0 : (s?.good ?? 0) + 1,
        checkedAt: at,
      };
      state.set(domain, next);
      const was = alerted.get(domain) ?? false;
      if (!was && next.bad >= RUNS_TO_CHANGE) {
        alerted.set(domain, true);
        deps.log.error("a sending domain's DNS records are wrong", { domain, problems });
        await deps.raise("domain.dns_problem", { domain, problems });
      } else if (was && next.good >= RUNS_TO_CHANGE) {
        alerted.set(domain, false);
        deps.log.info("a sending domain's DNS records are correct again", { domain });
        await deps.raise("domain.dns_ok", { domain });
      }
    }
  };
  const view = (): DomainView[] =>
    [...state].map(([domain, s]) => ({
      domain,
      problems: s.problems,
      alerted: alerted?.get(domain) ?? false,
      checkedAt: s.checkedAt,
    }));
  return { tick, view };
}

export async function domainProblems(
  r: Pick<ReturnType<typeof rotation>, "inspect" | "keys" | "selfCheck">,
  domain: string,
): Promise<string[] | null> {
  const d = await r.inspect(domain, await r.keys(domain));
  if (!d) return null;
  const problems = d.records
    .filter((x) => x.required && x.status !== "verified")
    .map((x) => `${x.type} ${x.name} is ${x.status === "mismatch" ? "wrong" : "missing"}`);
  const check = await r.selfCheck(domain, "active");
  if (!check.ok) {
    problems.push(
      `DKIM signatures do not verify: ${check.results.map((x) => `${x.selector}: ${x.reason ?? "ok"}`).join("; ")}`,
    );
  }
  return problems;
}
