import type { Config } from "../config.ts";
import { RpcClient, RpcError } from "../ipc/rpc.ts";
import { sockets } from "../roles/wire.ts";
import { parseArgs, UsageError } from "./args.ts";

interface DomainRecordView {
  record: string;
  name: string;
  value: string;
  required: boolean;
  status: string;
  found: string | null;
}

interface DomainView {
  name: string;
  status: string;
  records: DomainRecordView[];
}

const SYSTEM_RUN_DIR = "/run/bunzzle";

async function runDirOf(config: Config): Promise<string> {
  if (process.env["BUNZZLE_RUN_DIR"]) return config.runDir;
  const system = sockets(SYSTEM_RUN_DIR).core;
  const isSocket = await Bun.file(system)
    .stat()
    .then((s) => s.isSocket())
    .catch(() => false);
  return isSocket ? SYSTEM_RUN_DIR : config.runDir;
}

async function call<T>(config: Config, method: string, params: unknown): Promise<T> {
  const runDir = await runDirOf(config);
  const core = new RpcClient(sockets(runDir).core);
  try {
    return await core.call<T>(method, params, { timeoutMs: 60_000 });
  } catch (err) {
    if (err instanceof RpcError && err.code === "unavailable") {
      throw new UsageError(
        `cannot reach Bunzzle at ${runDir}/core.sock: is \`bunzzle serve\` running (same BUNZZLE_RUN_DIR)?`,
      );
    }
    if (err instanceof RpcError && (err.code === "invalid" || err.code === "not-found")) {
      throw new UsageError(err.message);
    }
    throw err;
  } finally {
    core.close();
  }
}

const mark = (status: string) =>
  status === "verified" ? "ok" : status === "not_started" ? "--" : status.toUpperCase();

function printDomain(d: DomainView) {
  console.log(`${d.name}: ${d.status}\n`);
  for (const r of d.records) {
    console.log(
      `[${mark(r.status)}] ${r.record}${r.required ? "" : " (recommended)"}  TXT  ${r.name}`,
    );
    console.log(`     ${r.value}`);
    if (r.status === "mismatch" && r.found) console.log(`     found instead: ${r.found}`);
  }
  if (d.status !== "verified") {
    console.log(
      "\nAdd the TXT records above at your DNS provider, then run `bunzzle domains verify` (Bunzzle also checks every few minutes).",
    );
  }
}

export async function domainsCommand(argv: string[], config: Config) {
  const [sub, name, ...rest] = argv;
  if (rest.length > 0) throw new UsageError(`unexpected argument: ${rest[0]}`);
  switch (sub) {
    case "add":
      if (!name) throw new UsageError("usage: bunzzle domains add DOMAIN");
      return printDomain(await call<DomainView>(config, "addDomain", { name }));
    case "verify":
      if (!name) throw new UsageError("usage: bunzzle domains verify DOMAIN");
      return printDomain(await call<DomainView>(config, "verifyDomain", { name }));
    case "show":
      if (!name) throw new UsageError("usage: bunzzle domains show DOMAIN");
      return printDomain(await call<DomainView>(config, "getDomain", { name }));
    case "rotate": {
      if (!name) throw new UsageError("usage: bunzzle domains rotate DOMAIN");
      const r = await call<{ result: string }>(config, "rotateDomain", { name });
      console.log(`${name}: ${r.result}`);
      return printDomain(await call<DomainView>(config, "getDomain", { name }));
    }
    case "list": {
      const all = await call<DomainView[]>(config, "listDomains", {});
      if (all.length === 0)
        console.log("No domains yet. Add one with `bunzzle domains add DOMAIN`.");
      for (const d of all) console.log(`${d.status.padEnd(9)} ${d.name}`);
      return;
    }
    default:
      throw new UsageError("usage: bunzzle domains add|verify|show|rotate|list");
  }
}

interface PathChange {
  at: string;
  change: string;
  reason: string;
  rate_per_sec: number;
  connections: number;
}

interface PathView {
  destination: string;
  source: string;
  state: string;
  until: string | null;
  rate_per_sec: number;
  connections: number;
  ceiling: { rate_per_sec: number; connections: number };
  in_flight: number;
  waiting: { transactional: number; bulk: number };
  delivered: number;
  changes: PathChange[];
}

export async function pathsCommand(argv: string[], config: Config) {
  if (argv.length > 0) throw new UsageError("usage: bunzzle paths");
  const paths = await call<PathView[]>(config, "paths", {});
  if (paths.length === 0) console.log("No paths yet: nothing has been sent since Bunzzle started.");
  for (const p of paths) {
    const until = p.until ? ` until ${p.until}` : "";
    console.log(
      `${p.source} → ${p.destination}: ${p.state}${until}, ${p.rate_per_sec}/s of ${p.ceiling.rate_per_sec}, ${p.connections} of ${p.ceiling.connections} connections, ${p.in_flight} sending, waiting ${p.waiting.transactional} transactional + ${p.waiting.bulk} bulk, ${p.delivered} delivered`,
    );
    for (const c of p.changes.slice(-5)) {
      console.log(
        `    ${c.at}  ${c.change.padEnd(12)} → ${c.rate_per_sec}/s, ${c.connections} conn  ${c.reason}`,
      );
    }
  }
}

export async function webhooksCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "add": {
      const [url, ...flags] = rest;
      if (!url) throw new UsageError("usage: bunzzle webhooks add URL [--event TYPE]...");
      const args = parseArgs(flags, { lists: ["event"] });
      const events = args.lists.get("event");
      const h = await call<{
        id: string;
        endpoint: string;
        events: string[];
        signing_secret: string;
      }>(config, "createWebhook", { url, ...(events ? { events } : {}) });
      console.log(`Webhook ${h.id} → ${h.endpoint}`);
      console.log(`Events: ${h.events.join(", ")}`);
      console.log(`Signing secret (Standard Webhooks format): ${h.signing_secret}`);
      return;
    }
    case "list": {
      const hooks = await call<{ id: string; endpoint: string; events: string[] }[]>(
        config,
        "listWebhooks",
        {},
      );
      if (hooks.length === 0)
        console.log("No webhooks yet. Add one with `bunzzle webhooks add URL`.");
      for (const h of hooks) console.log(`${h.id}  ${h.endpoint}  (${h.events.join(", ")})`);
      return;
    }
    case "remove": {
      const id = rest[0];
      if (!id) throw new UsageError("usage: bunzzle webhooks remove ID");
      await call(config, "deleteWebhook", { id });
      console.log(`Removed ${id}.`);
      return;
    }
    default:
      throw new UsageError("usage: bunzzle webhooks add|list|remove");
  }
}

export async function suppressionsCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "list": {
      const list = await call<
        { email: string; scope: string; reason: string; expires_at: string | null }[]
      >(config, "listSuppressions", {});
      if (list.length === 0) console.log("No suppressed addresses.");
      for (const s of list) {
        console.log(
          `${s.email}  ${s.scope.padEnd(4)}  ${s.reason}${s.expires_at ? `  until ${s.expires_at}` : ""}`,
        );
      }
      return;
    }
    case "add":
    case "remove": {
      const [email, ...flags] = rest;
      if (!email)
        throw new UsageError(`usage: bunzzle suppressions ${sub} EMAIL [--scope all|bulk]`);
      const scope = parseArgs(flags, { strings: ["scope"] }).strings.get("scope");
      if (scope && scope !== "all" && scope !== "bulk")
        throw new UsageError("--scope must be all or bulk");
      await call(config, sub === "add" ? "addSuppression" : "removeSuppression", {
        email,
        ...(scope ? { scope } : {}),
      });
      console.log(sub === "add" ? `Suppressed ${email}.` : `Removed ${email} from suppressions.`);
      return;
    }
    default:
      throw new UsageError("usage: bunzzle suppressions list|add|remove");
  }
}

interface DoctorView {
  checks: { area: string; item: string; status: "ok" | "warn" | "fail"; detail: string }[];
  summary: { ok: number; warn: number; fail: number };
}

export async function doctorCommand(argv: string[], config: Config): Promise<number> {
  if (argv.length > 0) throw new UsageError("usage: bunzzle doctor");
  const v = await call<DoctorView>(config, "doctor", {});
  let area = "";
  for (const c of v.checks) {
    if (c.area !== area) {
      area = c.area;
      console.log(`\n${area}`);
    }
    const mark = c.status === "ok" ? "[ok]  " : c.status === "warn" ? "[warn]" : "[FAIL]";
    console.log(`  ${mark} ${c.item}: ${c.detail}`);
  }
  console.log(`\n${v.summary.ok} ok, ${v.summary.warn} warnings, ${v.summary.fail} problems`);
  return v.summary.fail > 0 ? 1 : 0;
}

interface IpView {
  ip: string;
  pool: string;
  ehlo: string | null;
  reverse_dns_ok: boolean;
  reverse_dns_problem: string | null;
  warmup:
    | { state: "established" }
    | {
        state: string;
        providers: {
          provider: string;
          state: string;
          day: number;
          of_about: number;
          budget_today: number;
          sent_today: number;
        }[];
      };
}

export async function ipsCommand(argv: string[], config: Config) {
  if (argv.length > 0) throw new UsageError("usage: bunzzle ips");
  const ips = await call<IpView[]>(config, "ips", {});
  if (ips.length === 0) {
    console.log(
      "No source IPs configured: the system picks one. Set BUNZZLE_SOURCE_IPS to manage IPs.",
    );
  }
  for (const ip of ips) {
    const dns = ip.reverse_dns_ok
      ? `reverse DNS ok (${ip.ehlo})`
      : `reverse DNS: ${ip.reverse_dns_problem}`;
    console.log(`${ip.ip}  pool ${ip.pool}  ${dns}`);
    if (ip.warmup.state === "established") console.log("    established (no warm-up)");
    else if ("providers" in ip.warmup) {
      if (ip.warmup.providers.length === 0) console.log("    warm-up starts with the first email");
      for (const w of ip.warmup.providers) {
        console.log(
          `    ${w.provider.padEnd(9)} ${w.state === "done" ? "warm-up done" : `warming, day ${w.day} of ~${w.of_about}, today's budget ${w.budget_today} (${w.sent_today} sent)`}`,
        );
      }
    }
  }
}

interface HoldsView {
  holds: { id: string; target: string; lane: string; reason: string; created_at: string }[];
  senders: {
    domain: string;
    lane: string;
    delivered: number;
    complaint_rate: number;
    bounce_rate: number;
  }[];
}

export async function holdsCommand(argv: string[], config: Config) {
  const [sub = "list", id] = argv;
  if (sub === "release") {
    if (!id) throw new UsageError("usage: bunzzle holds release ID");
    await call(config, "releaseHold", { id });
    console.log(`Released ${id}. Bulk mail flows again; watch the rates closely.`);
    return;
  }
  if (sub !== "list") throw new UsageError("usage: bunzzle holds [list] | release ID");
  const v = await call<HoldsView>(config, "holds", {});
  if (v.holds.length === 0) console.log("No holds: all lanes are open.");
  for (const h of v.holds)
    console.log(`${h.id}  ${h.target} ${h.lane}  since ${h.created_at}\n    ${h.reason}`);
  for (const s of v.senders) {
    console.log(
      `${s.domain} ${s.lane}: ${s.delivered} delivered in 2 days, complaints ${s.complaint_rate}%, hard bounces ${s.bounce_rate}%`,
    );
  }
}

interface KeyView {
  id: string;
  name: string;
  prefix: string;
  scope: string;
  domains: string[] | null;
  rateLimit: number;
  lastUsedAt: number | null;
  revokedAt: number | null;
  token?: string;
}

export async function keysCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "create": {
      const args = parseArgs(rest, {
        strings: ["name", "scope", "rate-limit"],
        lists: ["domain"],
      });
      const name = args.strings.get("name");
      if (!name)
        throw new UsageError(
          "usage: bunzzle keys create --name NAME [--scope send|read|full] [--domain D]",
        );
      const scope = args.strings.get("scope") ?? "send";
      if (!["send", "read", "full"].includes(scope))
        throw new UsageError("--scope must be send, read or full");
      const rateLimit = args.strings.get("rate-limit");
      const domains = args.lists.get("domain");
      const key = await call<KeyView>(config, "createKey", {
        name,
        scope,
        ...(domains ? { domains } : {}),
        ...(rateLimit ? { rateLimit: Number(rateLimit) } : {}),
      });
      console.log(
        `Created API key "${key.name}" (${key.scope}${key.domains ? `, only ${key.domains.join(", ")}` : ""}).`,
      );
      console.log("Copy it now, it is shown only once:\n");
      console.log(key.token);
      return;
    }
    case "list": {
      const keys = await call<KeyView[]>(config, "listKeys", {});
      if (keys.length === 0)
        console.log("No API keys yet. Create one with `bunzzle keys create --name NAME`.");
      for (const k of keys) {
        const state = k.revokedAt ? "revoked" : "active";
        const used = k.lastUsedAt ? new Date(k.lastUsedAt).toISOString() : "never used";
        console.log(
          `${k.id}  ${k.prefix}…  ${state.padEnd(7)}  ${k.scope.padEnd(4)}  ${k.name}  (${used})`,
        );
      }
      return;
    }
    case "revoke": {
      const id = rest[0];
      if (!id || rest.length > 1) throw new UsageError("usage: bunzzle keys revoke ID");
      await call(config, "revokeKey", { id });
      console.log(`Revoked ${id}.`);
      return;
    }
    default:
      throw new UsageError("usage: bunzzle keys create|list|revoke");
  }
}
