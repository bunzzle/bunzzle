import type { Config } from "../config.ts";
import { RpcClient, RpcError } from "../ipc/rpc.ts";
import { adminSocket } from "../roles/admin-socket.ts";
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

export async function runDirOf(config: Config): Promise<string> {
  if (Bun.env["BUNZZLE_RUN_DIR"]) return config.runDir;
  const system = adminSocket(SYSTEM_RUN_DIR);
  const isSocket = await Bun.file(system)
    .stat()
    .then((s) => s.isSocket())
    .catch(() => false);
  return isSocket ? SYSTEM_RUN_DIR : config.runDir;
}

async function call<T>(config: Config, method: string, params: unknown): Promise<T> {
  const runDir = await runDirOf(config);
  const core = new RpcClient(adminSocket(runDir));
  try {
    return await core.call<T>(method, params, { timeoutMs: 60_000 });
  } catch (err) {
    if (err instanceof RpcError && err.code === "unavailable") {
      throw new UsageError(
        `cannot reach Bunzzle at ${adminSocket(runDir)}: is \`bunzzle serve\` running (same BUNZZLE_RUN_DIR)?`,
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

interface DmarcDayView {
  day: string;
  messages: number;
  dmarc_pass: number;
  reporters: string[];
  sources: {
    source_ip: string;
    messages: number;
    dmarc_pass: number;
    dkim_pass: number;
    spf_pass: number;
  }[];
}

async function dmarcReports(config: Config, name: string, rest: string[]) {
  const args = parseArgs(rest, { strings: ["days"] });
  const days = Number(args.strings.get("days") ?? "7");
  const r = await call<{ data: DmarcDayView[] }>(config, "dmarcReports", { domain: name, days });
  if (r.data.length === 0) {
    console.log(
      `No DMARC reports for ${name} in the last ${days} days. Reports arrive about once a day once the DMARC record asks for them.`,
    );
    return;
  }
  for (const d of r.data) {
    const pct = d.messages ? Math.round((100 * d.dmarc_pass) / d.messages) : 0;
    console.log(
      `${d.day}  ${d.messages} messages, ${pct}% pass DMARC  (${d.reporters.join(", ")})`,
    );
    for (const s of d.sources) {
      const flag = s.dmarc_pass < s.messages ? "FAIL" : "ok";
      console.log(
        `  [${flag}] ${s.source_ip.padEnd(39)} ${s.messages} messages, DKIM pass ${s.dkim_pass}, SPF pass ${s.spf_pass}`,
      );
    }
  }
}

export async function domainsCommand(argv: string[], config: Config) {
  const [sub, name, ...rest] = argv;
  if (sub === "reports") {
    if (!name) throw new UsageError("usage: bunzzle domains reports DOMAIN [--days N]");
    return dmarcReports(config, name, rest);
  }
  if (sub === "pool") {
    const [pool] = rest;
    if (!name || !pool || rest.length > 1) {
      throw new UsageError("usage: bunzzle domains pool DOMAIN POOL|none");
    }
    const r = await call<{ name: string; ip_pool: string | null }>(config, "setDomainPool", {
      name,
      pool: pool === "none" ? null : pool,
    });
    console.log(
      r.ip_pool
        ? `${r.name} now sends only from the IPs in the pool ${r.ip_pool}.`
        : `${r.name} uses the shared IPs again.`,
    );
    return;
  }
  if (sub === "tracking") {
    const [host, ...flags] = rest;
    if (!name || !host) {
      throw new UsageError("usage: bunzzle domains tracking DOMAIN HOST|none [--opens] [--clicks]");
    }
    const args = parseArgs(flags, { flags: ["opens", "clicks"] });
    const r = await call<{
      name: string;
      tracking: {
        host: string;
        opens: boolean;
        clicks: boolean;
        record: { value: string; status: string };
      } | null;
    }>(config, "setDomainTracking", {
      name,
      tracking:
        host === "none"
          ? null
          : { host, opens: args.flags.has("opens"), clicks: args.flags.has("clicks") },
    });
    const t = r.tracking;
    if (!t) {
      console.log(`${r.name} has no tracking.`);
      return;
    }
    const on = [t.opens ? "opens" : "", t.clicks ? "clicks" : ""].filter(Boolean).join(" and ");
    console.log(`${r.name} tracks ${on || "nothing by default"} through ${t.host}.`);
    console.log(`[${mark(t.record.status)}] CNAME  ${t.host}  ${t.record.value}`);
    return;
  }
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
      throw new UsageError("usage: bunzzle domains add|verify|show|rotate|list|reports");
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

export async function routesCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "add": {
      const [address, url, ...flags] = rest;
      if (!address || !url) {
        throw new UsageError("usage: bunzzle routes add ADDRESS URL [--raw]");
      }
      const args = parseArgs(flags, { flags: ["raw"] });
      const r = await call<{
        id: string;
        address: string;
        endpoint: string;
        format: string;
        signing_secret: string;
      }>(config, "createRoute", { address, url, format: args.flags.has("raw") ? "raw" : "parsed" });
      console.log(`Route ${r.id}: ${r.address} → ${r.endpoint} (${r.format})`);
      console.log(`Signing secret (Standard Webhooks format): ${r.signing_secret}`);
      return;
    }
    case "list": {
      const routes = await call<
        { id: string; address: string; endpoint: string; format: string }[]
      >(config, "listRoutes", {});
      if (routes.length === 0) {
        console.log("No routes yet. Add one with `bunzzle routes add ADDRESS URL`.");
      }
      for (const r of routes) console.log(`${r.id}  ${r.address}  ${r.endpoint}  (${r.format})`);
      return;
    }
    case "remove": {
      const id = rest[0];
      if (!id) throw new UsageError("usage: bunzzle routes remove ID");
      await call(config, "deleteRoute", { id });
      console.log(`Removed ${id}.`);
      return;
    }
    case "retry": {
      const id = rest[0];
      if (!id) throw new UsageError("usage: bunzzle routes retry ID");
      const r = await call<{ requeued: number }>(config, "retryRoute", { id });
      console.log(
        `${r.requeued} failed ${r.requeued === 1 ? "message" : "messages"} queued again.`,
      );
      return;
    }
    default:
      throw new UsageError("usage: bunzzle routes add|list|remove|retry");
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
  test: boolean;
  token?: string;
}

export async function keysCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "create": {
      const args = parseArgs(rest, {
        strings: ["name", "scope", "rate-limit", "pool"],
        lists: ["domain"],
        flags: ["test"],
      });
      const name = args.strings.get("name");
      if (!name)
        throw new UsageError(
          "usage: bunzzle keys create --name NAME [--scope send|read|full] [--domain D] [--test]",
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
        ...(args.flags.has("test") ? { test: true } : {}),
        ...(args.strings.get("pool") ? { pool: args.strings.get("pool") } : {}),
      });
      console.log(
        `Created ${key.test ? "test " : ""}API key "${key.name}" (${key.scope}${key.domains ? `, only ${key.domains.join(", ")}` : ""}).${key.test ? " Email sent with it is recorded but never delivered." : ""}`,
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
        const state = k.revokedAt ? "revoked" : k.test ? "test" : "active";
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

interface QueueRowView {
  destination: string;
  waiting: number;
  sending: number;
  retrying: number;
  scheduled: number;
  suspended: number;
  oldest_age_s: number;
}

interface SuspensionView {
  target: string;
  reason: string;
  until: string | null;
  since: string;
}

function duration(text: string | undefined, flag: string): number | undefined {
  if (text === undefined) return undefined;
  const m = /^(\d+)(s|m|h|d)$/.exec(text);
  if (!m) throw new UsageError(`--${flag} takes a duration like 30m, 6h or 2d`);
  const unit = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "s" | "m" | "h" | "d"];
  return Number(m[1]) * unit;
}

function age(seconds: number): string {
  if (seconds < 120) return `${seconds}s`;
  if (seconds < 7_200) return `${Math.round(seconds / 60)}m`;
  if (seconds < 172_800) return `${Math.round(seconds / 3_600)}h`;
  return `${Math.round(seconds / 86_400)}d`;
}

function printRows(title: string, rows: QueueRowView[]) {
  if (rows.length === 0) return;
  console.log(title);
  for (const r of rows) {
    console.log(
      `  ${r.destination.padEnd(40)} ${r.waiting} waiting, ${r.retrying} retrying, ${r.sending} sending, ${r.scheduled} scheduled, ${r.suspended} suspended, oldest ${age(r.oldest_age_s)}`,
    );
  }
}

export async function queueCommand(argv: string[], config: Config) {
  const [sub = "show", ...rest] = argv;
  switch (sub) {
    case "show": {
      const q = await call<{
        domains: QueueRowView[];
        routes: QueueRowView[];
        suspensions: SuspensionView[];
      }>(config, "queue", {});
      if (q.domains.length === 0) console.log("The queue is empty.");
      printRows("By recipient domain:", q.domains);
      printRows("By route:", q.routes);
      for (const s of q.suspensions) {
        console.log(
          `SUSPENDED ${s.target} since ${s.since}${s.until ? ` until ${s.until}` : ""}: ${s.reason}`,
        );
      }
      return;
    }
    case "suspend": {
      const args = parseArgs(rest, { strings: ["domain", "provider", "reason", "for"] });
      const domain = args.strings.get("domain");
      const provider = args.strings.get("provider");
      const reason = args.strings.get("reason");
      if ((domain === undefined) === (provider === undefined) || !reason) {
        throw new UsageError(
          "usage: bunzzle queue suspend --domain NAME | --provider ID --reason TEXT [--for 6h]",
        );
      }
      const ms = duration(args.strings.get("for"), "for");
      const s = await call<SuspensionView>(config, "suspend", {
        target: domain ? `domain:${domain.toLowerCase()}` : `provider:${provider?.toLowerCase()}`,
        reason,
        until: ms === undefined ? null : Date.now() + ms,
      });
      console.log(
        `Suspended ${s.target}${s.until ? ` until ${s.until}` : " until you resume it"}. Emails stay queued.`,
      );
      return;
    }
    case "resume": {
      const [target] = rest;
      if (!target) throw new UsageError("usage: bunzzle queue resume domain:NAME|provider:ID");
      const r = await call<{ woken: number }>(config, "resume", { target });
      console.log(`Resumed ${target}; ${r.woken} waiting jobs released.`);
      return;
    }
    case "fail":
    case "cancel": {
      const args = parseArgs(rest, {
        strings: ["domain", "sender-domain", "older-than", "reason"],
        flags: ["dry-run"],
      });
      const reason = args.strings.get("reason");
      if (!reason) {
        throw new UsageError(
          `usage: bunzzle queue ${sub} [--domain NAME] [--sender-domain NAME] [--older-than 6h] --reason TEXT [--dry-run]`,
        );
      }
      const olderThanMs = duration(args.strings.get("older-than"), "older-than");
      const domain = args.strings.get("domain");
      const senderDomain = args.strings.get("sender-domain");
      const dryRun = args.flags.has("dry-run");
      const r = await call<{ emails: number; recipients: number; skipped_sending: number }>(
        config,
        "removeQueued",
        {
          action: sub,
          reason,
          dryRun,
          ...(domain ? { domain: domain.toLowerCase() } : {}),
          ...(senderDomain ? { senderDomain: senderDomain.toLowerCase() } : {}),
          ...(olderThanMs !== undefined ? { olderThanMs } : {}),
        },
      );
      const verb = sub === "cancel" ? "canceled" : "failed";
      console.log(
        `${dryRun ? "Would have" : "Have"} ${verb} ${r.emails} emails (${r.recipients} recipients).${r.skipped_sending ? ` ${r.skipped_sending} are being sent right now and were left alone.` : ""}`,
      );
      return;
    }
    default:
      throw new UsageError("usage: bunzzle queue [show|suspend|resume|fail|cancel]");
  }
}

interface EmailRow {
  id: string;
  created_at: string;
  last_event: string;
  to: string[];
  tags: { name: string; value: string }[];
}

export async function emailsCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  if (sub !== "list") {
    throw new UsageError(
      "usage: bunzzle emails list [--to EMAIL] [--status S] [--tag NAME:VALUE] [--domain D] [--limit N] [--cursor ID]",
    );
  }
  const args = parseArgs(rest, { strings: ["to", "status", "tag", "domain", "limit", "cursor"] });
  const status = args.strings.get("status");
  const internal: Record<string, string> = {
    queued: "queued",
    delivery_delayed: "deferred",
    sending: "unknown",
    delivered: "delivered",
    bounced: "bounced",
    failed: "failed",
  };
  if (status && !internal[status]) {
    throw new UsageError(`--status must be one of: ${Object.keys(internal).join(", ")}`);
  }
  const page = await call<{ data: EmailRow[]; next_cursor: string | null }>(config, "listEmails", {
    limit: Number(args.strings.get("limit") ?? 20),
    ...(args.strings.get("cursor") ? { before: args.strings.get("cursor") } : {}),
    ...(args.strings.get("to") ? { to: args.strings.get("to") } : {}),
    ...(status ? { status: internal[status] } : {}),
    ...(args.strings.get("tag") ? { tag: args.strings.get("tag") } : {}),
    ...(args.strings.get("domain") ? { domain: args.strings.get("domain") } : {}),
  });
  if (page.data.length === 0) console.log("No emails match.");
  for (const e of page.data) {
    const tags = e.tags.map((t) => `${t.name}:${t.value}`).join(",");
    console.log(
      `${e.id}  ${e.created_at}  ${e.last_event.padEnd(16)}  ${e.to.join(", ")}${tags ? `  [${tags}]` : ""}`,
    );
  }
  if (page.next_cursor) console.log(`\nmore: --cursor ${page.next_cursor}`);
}

export async function statsCommand(argv: string[], config: Config) {
  const args = parseArgs(argv, { strings: ["since", "until", "domain", "tag"] });
  const day = (t: number) => new Date(t).toISOString().slice(0, 10);
  const until = args.strings.get("until") ?? day(Date.now());
  const since = args.strings.get("since") ?? day(Date.parse(until) - 6 * 86_400_000);
  const r = await call<{
    totals: Record<string, number>;
    data: ({ day: string } & Record<string, number>)[];
  }>(config, "stats", {
    since,
    until,
    ...(args.strings.get("domain") ? { domain: args.strings.get("domain") } : {}),
    ...(args.strings.get("tag") ? { tag: args.strings.get("tag") } : {}),
  });
  const cols = Object.keys(r.totals);
  console.log(`day         ${cols.map((c) => c.padStart(12)).join("")}`);
  for (const d of r.data) {
    console.log(`${d.day}  ${cols.map((c) => String(d[c] ?? 0).padStart(12)).join("")}`);
  }
  console.log(`total       ${cols.map((c) => String(r.totals[c]).padStart(12)).join("")}`);
}

interface HookView {
  id: string;
  kind: "check" | "scan";
  url: string;
  timeout_ms: number;
  on_error: "accept" | "refuse";
  max_score: number | null;
}

const describeHook = (h: HookView) =>
  `${h.id}  ${h.kind}  ${h.url}  timeout ${h.timeout_ms} ms, on error ${h.on_error}${h.max_score === null ? "" : `, refuse at score ${h.max_score}`}`;

export async function hooksCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "add": {
      const [kind, url, ...flags] = rest;
      if ((kind !== "check" && kind !== "scan") || !url) {
        throw new UsageError(
          "usage: bunzzle hooks add check|scan URL [--max-score N] [--timeout-ms N] [--on-error accept|refuse]",
        );
      }
      const args = parseArgs(flags, { strings: ["max-score", "timeout-ms", "on-error"] });
      const onError = args.strings.get("on-error") ?? "accept";
      if (onError !== "accept" && onError !== "refuse") {
        throw new UsageError("--on-error is accept or refuse");
      }
      const number = (name: string, fallback: number | null) => {
        const raw = args.strings.get(name);
        if (raw === undefined) return fallback;
        const n = Number(raw);
        if (!Number.isFinite(n)) throw new UsageError(`--${name} must be a number`);
        return n;
      };
      const h = await call<HookView>(config, "addHook", {
        kind,
        url,
        timeoutMs: number("timeout-ms", 2_000),
        onError,
        maxScore: number("max-score", null),
      });
      console.log(`Hook ${describeHook(h)}`);
      return;
    }
    case "list": {
      const hooks = await call<HookView[]>(config, "listHooks", {});
      if (hooks.length === 0) console.log("No hooks. Add one with `bunzzle hooks add`.");
      for (const h of hooks) console.log(describeHook(h));
      return;
    }
    case "remove": {
      const id = rest[0];
      if (!id) throw new UsageError("usage: bunzzle hooks remove ID");
      await call(config, "removeHook", { id });
      console.log(`Removed ${id}.`);
      return;
    }
    default:
      throw new UsageError("usage: bunzzle hooks add|list|remove");
  }
}
