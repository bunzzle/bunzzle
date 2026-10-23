import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import { fromPem } from "../asn1/der.ts";
import type { Config } from "../config.ts";
import type { StorageState } from "../core/storage.ts";
import { allDomains, domainPool, findDomain, getDomain, listDomains } from "../domains/domains.ts";
import { latestPostmaster } from "../guards/gmail.ts";
import { listHolds } from "../guards/guards.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { LOCAL, type NodeHealth } from "../nodes/fleet.ts";
import { type DeliveryNode, listNodes } from "../nodes/registry.ts";
import type { PathView } from "../shaping/shaper.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { resolveServer, scopeOf } from "./actor.ts";
import type { rotation } from "./core-rotation.ts";
import { project, tokenHash } from "./wire.ts";

export type CheckStatus = "ok" | "warn" | "fail";

export interface Check {
  area: string;
  item: string;
  status: CheckStatus;
  detail: string;
}

export interface DoctorDeps {
  db: Database;
  config: Config;
  delivery: RpcClient;
  rotation: ReturnType<typeof rotation>;
  paths: () => PathView[];
  storage?: () => StorageState;
  nodeCa?: () => string;
  corePin?: () => string;
  fleet?: () => { health: NodeHealth[]; conflicts: { ip: string; nodes: string[] }[] };
  now?: () => number;
}

const DAY = 86_400_000;
const CA_WARN_DAYS = 60;
const NODE_WARN_DAYS = 3;

const dnssecInfo = b.object({ mode: b.enum(["resolver", "own", "off"]), detail: b.string() });

export const ipInfo = b.array(
  b.object({
    ip: b.string(),
    ehlo: b.string(),
    ptr: b.string().nullable(),
    forwardConfirmed: b.boolean(),
    problem: b.string().nullable(),
    listings: b
      .array(
        b.object({
          list: b.string(),
          name: b.string(),
          status: b.enum(["clean", "listed", "unusable"]),
          detail: b.string(),
          removal: b.string().nullable(),
        }),
      )
      .nullable()
      .optional(),
  }),
);

export function nodeChecks(
  nodes: DeliveryNode[],
  caPem: string,
  corePin: string,
  now: number,
): Check[] {
  if (nodes.length === 0) return [];
  const checks: Check[] = [];
  const expiry = (item: string, notAfter: number, warnDays: number) => {
    const days = Math.floor((notAfter - now) / DAY);
    const when = new Date(notAfter).toISOString().slice(0, 10);
    const expired = notAfter <= now;
    checks.push({
      area: "nodes",
      item,
      status: expired ? "fail" : days < warnDays ? "warn" : "ok",
      detail: expired ? `expired ${when}` : `expires ${when}, in ${days} days`,
    });
  };
  for (const der of fromPem(caPem)) {
    const ca = parseCertificate(der);
    expiry(`CA ${ca.commonNames[0] ?? ""}`, ca.notAfter, CA_WARN_DAYS);
  }
  for (const n of nodes) {
    if (n.corePins.length > 0 && !n.corePins.includes(corePin)) {
      checks.push({
        area: "nodes",
        item: `${n.name} link`,
        status: "fail",
        detail: `does not accept core's current key (core renewed while ${n.name} was not reachable): run bunzzle nodes remove ${n.name}, then request, add and install again`,
      });
    }
    expiry(`${n.name} certificate`, n.notAfter, NODE_WARN_DAYS);
  }
  return checks;
}

export function fleetChecks(
  health: NodeHealth[],
  conflicts: { ip: string; nodes: string[] }[],
  configured: string[],
  now: number,
): Check[] {
  const checks: Check[] = [];
  const remote = health.filter((h) => h.name !== LOCAL);
  for (const h of remote) {
    const seen = h.lastSeen === null ? "never" : `${Math.round((now - h.lastSeen) / 1000)} s ago`;
    checks.push({
      area: "nodes",
      item: `${h.name} health`,
      status: h.up ? "ok" : "fail",
      detail: h.up
        ? `up, IPs: ${h.ips.join(", ") || "none"}`
        : `down, last seen ${seen}${h.error ? `: ${h.error}` : ""}; its IPs are paused`,
    });
  }
  for (const c of conflicts) {
    checks.push({
      area: "nodes",
      item: `${c.ip} owner`,
      status: "fail",
      detail: `reported by ${c.nodes.join(" and ")}; the IP is paused until only one node has it`,
    });
  }
  if (remote.length > 0 && health.every((h) => h.up)) {
    for (const ip of configured) {
      if (health.some((h) => h.ips.includes(ip))) continue;
      checks.push({
        area: "nodes",
        item: `${ip} owner`,
        status: "fail",
        detail: "no delivery role has this IP in BUNZZLE_SOURCE_IPS; the IP is paused",
      });
    }
  }
  return checks;
}

export function doctorMethods(deps: DoctorDeps): Methods {
  const { db, config, delivery, rotation } = deps;
  const now = deps.now ?? Date.now;

  const run = async (scope: ProjectId | null): Promise<Check[]> => {
    const checks: Check[] = [];
    const add = (area: string, item: string, status: CheckStatus, detail: string) =>
      checks.push({ area, item, status, detail });

    add(
      "config",
      "EHLO name",
      config.ehloName ? "ok" : "fail",
      config.ehloName ?? "BUNZZLE_EHLO_NAME is not set: nothing can be delivered",
    );
    add(
      "config",
      "public URL",
      config.publicUrl?.startsWith("https://") ? "ok" : "warn",
      config.publicUrl
        ? config.publicUrl.startsWith("https://")
          ? config.publicUrl
          : `${config.publicUrl} is not https: Gmail and Yahoo expect an https unsubscribe link`
        : "BUNZZLE_PUBLIC_URL is not set: bulk email gets no one-click unsubscribe link",
    );
    add(
      "config",
      "bounces and complaints",
      config.inboundPort !== null ? "ok" : "warn",
      config.inboundPort !== null
        ? `listening on port ${config.inboundPort}`
        : "BUNZZLE_INBOUND_PORT is not set: late bounces and complaints are not received",
    );
    const disk = deps.storage?.();
    if (disk && disk.minFreeMb > 0) {
      add(
        "config",
        "disk space",
        disk.freeMb === null ? "warn" : disk.low ? "fail" : "ok",
        disk.freeMb === null
          ? "could not read the free space of the data directory"
          : disk.low
            ? `${disk.freeMb} MB free, below BUNZZLE_MIN_FREE_MB (${disk.minFreeMb}): new email is refused`
            : `${disk.freeMb} MB free (new email is refused below ${disk.minFreeMb} MB)`,
      );
    }

    const dnssec = await delivery
      .call("dnssec", {}, { result: dnssecInfo, timeoutMs: 10_000 })
      .catch(() => null);
    if (dnssec) {
      add(
        "dns",
        "DNSSEC and DANE",
        dnssec.mode === "off" ? "warn" : "ok",
        dnssec.mode === "off" ? `DANE is off: ${dnssec.detail}` : `DANE is on: ${dnssec.detail}`,
      );
    }

    const ips = await delivery
      .call("ips", {}, { result: ipInfo, timeoutMs: 10_000 })
      .catch(() => null);
    if (!ips) add("ips", "delivery role", "fail", "the delivery role is not answering");
    else if (ips.length === 0) {
      add(
        "ips",
        "source IPs",
        "warn",
        "BUNZZLE_SOURCE_IPS is not set: the system picks the IP, so there is no warm-up and no reverse DNS check",
      );
    }
    for (const ip of ips ?? []) {
      add(
        "ips",
        ip.ip,
        ip.forwardConfirmed ? "ok" : "fail",
        ip.forwardConfirmed
          ? `reverse DNS ${ip.ptr}, EHLO ${ip.ehlo}`
          : `${ip.problem}: Gmail and others reject mail from IPs without matching reverse DNS`,
      );
      const listings = ip.listings ?? null;
      if (!listings) {
        add("ips", `${ip.ip} blocklists`, "warn", "not checked yet");
        continue;
      }
      for (const l of listings.filter((x) => x.status === "listed")) {
        add("ips", `${ip.ip} on ${l.name}`, "fail", `${l.detail}; removal: ${l.removal}`);
      }
      for (const l of listings.filter((x) => x.status === "unusable")) {
        add("ips", `${ip.ip} ${l.name}`, "warn", `could not check: ${l.detail}`);
      }
      const clean = listings.filter((x) => x.status === "clean").length;
      if (clean === listings.length) {
        add("ips", `${ip.ip} blocklists`, "ok", `not listed on ${clean} blocklists`);
      }
    }

    const domains = scope === null ? allDomains(db) : listDomains(db, scope);
    if (domains.length === 0) add("domains", "sending domains", "warn", "no domain added yet");
    for (const d of domains) {
      const keys = await rotation.keys(d.name).catch(() => null);
      const fresh = keys ? await rotation.rebuild(d.name, keys).catch(() => null) : null;
      const records = (fresh ?? d).records;
      const pool = domainPool(db, d.name);
      if (pool) {
        const has = config.sourceIps.filter((x) => x.pool === pool).map((x) => x.ip);
        add(
          "domains",
          `${d.name} IP pool`,
          has.length ? "ok" : "fail",
          has.length
            ? `sends only from the pool ${pool}: ${has.join(", ")}`
            : `the pool ${pool} has no IPs in BUNZZLE_SOURCE_IPS: its email waits`,
        );
      }
      const gmail = latestPostmaster(db, d.name);
      if (gmail) {
        const spam = gmail.spamRatio;
        add(
          "domains",
          `${d.name} Gmail`,
          (spam ?? 0) >= 0.003 || gmail.reputation === "BAD"
            ? "fail"
            : (spam ?? 0) >= 0.001 || gmail.reputation === "LOW"
              ? "warn"
              : "ok",
          `${gmail.day}: spam rate ${spam === null ? "not reported" : `${(spam * 100).toFixed(2)}%`}, reputation ${gmail.reputation ?? "not reported"}`,
        );
      }
      for (const r of records) {
        const status: CheckStatus =
          r.status === "verified"
            ? "ok"
            : r.required
              ? "fail"
              : r.record === "DKIM_RETIRING"
                ? "ok"
                : "warn";
        const detail =
          r.status === "verified"
            ? `${r.type} ${r.name} is correct`
            : r.status === "mismatch"
              ? `${r.type} ${r.name} is wrong: found "${r.found}", expected "${r.value}"`
              : `${r.type} ${r.name} is missing: add "${r.value}"`;
        add(`domain ${d.name}`, r.record, status, detail);
      }
      if ((fresh ?? d).status === "verified") {
        const check = await rotation.selfCheck(d.name, "active").catch((err: Error) => ({
          ok: false,
          which: "active" as const,
          results: [{ selector: "-", ok: false, reason: err.message }],
        }));
        add(
          `domain ${d.name}`,
          "DKIM self-check",
          check.ok ? "ok" : "fail",
          check.ok
            ? `a test message signed now verifies against live DNS (${check.results.map((r) => r.selector).join(", ")})`
            : `signatures do not verify against live DNS: ${check.results.map((r) => `${r.selector}: ${r.reason ?? "ok"}`).join("; ")}`,
        );
      }
    }

    for (const h of listHolds(db, scope)) {
      add(
        "guards",
        `${h.target} ${h.lane}`,
        "warn",
        `on hold since ${new Date(h.createdAt).toISOString()}: ${h.reason}`,
      );
    }
    for (const p of deps.paths()) {
      if (p.mode === "paused" || p.mode === "probing") {
        add("paths", p.key, "warn", `${p.mode}: ${p.changes.at(-1)?.reason ?? ""}`);
      }
    }
    const failed =
      db
        .query<{ n: number }, [number]>(
          "SELECT count(*) AS n FROM webhook_deliveries WHERE state = 'failed' AND updated_at > ?",
        )
        .get(now() - 86_400_000)?.n ?? 0;
    if (failed > 0)
      add("webhooks", "deliveries", "warn", `${failed} webhook deliveries gave up in the last day`);

    const f = scope === null ? deps.fleet?.() : undefined;
    if (f) {
      const configured = config.sourceIps.map((x) => x.ip);
      checks.push(...fleetChecks(f.health, f.conflicts, configured, now()));
    }
    if (scope === null)
      checks.push(
        ...nodeChecks(listNodes(db), deps.nodeCa?.() ?? "", deps.corePin?.() ?? "", now()),
      );
    return checks;
  };

  return {
    doctor: method(b.object({ tokenHash, project }), async (p) => {
      const actor = resolveServer(db, p, "full");
      const checks = await run(scopeOf(actor));
      return {
        checks,
        summary: {
          ok: checks.filter((c) => c.status === "ok").length,
          warn: checks.filter((c) => c.status === "warn").length,
          fail: checks.filter((c) => c.status === "fail").length,
        },
      };
    }),
    rotateDomain: method(b.object({ tokenHash, project, name: b.string().max(253) }), async (p) => {
      const scope = scopeOf(resolveServer(db, p, "full"));
      const name = p.name.toLowerCase();
      if (!(scope === null ? findDomain(db, name) : getDomain(db, scope, name)))
        throw new RpcError("not-found", "domain not found");
      return { result: await rotation.step(name, true) };
    }),
  };
}
