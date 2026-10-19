import type { Database } from "bun:sqlite";
import { allows, keyForHash } from "../accounts/api-keys.ts";
import type { Config } from "../config.ts";
import { listDomains } from "../domains/domains.ts";
import { listHolds } from "../guards/guards.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import type { PathView } from "../shaping/shaper.ts";
import { b } from "../validate/schema.ts";
import type { rotation } from "./core-rotation.ts";
import { tokenHash } from "./wire.ts";

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
  now?: () => number;
}

const dnssecInfo = b.object({ mode: b.enum(["resolver", "own", "off"]), detail: b.string() });

const ipInfo = b.array(
  b.object({
    ip: b.string(),
    ehlo: b.string(),
    ptr: b.string().nullable(),
    forwardConfirmed: b.boolean(),
    problem: b.string().nullable(),
  }),
);

export function doctorMethods(deps: DoctorDeps): Methods {
  const { db, config, delivery, rotation } = deps;
  const now = deps.now ?? Date.now;

  const caller = (hash: string | undefined) => {
    if (hash === undefined) return;
    const key = keyForHash(db, hash);
    if (!key) throw new RpcError("unauthenticated", "API key is invalid");
    if (!allows(key.scope, "full")) throw new RpcError("forbidden", "this API key cannot do this");
  };

  const run = async (): Promise<Check[]> => {
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
    }

    const domains = listDomains(db);
    if (domains.length === 0) add("domains", "sending domains", "warn", "no domain added yet");
    for (const d of domains) {
      const keys = await rotation.keys(d.name).catch(() => null);
      const fresh = keys ? await rotation.rebuild(d.name, keys).catch(() => null) : null;
      const records = (fresh ?? d).records;
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

    for (const h of listHolds(db)) {
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
    return checks;
  };

  return {
    doctor: method(b.object({ tokenHash }), async (p) => {
      caller(p.tokenHash);
      const checks = await run();
      return {
        checks,
        summary: {
          ok: checks.filter((c) => c.status === "ok").length,
          warn: checks.filter((c) => c.status === "warn").length,
          fail: checks.filter((c) => c.status === "fail").length,
        },
      };
    }),
    rotateDomain: method(b.object({ tokenHash, name: b.string().max(253) }), async (p) => {
      caller(p.tokenHash);
      return { result: await rotation.step(p.name.toLowerCase(), true) };
    }),
  };
}
