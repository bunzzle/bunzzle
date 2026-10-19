import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { keyFromTxt, selectorsOf, verifyDkim } from "../dkim/verify.ts";
import {
  type Domain,
  type DomainRecord,
  evaluate,
  expectedRecords,
  getDomain,
  listDomains,
  saveDomain,
} from "../domains/domains.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

const DAY = 86_400_000;
const OVERLAP_DAYS = 7;

const keyInfo = b.array(
  b.object({
    selector: b.string(),
    algorithm: b.enum(["rsa-sha256", "ed25519-sha256"]),
    publicKey: b.string(),
    state: b.enum(["active", "next", "retiring"]),
    createdAt: b.number().nullable(),
    retiringSince: b.number().nullable(),
  }),
);
type KeyInfo = b.infer<typeof keyInfo>[number];

export interface RotationDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  dns: RpcClient;
  sourceIp: string | string[] | null;
  inboundHost: string | null;
  rotateDays: number;
  now?: () => number;
}

export interface SelfCheck {
  ok: boolean;
  which: "active" | "next";
  results: { selector: string; ok: boolean; reason?: string }[];
}

export function rotation(deps: RotationDeps) {
  const { db, writer, log, signer, delivery, dns } = deps;
  const now = deps.now ?? Date.now;

  const lookup = (queries: { name: string; type: "TXT" | "MX" }[]) =>
    delivery.call(
      "dns",
      { queries },
      { result: b.record(b.string(), b.array(b.string())), timeoutMs: 30_000 },
    );

  const keys = (domain: string) => signer.call("keyStates", { domain }, { result: keyInfo });

  const rebuild = async (domain: string, list: KeyInfo[]): Promise<Domain | null> => {
    const d = getDomain(db, domain);
    if (!d) return null;
    const records = expectedRecords(domain, list, deps.sourceIp, deps.inboundHost);
    const queries = [
      ...new Map(
        records.map((r) => [`${r.type}:${r.name}`, { name: r.name, type: r.type }]),
      ).values(),
    ];
    const checked = evaluate(records, await lookup(queries), deps.sourceIp);
    const next: Domain = {
      ...d,
      records: checked.records,
      status: checked.status,
      checkedAt: now(),
    };
    await writer.run((w) => saveDomain(w, next, now()));
    return next;
  };

  const publish = async (records: DomainRecord[], remove = false) => {
    const status = await dns
      .call<{ enabled: boolean }>("publish", { op: "status" }, { timeoutMs: 5_000 })
      .catch(() => ({ enabled: false }));
    if (!status.enabled) return false;
    for (const r of records) {
      if (r.record === "SPF" || r.record === "DMARC") continue;
      const record =
        r.type === "MX"
          ? {
              type: "MX",
              name: r.name,
              content: r.value.split(" ")[1] ?? "",
              priority: Number(r.value.split(" ")[0]),
            }
          : { type: "TXT", name: r.name, content: r.value };
      const result = await dns
        .call<{ ok: boolean; action?: string; error?: string }>(
          "publish",
          { op: remove ? "remove" : "upsert", record },
          { timeoutMs: 60_000 },
        )
        .catch((err: Error): { ok: boolean; action?: string; error?: string } => ({
          ok: false,
          error: err.message,
        }));
      if (result.ok) log.info("DNS record published", { name: r.name, action: result.action });
      else
        log.warn("could not publish a DNS record", {
          name: r.name,
          error: result.error,
        });
    }
    return true;
  };

  const selfCheck = async (domain: string, which: "active" | "next"): Promise<SelfCheck> => {
    const canary = await signer.call("signCanary", { domain, which }, { result: b.string() });
    const selectors = selectorsOf(canary);
    const found = await lookup(
      selectors.map((s) => ({ name: `${s}._domainkey.${domain}`, type: "TXT" as const })),
    );
    const published = Object.fromEntries(
      selectors.flatMap((s) => {
        const txt = found[`TXT:${s}._domainkey.${domain}`]?.[0];
        const key = txt ? keyFromTxt(txt) : null;
        return key ? [[s, key]] : [];
      }),
    );
    const results = await verifyDkim(canary, published);
    return { ok: results.length > 0 && results.every((r) => r.ok), which, results };
  };

  const selectorBase = (list: KeyInfo[]) => {
    const d = new Date(now());
    const day = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
    let base = `bz${day}`;
    if (list.some((k) => k.selector.startsWith(base))) {
      base = `${base}${String(d.getUTCHours()).padStart(2, "0")}${String(d.getUTCMinutes()).padStart(2, "0")}`;
    }
    return base;
  };

  const step = async (domain: string, force: boolean): Promise<string> => {
    const d = getDomain(db, domain);
    if (d?.status !== "verified") return "domain not verified";
    let list = await keys(domain);
    const t = now();
    const next = list.filter((k) => k.state === "next");
    const active = list.filter((k) => k.state === "active");
    const retiring = list.filter((k) => k.state === "retiring");

    if (
      retiring.length > 0 &&
      retiring.every((k) => (k.retiringSince ?? t) + OVERLAP_DAYS * DAY <= t)
    ) {
      const gone = await signer.call("dropRetiring", { domain }, { result: keyInfo });
      await rebuild(domain, await keys(domain));
      await publish(
        expectedRecords(
          domain,
          gone.map((k) => ({ ...k, state: "retiring" as const })),
          null,
        ).filter((r) => r.record === "DKIM_RETIRING"),
        true,
      );
      log.info("old DKIM keys destroyed; their DNS records can be deleted", {
        domain,
        selectors: gone.map((k) => k.selector),
      });
      return "old keys removed";
    }

    if (next.length > 0) {
      const rebuilt = await rebuild(domain, list);
      const ready = rebuilt?.records
        .filter((r) => r.record === "DKIM_NEXT")
        .every((r) => r.status === "verified");
      if (!ready) return "waiting for the new DKIM records in DNS";
      const check = await selfCheck(domain, "next");
      if (!check.ok) {
        log.error("DKIM self-check failed: not switching to the new keys", {
          domain,
          results: check.results,
        });
        return "self-check failed";
      }
      list = await signer.call("promote", { domain }, { result: keyInfo });
      await rebuild(domain, list);
      const after = await selfCheck(domain, "active");
      log.info("switched to new DKIM keys", { domain, selfCheck: after.ok });
      if (!after.ok)
        log.error("DKIM self-check failed after switching keys", {
          domain,
          results: after.results,
        });
      return "switched to new keys";
    }

    const age = Math.min(...active.map((k) => k.createdAt ?? Number.POSITIVE_INFINITY));
    const due = Number.isFinite(age) && t - age >= (deps.rotateDays - OVERLAP_DAYS) * DAY;
    if (!force && !due) return "keys are current";
    list = await signer.call(
      "rotateStart",
      { domain, selectorBase: selectorBase(list) },
      { result: keyInfo },
    );
    const rebuilt = await rebuild(domain, list);
    await publish(rebuilt?.records.filter((r) => r.record === "DKIM_NEXT") ?? []);
    log.info("new DKIM keys created; publish their records to finish rotation", {
      domain,
      selectors: list.filter((k) => k.state === "next").map((k) => k.selector),
    });
    return "new keys created";
  };

  const tick = async () => {
    for (const d of listDomains(db)) {
      try {
        await step(d.name, false);
      } catch (err) {
        log.warn("DKIM rotation check failed", { domain: d.name, error: (err as Error).message });
      }
    }
  };

  return { step, tick, publish, selfCheck, rebuild, keys };
}
