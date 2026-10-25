import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { keyFromTxt, selectorsOf, verifyDkim } from "../dkim/verify.ts";
import { domainRecords, isSlot, labelClash, SLOT_BASES } from "../domains/delegated.ts";
import {
  allDomains,
  type Domain,
  type DomainMode,
  type DomainRecord,
  evaluate,
  expectedRecords,
  findDomain,
  lookupRecords,
  saveDomain,
  setDomainMode,
  setSlotKeys,
  zoneDomainNames,
} from "../domains/domains.ts";
import { type RpcClient, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

const DAY = 86_400_000;
export const OVERLAP_DAYS = 7;

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
  nsZone?: string | null;
  zoneServes?: (domain: string, keys: KeyInfo[]) => boolean;
  rotateDays: () => number;
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

  const lookup = (queries: { name: string; type: DomainRecord["type"] }[]) =>
    delivery.call(
      "dns",
      { queries },
      { result: b.record(b.string(), b.array(b.string())), timeoutMs: 30_000 },
    );

  const keys = (domain: string) => signer.call("keyStates", { domain }, { result: keyInfo });

  const inspect = async (domain: string, list: KeyInfo[]): Promise<Domain | null> => {
    const d = findDomain(db, domain);
    if (!d) return null;
    const records = domainRecords(d, list, deps.sourceIp, deps.inboundHost, deps.nsZone ?? null);
    const checked = evaluate(
      records,
      await lookupRecords(records, lookup, [d.name, deps.nsZone ?? d.name]),
      deps.sourceIp,
    );
    return { ...d, records: checked.records, status: checked.status, checkedAt: now() };
  };

  const rebuild = async (domain: string, list: KeyInfo[]): Promise<Domain | null> => {
    const next = await inspect(domain, list);
    if (!next) return null;
    await writer.run((w) => {
      saveDomain(w, next, now());
      setSlotKeys(
        w,
        domain,
        list.some((k) => isSlot(k.selector)),
      );
    });
    return next;
  };

  const publish = async (records: DomainRecord[], remove = false) => {
    const status = await dns
      .call<{ enabled: boolean }>("publish", { op: "status" }, { timeoutMs: 5_000 })
      .catch(() => ({ enabled: false }));
    if (!status.enabled) return false;
    for (const r of records) {
      if (r.record === "SPF" || r.record === "DMARC" || r.type === "CNAME") continue;
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

  const served = async (domain: string, list: KeyInfo[]) => {
    const names = list.map((k) => `${k.selector}._domainkey.${domain}`);
    const found = await lookup(names.map((name) => ({ name, type: "TXT" as const })));
    return list.every((k, i) =>
      (found[`TXT:${names[i]}`] ?? []).some((t) => keyFromTxt(t)?.key.toBase64() === k.publicKey),
    );
  };

  const freeSlot = (list: KeyInfo[]) => {
    const used = (base: string) => list.some((k) => k.selector.startsWith(base));
    return SLOT_BASES.find((base) => !used(base)) ?? null;
  };

  const step = async (domain: string, force: boolean): Promise<string> => {
    const d = findDomain(db, domain);
    if (d?.status !== "verified") return "domain not verified";
    const delegated = d.mode === "delegated";
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
      const slots = gone.filter((k) => isSlot(k.selector));
      const dated = gone.filter((k) => !isSlot(k.selector));
      if (slots.length > 0) {
        log.info("old DKIM keys destroyed; their slots are free", {
          domain,
          selectors: slots.map((k) => k.selector),
        });
      }
      if (dated.length > 0) {
        await publish(
          expectedRecords(
            domain,
            dated.map((k) => ({ ...k, state: "retiring" as const })),
            null,
          ).filter((r) => r.record === "DKIM_RETIRING"),
          true,
        );
        log.info("old DKIM keys destroyed; their DNS records can be deleted", {
          domain,
          selectors: dated.map((k) => k.selector),
        });
      }
      return "old keys removed";
    }

    if (next.length > 0) {
      const rebuilt = await rebuild(domain, list);
      const slotted = next.every((k) => isSlot(k.selector));
      if (slotted && deps.zoneServes && !deps.zoneServes(domain, next)) {
        return "waiting for every NS to serve the new keys";
      }
      const ready = slotted
        ? rebuilt?.records
            .filter((r) => r.record === "DKIM" && r.type === "CNAME")
            .every((r) => r.status === "verified") && (await served(domain, next))
        : rebuilt?.records
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
    const due = Number.isFinite(age) && t - age >= (deps.rotateDays() - OVERLAP_DAYS) * DAY;
    if (!force && !due) return "keys are current";
    const base = delegated ? freeSlot(list) : selectorBase(list);
    if (!base) return "waiting for the old keys to leave their slot";
    list = await signer.call("rotateStart", { domain, selectorBase: base }, { result: keyInfo });
    if (delegated) {
      await rebuild(domain, list);
      log.info("new DKIM keys created in the free slot", {
        domain,
        selectors: list.filter((k) => k.state === "next").map((k) => k.selector),
      });
      return "new keys created";
    }
    const rebuilt = await rebuild(domain, list);
    await publish(rebuilt?.records.filter((r) => r.record === "DKIM_NEXT") ?? []);
    log.info("new DKIM keys created; publish their records to finish rotation", {
      domain,
      selectors: list.filter((k) => k.state === "next").map((k) => k.selector),
    });
    return "new keys created";
  };

  const switchMode = async (domain: string, mode: DomainMode): Promise<Domain> => {
    const d = findDomain(db, domain);
    if (!d) throw new RpcError("not-found", "domain not found");
    if (d.mode === mode) return d;
    if (d.status !== "verified") {
      throw new RpcError(
        "invalid",
        `${domain} is not verified; delete it and add it again in ${mode} mode`,
      );
    }
    if (mode === "delegated") {
      const clash = labelClash(domain, zoneDomainNames(db));
      if (clash) throw new RpcError("domain-taken", `${domain} shares its zone name with ${clash}`);
    }
    let list = await keys(domain);
    if (list.some((k) => k.state === "next")) {
      throw new RpcError("invalid", `a DKIM key rotation of ${domain} is still running`);
    }
    const base = mode === "delegated" ? freeSlot(list) : selectorBase(list);
    if (!base) {
      throw new RpcError("invalid", `the old DKIM keys of ${domain} still hold both slots`);
    }
    await writer.run((w) => setDomainMode(w, domain, mode, now()));
    try {
      list = await signer.call("rotateStart", { domain, selectorBase: base }, { result: keyInfo });
    } catch (err) {
      await writer.run((w) => setDomainMode(w, domain, d.mode, now()));
      throw err;
    }
    const rebuilt = await rebuild(domain, list);
    if (mode === "records") {
      await publish(rebuilt?.records.filter((r) => r.record === "DKIM_NEXT") ?? []);
    }
    log.info("domain mode switch started", { domain, mode });
    return rebuilt ?? d;
  };

  const tick = async () => {
    for (const d of allDomains(db)) {
      try {
        await step(d.name, false);
      } catch (err) {
        log.warn("DKIM rotation check failed", { domain: d.name, error: (err as Error).message });
      }
    }
  };

  return { step, tick, publish, selfCheck, inspect, rebuild, keys, switchMode };
}
