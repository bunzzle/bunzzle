import type { DkimCheck } from "../dkim/check.ts";
import { lookup, txtStrings, validDomain } from "../dns/lookup.ts";
import type { Resolver } from "../dns/resolver.ts";
import type { SpfCheck } from "../spf/check.ts";

export type DmarcResult = "pass" | "fail" | "none" | "temperror" | "permerror";
export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface DmarcCheck {
  result: DmarcResult;
  domain: string | null;
  policy: DmarcPolicy | null;
  reason: string | null;
}

export interface DmarcRecord {
  p: DmarcPolicy;
  sp: DmarcPolicy | null;
  np: DmarcPolicy | null;
  adkim: "r" | "s";
  aspf: "r" | "s";
  testing: boolean;
  psd: "y" | "n" | null;
}

export type DmarcFrom = { domain: string } | { problem: string };

class LookupFailed extends Error {}

const POLICIES: readonly string[] = ["none", "quarantine", "reject"];
const policyOf = (v: string | undefined): DmarcPolicy | null =>
  v !== undefined && POLICIES.includes(v) ? (v as DmarcPolicy) : null;

export function parseDmarcRecord(txt: string): DmarcRecord | null {
  const parts = txt.split(";").map((p) => p.trim());
  if (!/^v\s*=\s*DMARC1$/i.test(parts[0] ?? "")) return null;
  const tags = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const eq = part.indexOf("=");
    if (eq > 0) tags.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  const lower = (k: string) => tags.get(k)?.toLowerCase();
  const pct = tags.get("pct");
  const psd = lower("psd");
  return {
    p: policyOf(lower("p")) ?? "none",
    sp: policyOf(lower("sp")),
    np: policyOf(lower("np")),
    adkim: lower("adkim") === "s" ? "s" : "r",
    aspf: lower("aspf") === "s" ? "s" : "r",
    testing: lower("t") === "y" || (pct !== undefined && pct !== "100"),
    psd: psd === "y" || psd === "n" ? psd : null,
  };
}

function walk(domain: string): string[] {
  const labels = domain.split(".");
  const out = [domain];
  for (let n = Math.min(labels.length - 1, 7); n >= 1; n--) out.push(labels.slice(-n).join("."));
  return out;
}

async function recordAt(resolver: Resolver, name: string): Promise<DmarcRecord | null> {
  const r = await lookup(resolver, `_dmarc.${name}`, "TXT");
  if (r.kind === "failed") throw new LookupFailed(`DMARC lookup for ${name} failed`);
  if (r.kind === "missing") return null;
  const records = txtStrings(r.records).flatMap((t) => {
    const rec = parseDmarcRecord(t);
    return rec ? [rec] : [];
  });
  return records.length === 1 ? (records[0] as DmarcRecord) : null;
}

export async function organizationalDomain(resolver: Resolver, domain: string): Promise<string> {
  const names = walk(domain);
  let org = domain;
  for (const name of names) {
    const rec = await recordAt(resolver, name);
    if (!rec) continue;
    if (rec.psd === "n") return name;
    if (rec.psd === "y") {
      const below = domain
        .split(".")
        .slice(-(name.split(".").length + 1))
        .join(".");
      return below === name ? domain : below;
    }
    org = name;
  }
  return org;
}

function relaxedCandidate(a: string, b: string): boolean {
  const tail = (d: string) => d.split(".").slice(-2).join(".");
  return tail(a) === tail(b);
}

function downgrade(p: DmarcPolicy): DmarcPolicy {
  return p === "reject" ? "quarantine" : "none";
}

export async function checkDmarc(
  resolver: Resolver,
  from: DmarcFrom,
  spf: SpfCheck,
  dkim: DkimCheck[],
): Promise<DmarcCheck> {
  if ("problem" in from) {
    return { result: "permerror", domain: null, policy: null, reason: from.problem };
  }
  const domain = from.domain.toLowerCase().replace(/\.$/, "");
  if (!validDomain(domain)) {
    return { result: "permerror", domain, policy: null, reason: "the From domain is not valid" };
  }
  try {
    let found: { name: string; record: DmarcRecord } | null = null;
    for (const name of walk(domain)) {
      const record = await recordAt(resolver, name);
      if (record) {
        found = { name, record };
        break;
      }
    }
    if (!found) return { result: "none", domain, policy: null, reason: null };
    const { record } = found;
    let policy = record.p;
    if (found.name !== domain) {
      const exists = await lookup(resolver, domain, "A");
      if (exists.kind === "failed") throw new LookupFailed(`A lookup for ${domain} failed`);
      const missing = exists.kind === "missing" && exists.nxdomain;
      policy = (missing ? record.np : null) ?? record.sp ?? record.p;
    }
    if (record.testing) policy = downgrade(policy);
    const orgs = new Map<string, Promise<string>>();
    const org = (d: string) => {
      let p = orgs.get(d);
      if (!p) {
        p = organizationalDomain(resolver, d);
        orgs.set(d, p);
      }
      return p;
    };
    const aligned = async (d: string, mode: "r" | "s") => {
      const id = d.toLowerCase().replace(/\.$/, "");
      if (id === domain) return true;
      if (mode === "s" || !relaxedCandidate(id, domain)) return false;
      return (await org(id)) === (await org(domain));
    };
    for (const d of dkim) {
      if (d.result === "pass" && d.domain && (await aligned(d.domain, record.adkim))) {
        return { result: "pass", domain, policy, reason: null };
      }
    }
    if (spf.result === "pass" && spf.scope === "mailfrom" && spf.domain) {
      if (await aligned(spf.domain, record.aspf)) {
        return { result: "pass", domain, policy, reason: null };
      }
    }
    return { result: "fail", domain, policy, reason: "no aligned SPF or DKIM pass" };
  } catch (err) {
    if (err instanceof LookupFailed) {
      return { result: "temperror", domain, policy: null, reason: err.message };
    }
    throw err;
  }
}
