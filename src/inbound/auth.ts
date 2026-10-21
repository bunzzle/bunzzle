import { splitMessage } from "../dkim/canonicalize.ts";
import { checkDkim, type DkimCheck } from "../dkim/check.ts";
import { checkDmarc, type DmarcCheck, type DmarcFrom } from "../dmarc/policy.ts";
import { forbiddenReason } from "../dns/ip.ts";
import type { Resolver } from "../dns/resolver.ts";
import { type Blocklist, checkBlocklists, type Listing } from "../ips/blocklists.ts";
import { AddressError, domainOf, parseAddress } from "../mime/address.ts";
import { decodeWords } from "../mime/parse.ts";
import { checkSpf, type SpfCheck } from "../spf/check.ts";

export const REFUSE_CHECKS = ["spf", "dmarc", "blocklist"] as const;
export type RefuseCheck = (typeof REFUSE_CHECKS)[number];

export interface AuthResults {
  spf: SpfCheck;
  dkim: DkimCheck[];
  dmarc: DmarcCheck;
  blocklists: Listing[];
}

export interface AuthMeta {
  ip: string;
  mailFrom: string;
  helo: string | null;
}

function splitList(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  let angle = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i] as string;
    if (ch === "\\" && quoted) {
      cur += ch + (value[++i] ?? "");
      continue;
    }
    if (ch === '"') quoted = !quoted;
    else if (!quoted && ch === "<") angle++;
    else if (!quoted && ch === ">") angle = Math.max(0, angle - 1);
    else if (!quoted && angle === 0 && ch === ",") {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

export function fromDomain(raw: string): DmarcFrom {
  const froms = splitMessage(raw).headers.filter((h) => h.name.trim().toLowerCase() === "from");
  if (froms.length !== 1) return { problem: "the message must have exactly one From header" };
  const raw0 = (froms[0] as { raw: string }).raw;
  const value = decodeWords(raw0.slice(raw0.indexOf(":") + 1).replace(/\r\n/g, ""));
  const list = splitList(value.replace(/\([^()]*\)/g, ""));
  if (list.length !== 1) return { problem: "the From header must have exactly one address" };
  try {
    const domain = domainOf(parseAddress(list[0] as string).address);
    return domain ? { domain } : { problem: "the From address has no domain" };
  } catch (err) {
    if (err instanceof AddressError) return { problem: "the From address is not valid" };
    throw err;
  }
}

export async function checkAuth(
  resolver: Resolver,
  raw: string,
  meta: AuthMeta,
  lists: Blocklist[],
): Promise<AuthResults> {
  const [spf, dkim, blocklists] = await Promise.all([
    checkSpf(resolver, meta),
    checkDkim(resolver, raw),
    lists.length === 0 || forbiddenReason(meta.ip)
      ? Promise.resolve([])
      : checkBlocklists(resolver, meta.ip, lists),
  ]);
  const dmarc = await checkDmarc(resolver, fromDomain(raw), spf, dkim);
  return { spf, dkim, dmarc, blocklists };
}

export function refusal(
  auth: AuthResults,
  refuse: readonly RefuseCheck[],
  ip: string,
): { code: number; text: string } | null {
  const listed = auth.blocklists.filter((l) => l.status === "listed");
  if (refuse.includes("blocklist") && listed.length > 0) {
    return { code: 554, text: `5.7.1 ${ip} is listed on ${listed.map((l) => l.name).join(", ")}` };
  }
  if (refuse.includes("spf") && auth.spf.result === "fail") {
    return { code: 550, text: `5.7.23 SPF check failed for ${auth.spf.domain}` };
  }
  if (refuse.includes("dmarc")) {
    if (auth.dmarc.result === "temperror") {
      return { code: 451, text: "4.7.0 DMARC check could not be completed, try again later" };
    }
    if (auth.dmarc.result === "fail" && auth.dmarc.policy === "reject") {
      return { code: 550, text: `5.7.1 Rejected by the DMARC policy of ${auth.dmarc.domain}` };
    }
  }
  return null;
}

export function authPayload(auth: AuthResults) {
  return {
    spf: auth.spf,
    dkim: auth.dkim,
    dmarc: auth.dmarc,
    blocklists: auth.blocklists.map((l) => ({ list: l.list, status: l.status, detail: l.detail })),
  };
}
