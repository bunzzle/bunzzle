import type { Resolver } from "../dns/resolver.ts";

export type StsMode = "enforce" | "testing" | "none";

export interface StsPolicy {
  domain: string;
  id: string;
  mode: StsMode;
  mx: string[];
  maxAge: number;
  fetchedAt: number;
}

export type FetchText = (
  url: string,
) => Promise<{ status: number; type: string; body: string } | null>;

const MAX_AGE = 31_557_600;

export function parsePolicy(text: string): Pick<StsPolicy, "mode" | "mx" | "maxAge"> | null {
  let version = "";
  let mode: StsMode | null = null;
  let maxAge: number | null = null;
  const mx: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "version") version = value;
    else if (key === "mode" && (value === "enforce" || value === "testing" || value === "none"))
      mode = value;
    else if (key === "max_age" && /^\d{1,10}$/.test(value))
      maxAge = Math.min(MAX_AGE, Number(value));
    else if (key === "mx" && /^(\*\.)?[a-z0-9.-]+$/i.test(value)) mx.push(value.toLowerCase());
  }
  if (version !== "STSv1" || !mode || maxAge === null) return null;
  if (mode !== "none" && mx.length === 0) return null;
  return { mode, mx, maxAge };
}

export function mxAllowed(host: string, patterns: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return patterns.some((p) => {
    if (p.startsWith("*.")) {
      const suffix = p.slice(1);
      const label = h.slice(0, h.length - suffix.length);
      return h.endsWith(suffix) && label.length > 0 && !label.includes(".");
    }
    return h === p;
  });
}

function txtId(strings: string[]): string | null {
  for (const s of strings) {
    if (!/^v=STSv1\s*;/i.test(s.trim())) continue;
    const m = /(?:^|;)\s*id=([A-Za-z0-9]{1,32})\s*(?:;|$)/.exec(s);
    if (m) return m[1] as string;
  }
  return null;
}

export class StsCache {
  readonly #cache = new Map<string, StsPolicy>();
  readonly #absent = new Map<string, number>();

  constructor(
    private readonly resolver: Resolver,
    private readonly fetchText: FetchText,
    private readonly now: () => number = Date.now,
  ) {}

  #valid(p: StsPolicy | undefined): p is StsPolicy {
    return p !== undefined && this.now() < p.fetchedAt + p.maxAge * 1000;
  }

  async policyFor(domain: string): Promise<StsPolicy | null> {
    const d = domain.toLowerCase();
    const cached = this.#cache.get(d);
    const absentUntil = this.#absent.get(d);
    if (!cached && absentUntil !== undefined && this.now() < absentUntil) return null;
    let id: string | null = null;
    try {
      const answer = await this.resolver.query(`_mta-sts.${d}`, "TXT");
      id = txtId(answer.records.flatMap((r) => (r.type === "TXT" ? [r.strings.join("")] : [])));
    } catch {
      return this.#valid(cached) ? cached : null;
    }
    if (!id) {
      if (this.#valid(cached)) return cached;
      this.#absent.set(d, this.now() + 3_600_000);
      return null;
    }
    if (this.#valid(cached) && cached.id === id) return cached;
    const res = await this.fetchText(`https://mta-sts.${d}/.well-known/mta-sts.txt`).catch(
      () => null,
    );
    const parsed =
      res && res.status === 200 && res.type.toLowerCase().startsWith("text/plain")
        ? parsePolicy(res.body)
        : null;
    if (!parsed) return this.#valid(cached) ? cached : null;
    const policy: StsPolicy = { domain: d, id, ...parsed, fetchedAt: this.now() };
    this.#cache.set(d, policy);
    this.#absent.delete(d);
    return policy;
  }
}
