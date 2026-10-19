import {
  type DnskeyData,
  type DnsMessage,
  type DsData,
  Rcode,
  type ResourceRecord,
  RRType,
  type RrsigData,
} from "../dns/wire.ts";
import { ALGORITHMS, DIGESTS, dsMatches } from "./crypto.ts";
import {
  type Denial,
  type Nsec3Record,
  type NsecRecord,
  nsec3Denial,
  nsec3WildcardProof,
  nsecDenial,
  nsecWildcardProof,
} from "./denial.ts";
import { isSubdomain, labelCount, verifyRrset } from "./rrset.ts";

export type Status = "secure" | "insecure" | "bogus";

export interface Validated {
  status: Status;
  reason: string | null;
  message: DnsMessage;
}

export type Fetch = (name: string, type: number) => Promise<DnsMessage>;

export interface ValidatorOptions {
  fetch: Fetch;
  anchors?: DsData[];
  now?: () => number;
}

export interface RRset {
  name: string;
  type: number;
  records: ResourceRecord[];
  sigs: RrsigData[];
}

const anchor = (keyTag: number, hex: string): DsData => ({
  keyTag,
  algorithm: 8,
  digestType: 2,
  digest: Uint8Array.fromHex(hex),
});

export const ROOT_ANCHORS: DsData[] = [
  anchor(20326, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
  anchor(38696, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
];

const LIMITS = { depth: 12, queries: 32, signatures: 32, keysPerSignature: 4 };
const HOUR = 3_600_000;
const BOGUS_MS = 60_000;

type ZoneState =
  | { status: "secure"; keys: DnskeyData[] }
  | { status: "insecure"; reason: string }
  | { status: "bogus"; reason: string; transient?: boolean };

type Outcome = { status: Status; reason: string; transient?: boolean; verdict?: Denial };

const insecure = (reason: string): Outcome => ({ status: "insecure", reason });
const bogus = (reason: string): Outcome => ({ status: "bogus", reason });

class Bogus extends Error {}

class Transient extends Bogus {}

class Budget {
  queries = 0;
  signatures = 0;

  query(): void {
    if (++this.queries > LIMITS.queries) throw new Transient("too many DNS queries for one answer");
  }

  signature(): void {
    if (++this.signatures > LIMITS.signatures)
      throw new Transient("too many signatures to check for one answer");
  }
}

export function rrsets(records: ResourceRecord[]): RRset[] {
  const out = new Map<string, RRset>();
  const get = (name: string, type: number) => {
    const key = `${name}|${type}`;
    let set = out.get(key);
    if (!set) {
      set = { name, type, records: [], sigs: [] };
      out.set(key, set);
    }
    return set;
  };
  for (const r of records) {
    if (r.type === "RRSIG") get(r.name, r.rrsig.typeCovered).sigs.push(r.rrsig);
    else get(r.name, r.rrtype).records.push(r);
  }
  return [...out.values()].filter((s) => s.records.length > 0);
}

const worst = (a: Status, b: Status): Status =>
  a === "bogus" || b === "bogus"
    ? "bogus"
    : a === "insecure" || b === "insecure"
      ? "insecure"
      : "secure";

export class Validator {
  readonly #fetch: Fetch;
  readonly #anchors: DsData[];
  readonly #now: () => number;
  readonly #zones = new Map<string, { until: number; state: Promise<ZoneState> }>();
  readonly #unsignedAt = new Map<string, number>();

  constructor(o: ValidatorOptions) {
    this.#fetch = o.fetch;
    this.#anchors = o.anchors ?? ROOT_ANCHORS;
    this.#now = o.now ?? Date.now;
  }

  async validate(name: string, type: number): Promise<Validated> {
    const budget = new Budget();
    let message: DnsMessage;
    try {
      budget.query();
      message = await this.#fetch(name, type);
    } catch (err) {
      return {
        status: "bogus",
        reason: (err as Error).message,
        message: emptyMessage(),
      };
    }
    try {
      if (message.rcode !== Rcode.NOERROR && message.rcode !== Rcode.NXDOMAIN) {
        return { status: "bogus", reason: `the server answered rcode ${message.rcode}`, message };
      }
      const sets = rrsets(message.answers);
      const acc: { status: Status; reason: string | null } = { status: "secure", reason: null };
      const add = (r: Outcome) => {
        acc.status = worst(acc.status, r.status);
        if (r.status !== "secure") acc.reason ??= r.reason;
      };
      for (const set of sets) {
        add(await this.#rrset(set, message.authority, budget, 0));
        if (acc.status === "bogus") break;
      }
      const end = chainEnd(sets, name, type);
      if (acc.status !== "bogus" && !sets.some((x) => x.name === end && x.type === type)) {
        add(await this.#denial(message, end, type, budget, 0, true));
      }
      return { status: acc.status, reason: acc.status === "secure" ? null : acc.reason, message };
    } catch (err) {
      if (err instanceof Bogus) return { status: "bogus", reason: err.message, message };
      throw err;
    }
  }

  async #rrset(
    set: RRset,
    authority: ResourceRecord[],
    budget: Budget,
    depth: number,
  ): Promise<Outcome> {
    if (set.sigs.length === 0) return this.#unsigned(set.name, budget, depth);
    let reason = "";
    let transient = false;
    for (const sig of set.sigs) {
      const zone = await this.#zone(sig.signer, budget, depth + 1);
      if (zone.status === "insecure") return insecure(zone.reason);
      if (zone.status === "bogus") {
        reason = zone.reason;
        transient ||= zone.transient === true;
        continue;
      }
      const r = await this.#verify(set, sig, zone.keys, budget);
      if (r !== null) {
        reason = r;
        continue;
      }
      const own = labelCount(set.name) - (set.name.startsWith("*.") || set.name === "*" ? 1 : 0);
      if (sig.labels < own) {
        const proof = await this.#proofs(authority, sig.signer, budget, depth);
        if (proof.outcome) return proof.outcome;
        const proven = proof.nsec3.length
          ? nsec3WildcardProof(proof.nsec3, sig.signer, set.name, sig.labels)
          : nsecWildcardProof(proof.nsec, set.name);
        if (!proven) {
          reason = `${set.name} comes from a wildcard that is not proven`;
          continue;
        }
      }
      return { status: "secure", reason: "" };
    }
    return { status: "bogus", reason, ...(transient ? { transient } : {}) };
  }

  async #proofs(
    authority: ResourceRecord[],
    zone: string,
    budget: Budget,
    depth: number,
  ): Promise<{ outcome: Outcome | null; nsec: NsecRecord[]; nsec3: Nsec3Record[] }> {
    const nsec: NsecRecord[] = [];
    const nsec3: Nsec3Record[] = [];
    for (const set of rrsets(authority)) {
      if (set.type !== RRType.NSEC && set.type !== RRType.NSEC3) continue;
      const sigs = set.sigs.filter((g) => g.signer === zone);
      if (sigs.length === 0) continue;
      const r = await this.#rrset({ ...set, sigs }, [], budget, depth);
      if (r.status !== "secure") return { outcome: r, nsec, nsec3 };
      for (const rec of set.records) {
        if (rec.type === "NSEC") nsec.push({ owner: rec.name, nsec: rec.nsec });
        if (rec.type === "NSEC3") nsec3.push({ owner: rec.name, nsec3: rec.nsec3 });
      }
    }
    return { outcome: null, nsec, nsec3 };
  }

  async #denial(
    message: DnsMessage,
    name: string,
    type: number,
    budget: Budget,
    depth: number,
    walk: boolean,
  ): Promise<Outcome> {
    const signers = rrsets(message.authority)
      .flatMap((x) => x.sigs.map((g) => g.signer))
      .filter((z) => isSubdomain(name, z) && (type !== RRType.DS || z !== name))
      .sort((a, b) => b.length - a.length);
    const zone = signers[0];
    if (zone === undefined) {
      return walk
        ? this.#unsigned(name, budget, depth)
        : bogus(`the denial of ${name || "."} is not signed`);
    }
    const keys = await this.#zone(zone, budget, depth + 1);
    if (keys.status === "insecure") return insecure(keys.reason);
    if (keys.status === "bogus")
      return {
        status: "bogus",
        reason: keys.reason,
        ...(keys.transient ? { transient: true } : {}),
      };
    const proof = await this.#proofs(message.authority, zone, budget, depth);
    if (proof.outcome) return proof.outcome;
    const verdict = proof.nsec3.length
      ? nsec3Denial(proof.nsec3, zone, name, type)
      : nsecDenial(proof.nsec, name, type);
    if (verdict === "too-many-iterations")
      return insecure(`${zone || "."} uses too many NSEC3 iterations`);
    if (verdict === null) return bogus(`the denial of ${name || "."} is not proven`);
    if (verdict === "insecure")
      return { ...insecure(`${name} is in an unsigned delegation`), verdict };
    const nx = message.rcode === Rcode.NXDOMAIN;
    if (nx !== (verdict === "nxdomain"))
      return bogus(`the denial of ${name || "."} does not match the answer`);
    return { status: "secure", reason: "", verdict };
  }

  async #unsigned(name: string, budget: Budget, depth: number): Promise<Outcome> {
    const parts = name === "" ? [] : name.split(".");
    const now = this.#now();
    for (let i = 0; i < parts.length; i++) {
      const cut = parts.slice(i).join(".");
      if ((this.#unsignedAt.get(cut) ?? 0) > now)
        return insecure(`${cut} is in an unsigned delegation`);
    }
    for (let i = parts.length - 1; i >= 0; i--) {
      const cut = parts.slice(i).join(".");
      budget.query();
      const msg = await this.#fetch(cut, RRType.DS);
      const set = rrsets(msg.answers).find((x) => x.name === cut && x.type === RRType.DS);
      if (set) {
        const z = await this.#zone(cut, budget, depth + 1);
        if (z.status === "insecure") return insecure(z.reason);
        if (z.status === "bogus")
          return { status: "bogus", reason: z.reason, ...(z.transient ? { transient: true } : {}) };
        continue;
      }
      const d = await this.#denial(msg, cut, RRType.DS, budget, depth + 1, false);
      if (d.status === "insecure") {
        if (d.verdict === "insecure") this.#unsignedAt.set(cut, now + HOUR);
        return d;
      }
      if (d.status === "bogus") return d;
    }
    return bogus(`${name || "."} is not signed`);
  }

  async #verify(
    set: RRset,
    sig: RrsigData,
    keys: DnskeyData[],
    budget: Budget,
  ): Promise<string | null> {
    const matching = keys
      .filter((k) => k.keyTag === sig.keyTag && k.algorithm === sig.algorithm)
      .slice(0, LIMITS.keysPerSignature);
    if (matching.length === 0) return `no key ${sig.keyTag} in ${sig.signer || "."}`;
    let reason = "";
    for (const key of matching) {
      budget.signature();
      const r = await verifyRrset(set.records, sig, sig.signer, [key], this.#now());
      if (r.ok) return null;
      reason = r.reason;
    }
    return `${set.name || "."}: ${reason}`;
  }

  #zone(zone: string, budget: Budget, depth: number): Promise<ZoneState> {
    const now = this.#now();
    const cached = this.#zones.get(zone);
    if (cached && cached.until > now) return cached.state;
    const entry = {
      until: now + HOUR,
      state: Promise.resolve<ZoneState>({ status: "bogus", reason: "" }),
    };
    entry.state = this.#loadZone(zone, budget, depth).then(
      ({ state, ttl }) => {
        entry.until = now + (state.status === "bogus" ? BOGUS_MS : Math.min(HOUR, ttl));
        return state;
      },
      (err: Error): ZoneState => {
        if (err instanceof Bogus && !(err instanceof Transient)) {
          entry.until = now + BOGUS_MS;
        } else if (this.#zones.get(zone) === entry) {
          this.#zones.delete(zone);
        }
        return {
          status: "bogus",
          reason: err.message,
          transient: !(err instanceof Bogus) || err instanceof Transient,
        };
      },
    );
    this.#zones.set(zone, entry);
    return entry.state;
  }

  async #loadZone(
    zone: string,
    budget: Budget,
    depth: number,
  ): Promise<{ state: ZoneState; ttl: number }> {
    if (depth > LIMITS.depth) throw new Bogus("the chain of trust is too deep");
    let ds: DsData[];
    let ttl = HOUR;
    if (zone === "") {
      ds = this.#anchors;
    } else {
      budget.query();
      const msg = await this.#fetch(zone, RRType.DS);
      const set = rrsets(msg.answers).find((s) => s.name === zone && s.type === RRType.DS);
      if (!set) {
        const d = await this.#denial(msg, zone, RRType.DS, budget, depth, false);
        if (d.status === "insecure")
          return { state: { status: "insecure", reason: d.reason }, ttl };
        if (d.transient) throw new Transient(d.reason);
        throw new Bogus(
          d.status === "bogus" ? d.reason : `${zone} signs itself but its parent has no DS for it`,
        );
      }
      const sigs = set.sigs.filter((s) => s.signer !== zone && isSubdomain(zone, s.signer));
      if (sigs.length === 0) throw new Bogus(`the DS for ${zone} is not signed by a parent zone`);
      const p = await this.#rrset({ ...set, sigs }, [], budget, depth);
      if (p.status === "insecure") return { state: { status: "insecure", reason: p.reason }, ttl };
      if (p.status === "bogus") throw p.transient ? new Transient(p.reason) : new Bogus(p.reason);
      ds = set.records.flatMap((r) => (r.type === "DS" ? [r.ds] : []));
      ttl = Math.min(ttl, ...set.records.map((r) => r.ttl * 1000));
    }
    const usable = ds.filter((d) => ALGORITHMS.has(d.algorithm) && DIGESTS.has(d.digestType));
    if (usable.length === 0) {
      return {
        state: { status: "insecure", reason: `${zone || "."} uses only unsupported algorithms` },
        ttl,
      };
    }

    budget.query();
    const msg = await this.#fetch(zone, RRType.DNSKEY);
    const set = rrsets(msg.answers).find((s) => s.name === zone && s.type === RRType.DNSKEY);
    if (!set) throw new Bogus(`${zone || "."} has no DNSKEY records`);
    const keys = set.records.flatMap((r) =>
      r.type === "DNSKEY" ? [{ key: r.dnskey, rdata: r.rdata }] : [],
    );
    const trusted = keys.filter((k) => usable.some((d) => dsMatches(d, zone, k.key, k.rdata)));
    if (trusted.length === 0) throw new Bogus(`no DNSKEY of ${zone || "."} matches its DS`);
    let reason = `the DNSKEY set of ${zone || "."} is not signed by a key in its DS`;
    for (const sig of set.sigs) {
      if (sig.signer !== zone) continue;
      const r = await this.#verify(
        set,
        sig,
        trusted.map((k) => k.key),
        budget,
      );
      if (r === null) {
        const expires = sig.expiration * 1000 - this.#now();
        ttl = Math.min(
          ttl,
          set.records[0] ? set.records[0].ttl * 1000 : HOUR,
          Math.max(0, expires),
        );
        return { state: { status: "secure", keys: keys.map((k) => k.key) }, ttl };
      }
      reason = r;
    }
    throw new Bogus(reason);
  }
}

function chainEnd(sets: RRset[], name: string, type: number): string {
  if (type === RRType.CNAME) return name;
  let current = name;
  for (let hops = 0; hops < 8; hops++) {
    const alias = sets.find((x) => x.name === current && x.type === RRType.CNAME);
    const target = alias?.records.find((r) => r.type === "CNAME");
    if (target?.type !== "CNAME") return current;
    current = target.target;
  }
  return current;
}

function emptyMessage(): DnsMessage {
  return {
    id: 0,
    rcode: Rcode.SERVFAIL,
    truncated: false,
    authenticated: false,
    question: null,
    answers: [],
    authority: [],
  };
}
