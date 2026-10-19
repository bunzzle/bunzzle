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
      if (sets.length === 0) {
        return { status: "bogus", reason: "a missing record is not proven", message };
      }
      let status: Status = "secure";
      let reason: string | null = null;
      for (const set of sets) {
        const r = await this.#rrset(set, budget, 0);
        status = worst(status, r.status);
        if (r.status !== "secure") reason ??= r.reason;
        if (status === "bogus") break;
      }
      return { status, reason: status === "secure" ? null : reason, message };
    } catch (err) {
      if (err instanceof Bogus) return { status: "bogus", reason: err.message, message };
      throw err;
    }
  }

  async #rrset(
    set: RRset,
    budget: Budget,
    depth: number,
  ): Promise<{ status: Status; reason: string; transient?: boolean }> {
    if (set.sigs.length === 0)
      return { status: "bogus", reason: `${set.name || "."} is not signed` };
    let reason = "";
    let transient = false;
    for (const sig of set.sigs) {
      if (sig.labels < labelCount(set.name)) {
        reason = `${set.name} comes from a wildcard that is not proven`;
        continue;
      }
      const zone = await this.#zone(sig.signer, budget, depth + 1);
      if (zone.status === "insecure") return { status: "insecure", reason: zone.reason };
      if (zone.status === "bogus") {
        reason = zone.reason;
        transient ||= zone.transient === true;
        continue;
      }
      const r = await this.#verify(set, sig, zone.keys, budget);
      if (r === null) return { status: "secure", reason: "" };
      reason = r;
    }
    return { status: "bogus", reason, ...(transient ? { transient } : {}) };
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
      if (!set) throw new Bogus(`the delegation to ${zone} is not proven`);
      const sigs = set.sigs.filter((s) => s.signer !== zone && isSubdomain(zone, s.signer));
      if (sigs.length === 0) throw new Bogus(`the DS for ${zone} is not signed by a parent zone`);
      const p = await this.#rrset({ ...set, sigs }, budget, depth);
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
