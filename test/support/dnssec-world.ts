import {
  type DnsMessage,
  type DsData,
  Rcode,
  type ResourceRecord,
  RRType,
} from "../../src/dns/wire.ts";
import { isSubdomain } from "../../src/dnssec/rrset.ts";
import { ds, record, type SignOptions, sign, type ZoneKey, zoneKey } from "./dnssec.ts";

export interface WorldZone {
  name: string;
  ksk: ZoneKey;
  zsk: ZoneKey;
  records: ResourceRecord[];
  signed: boolean;
  sign: SignOptions;
}

export interface ZoneOptions {
  algorithm?: number;
  signed?: boolean;
  delegated?: boolean;
  sign?: SignOptions;
}

const soa = (zone: string) =>
  record(
    zone,
    RRType.SOA,
    Uint8Array.from([0, 0, 1, 2, 3, 4, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0, 60]),
    60,
  );

export class TestWorld {
  readonly zones = new Map<string, WorldZone>();
  readonly queries: { name: string; type: number }[] = [];
  readonly overrides = new Map<string, (m: DnsMessage) => DnsMessage>();
  #answers = new Map<string, ResourceRecord[]>();

  get anchors(): DsData[] {
    const root = this.zones.get("");
    return root ? [ds(root.ksk).ds] : [];
  }

  async zone(name: string, o: ZoneOptions = {}): Promise<WorldZone> {
    const algorithm = o.algorithm ?? 13;
    const z: WorldZone = {
      name,
      ksk: await zoneKey(name, algorithm),
      zsk: await zoneKey(name, algorithm, { ksk: false }),
      records: [soa(name)],
      signed: o.signed ?? true,
      sign: o.sign ?? {},
    };
    this.zones.set(name, z);
    if (name !== "" && o.delegated !== false) {
      const parent = this.zoneOf(name, true);
      if (parent && z.signed) parent.records.push(ds(z.ksk));
    }
    return z;
  }

  add(...records: ResourceRecord[]): void {
    for (const r of records) (this.zoneOf(r.name, false) as WorldZone).records.push(r);
  }

  zoneOf(name: string, parentOnly: boolean): WorldZone | undefined {
    let best: WorldZone | undefined;
    for (const z of this.zones.values()) {
      if (parentOnly && z.name === name) continue;
      if (isSubdomain(name, z.name) && (!best || z.name.length > best.name.length)) best = z;
    }
    return best;
  }

  async build(): Promise<void> {
    this.#answers.clear();
    for (const z of this.zones.values()) {
      const groups = new Map<string, ResourceRecord[]>();
      const all = [...z.records, z.ksk.record, z.zsk.record];
      for (const r of all) {
        const key = `${r.name}|${r.rrtype}`;
        groups.set(key, [...(groups.get(key) ?? []), r]);
      }
      for (const [key, set] of groups) {
        const out = [...set];
        if (z.signed) {
          const isKeys = set[0]?.rrtype === RRType.DNSKEY;
          out.push(await sign(set, isKeys ? z.ksk : z.zsk, z.sign));
        }
        this.#answers.set(`${z.name}#${key}`, out);
      }
    }
  }

  #lookup(zone: WorldZone, name: string, type: number): ResourceRecord[] {
    return this.#answers.get(`${zone.name}#${name}|${type}`) ?? [];
  }

  fetch = async (name: string, type: number): Promise<DnsMessage> => {
    this.queries.push({ name, type });
    const answers: ResourceRecord[] = [];
    let current = name;
    let rcode: number = Rcode.NOERROR;
    let zone = this.zoneOf(current, type === RRType.DS) as WorldZone;
    for (let hops = 0; hops < 8; hops++) {
      zone = this.zoneOf(current, type === RRType.DS) as WorldZone;
      const direct = this.#lookup(zone, current, type);
      if (direct.length > 0) {
        answers.push(...direct);
        break;
      }
      const cname = this.#lookup(zone, current, RRType.CNAME);
      const target = cname.find((r) => r.type === "CNAME");
      if (target?.type === "CNAME") {
        answers.push(...cname);
        current = target.target;
        continue;
      }
      const exists = zone.records.some((r) => r.name === current || r.name.endsWith(`.${current}`));
      if (!exists && !this.zones.has(current)) rcode = Rcode.NXDOMAIN;
      break;
    }
    const authority = answers.length === 0 ? this.#lookup(zone, zone.name, RRType.SOA) : [];
    const msg: DnsMessage = {
      id: 0,
      rcode,
      truncated: false,
      authenticated: false,
      question: { name, type },
      answers,
      authority,
    };
    const override = this.overrides.get(`${name}|${type}`);
    return override ? override(msg) : msg;
  };
}

export async function world(
  zones: [string, ZoneOptions?][],
  records: ResourceRecord[] = [],
): Promise<TestWorld> {
  const w = new TestWorld();
  for (const [name, o] of zones) await w.zone(name, o);
  w.add(...records);
  await w.build();
  return w;
}
