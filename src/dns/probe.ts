import type { Delegation } from "./delegation.ts";
import { askServer, type QueryType, type Resolver, type Server } from "./resolver.ts";
import type { DnsMessage } from "./wire.ts";

export interface NsMeasure {
  udp: number | null;
  tcp: number | null;
  served: number | null;
}

type Ask = (
  server: Server,
  name: string,
  type: QueryType,
  proto: "udp" | "tcp",
) => Promise<DnsMessage>;

export async function measureNs(
  server: Server,
  rawZone: string,
  ask: Ask = askServer,
): Promise<NsMeasure> {
  const zone = rawZone.toLowerCase().replace(/\.$/, "");
  const soa = async (proto: "udp" | "tcp") => {
    const msg = await ask(server, zone, "SOA", proto);
    const rr = msg.answers.find((r) => r.type === "SOA" && r.name === zone);
    return msg.rcode === 0 && msg.authoritative === true && rr?.type === "SOA"
      ? rr.soa.serial
      : null;
  };
  const check = async () => {
    const msg = await ask(server, `_check.${zone}`, "TXT", "udp");
    const rr = msg.answers.find((r) => r.type === "TXT");
    const serial = rr?.type === "TXT" ? Number(rr.strings.join("")) : Number.NaN;
    return msg.rcode === 0 && Number.isInteger(serial) ? serial : null;
  };
  const [udp, tcp, served] = await Promise.all([
    soa("udp").catch(() => null),
    soa("tcp").catch(() => null),
    check().catch(() => null),
  ]);
  return { udp, tcp, served };
}

export async function delegationAt(
  rawZone: string,
  resolver: Resolver,
  ask: Ask = askServer,
): Promise<Delegation> {
  const zone = rawZone.toLowerCase().replace(/\.$/, "");
  const labels = zone.split(".");
  const out: Delegation = {
    parent: null,
    asked: null,
    ns: [],
    glue: {},
    addresses: {},
    error: null,
  };
  let parentNs: string[] = [];
  for (let i = 1; i < labels.length && parentNs.length === 0; i++) {
    const candidate = labels.slice(i).join(".");
    const answer = await resolver.query(candidate, "NS").catch(() => null);
    parentNs = (answer?.records ?? []).flatMap((r) => (r.type === "NS" ? [r.target] : []));
    if (parentNs.length > 0) out.parent = candidate;
  }
  if (!out.parent) return { ...out, error: "no parent zone with NS records found" };
  for (const name of parentNs.sort()) {
    const a = await resolver.query(name, "A").catch(() => null);
    const ip = a?.records.find((r) => r.type === "A");
    if (ip?.type !== "A") continue;
    try {
      const msg = await ask({ host: ip.address, port: 53 }, zone, "NS", "udp");
      out.asked = name;
      out.ns = [
        ...new Set(
          [...msg.answers, ...msg.authority].flatMap((r) =>
            r.type === "NS" && r.name === zone ? [r.target.toLowerCase()] : [],
          ),
        ),
      ].sort();
      for (const r of msg.additional ?? []) {
        if ((r.type === "A" || r.type === "AAAA") && out.ns.includes(r.name.toLowerCase())) {
          const list = out.glue[r.name.toLowerCase()] ?? [];
          list.push(r.address);
          out.glue[r.name.toLowerCase()] = list.sort();
        }
      }
      for (const n of out.ns) {
        if (out.glue[n]) {
          out.addresses[n] = out.glue[n];
          continue;
        }
        const found = await Promise.all(
          (["A", "AAAA"] as const).map((t) => resolver.query(n, t).catch(() => null)),
        );
        out.addresses[n] = found
          .flatMap((a) => a?.records ?? [])
          .flatMap((r) => (r.type === "A" || r.type === "AAAA" ? [r.address] : []))
          .sort();
      }
      return out;
    } catch {}
  }
  return { ...out, error: `no answer from the servers of ${out.parent}` };
}
