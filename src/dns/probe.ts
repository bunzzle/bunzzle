import { askServer, type QueryType, type Server } from "./resolver.ts";
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
