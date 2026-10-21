import type { DnsAnswer, QueryType, Resolver } from "./resolver.ts";
import { DnsWireError, Rcode, type ResourceRecord } from "./wire.ts";

export type Lookup =
  | { kind: "found"; records: ResourceRecord[] }
  | { kind: "missing"; nxdomain: boolean }
  | { kind: "failed" };

export async function lookup(resolver: Resolver, name: string, type: QueryType): Promise<Lookup> {
  let a: DnsAnswer;
  try {
    a = await resolver.query(name, type);
  } catch (err) {
    if (err instanceof DnsWireError) return { kind: "missing", nxdomain: true };
    return { kind: "failed" };
  }
  if (a.rcode === Rcode.NXDOMAIN) return { kind: "missing", nxdomain: true };
  if (a.rcode !== Rcode.NOERROR) return { kind: "failed" };
  const records = a.records.filter((r) => r.type === type);
  return records.length > 0 ? { kind: "found", records } : { kind: "missing", nxdomain: false };
}

export function txtStrings(records: ResourceRecord[]): string[] {
  return records.flatMap((r) => (r.type === "TXT" ? [r.strings.join("")] : []));
}

export function validDomain(name: string): boolean {
  if (name.length === 0 || name.length > 253) return false;
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((l) => l.length > 0 && l.length <= 63);
}
