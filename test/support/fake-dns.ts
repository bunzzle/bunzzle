import { RRType } from "../../src/dns/wire.ts";

export interface ZoneEntry {
  MX?: [number, string][];
  A?: string[];
  AAAA?: string[];
  TXT?: string[];
  CNAME?: string;
  rcode?: number;
  ttl?: number;
  truncate?: boolean;
  silent?: boolean;
}

export type Zone = Record<string, ZoneEntry>;

function encodeName(name: string): number[] {
  if (name === "") return [0];
  return [...name.split(".").flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0];
}

function u16(n: number): number[] {
  return [n >> 8, n & 0xff];
}

function u32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function ipv6Bytes(ip: string): number[] {
  const [head = "", tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = [...h, ...new Array(8 - h.length - t.length).fill("0"), ...t];
  return groups.flatMap((g) => u16(Number.parseInt(g, 16)));
}

function rr(name: string, type: number, ttl: number, data: number[]): number[] {
  return [...encodeName(name), ...u16(type), ...u16(1), ...u32(ttl), ...u16(data.length), ...data];
}

export interface FakeDns {
  port: number;
  queries: { name: string; type: number; tcp: boolean }[];
  stop(): void;
}

function parseQuery(q: Uint8Array): { id: number; name: string; type: number; end: number } {
  const id = ((q[0] as number) << 8) | (q[1] as number);
  let p = 12;
  const labels: string[] = [];
  while (q[p] !== 0) {
    const len = q[p] as number;
    labels.push(new TextDecoder().decode(q.subarray(p + 1, p + 1 + len)));
    p += len + 1;
  }
  p++;
  const type = ((q[p] as number) << 8) | (q[p + 1] as number);
  return { id, name: labels.join("."), type, end: p + 4 };
}

function answer(zone: Zone, q: Uint8Array, tcp: boolean): Uint8Array | null {
  const { id, name, type, end } = parseQuery(q);
  const entry = zone[name];
  if (entry?.silent) return null;
  const ttl = entry?.ttl ?? 300;
  const records: number[][] = [];
  let rcode = entry ? (entry.rcode ?? 0) : 3;
  let target = name;
  let current = entry;
  if (current?.CNAME && type !== RRType.CNAME) {
    records.push(rr(name, RRType.CNAME, ttl, encodeName(current.CNAME)));
    target = current.CNAME;
    current = zone[target];
    if (!current) rcode = 3;
  }
  if (current && rcode === 0) {
    if (type === RRType.MX) {
      for (const [pref, host] of current.MX ?? []) {
        records.push(rr(target, type, ttl, [...u16(pref), ...encodeName(host)]));
      }
    }
    if (type === RRType.A) {
      for (const ip of current.A ?? [])
        records.push(rr(target, type, ttl, ip.split(".").map(Number)));
    }
    if (type === RRType.AAAA) {
      for (const ip of current.AAAA ?? []) records.push(rr(target, type, ttl, ipv6Bytes(ip)));
    }
    if (type === RRType.TXT) {
      for (const t of current.TXT ?? []) {
        const b = [...new TextEncoder().encode(t)];
        records.push(rr(target, type, ttl, [b.length, ...b]));
      }
    }
  }
  const truncated = !tcp && !!entry?.truncate;
  const authority =
    records.length === 0 && (rcode === 0 || rcode === 3)
      ? [
          rr("test", RRType.SOA, 60, [
            ...encodeName("ns.test"),
            ...encodeName("admin.test"),
            ...u32(1),
            ...u32(1),
            ...u32(1),
            ...u32(1),
            ...u32(30),
          ]),
        ]
      : [];
  const flags = 0x8000 | 0x0100 | 0x0080 | (truncated ? 0x0200 : 0) | rcode;
  const body = truncated ? [] : records.flat();
  return new Uint8Array([
    ...u16(id),
    ...u16(flags),
    ...u16(1),
    ...u16(truncated ? 0 : records.length),
    ...u16(authority.length),
    ...u16(0),
    ...q.subarray(12, end),
    ...body,
    ...authority.flat(),
  ]);
}

export async function startFakeDns(zone: Zone): Promise<FakeDns> {
  const queries: FakeDns["queries"] = [];
  const udp = await Bun.udpSocket({
    hostname: "127.0.0.1",
    binaryType: "uint8array",
    socket: {
      data(sock, data, port, address) {
        const q = parseQuery(data);
        queries.push({ name: q.name, type: q.type, tcp: false });
        const res = answer(zone, data, false);
        if (res) sock.send(res, port, address);
      },
    },
  });
  const tcp = Bun.listen({
    hostname: "127.0.0.1",
    port: udp.port,
    socket: {
      data(sock, data) {
        const msg = new Uint8Array(data).subarray(2);
        const q = parseQuery(msg);
        queries.push({ name: q.name, type: q.type, tcp: true });
        const res = answer(zone, msg, true);
        if (!res) return;
        sock.write(new Uint8Array([...u16(res.length), ...res]));
      },
    },
  });
  return {
    port: udp.port,
    queries,
    stop() {
      udp.close();
      tcp.stop(true);
    },
  };
}
