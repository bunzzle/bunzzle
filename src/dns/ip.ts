export type Family = 4 | 6;

export function parseIPv4(s: string): Uint8Array | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i] as string;
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p.startsWith("0"))) return null;
    const n = Number(p);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

export function parseIPv6(s: string): Uint8Array | null {
  let str = s.replace(/%.*$/, "");
  const out = new Uint8Array(16);
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(str);
  let tail: number[] = [];
  if (v4) {
    const b = parseIPv4(v4[1] as string);
    if (!b) return null;
    tail = [(b[0] as number) * 256 + (b[1] as number), (b[2] as number) * 256 + (b[3] as number)];
    str = str.slice(0, -(v4[1] as string).length);
    if (str.endsWith(":") && !str.endsWith("::")) str = str.slice(0, -1);
    else if (!str.endsWith("::")) return null;
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  const parse = (h: string): number[] | null => {
    if (h === "") return [];
    const groups: number[] = [];
    for (const g of h.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      groups.push(Number.parseInt(g, 16));
    }
    return groups;
  };
  const head = parse(halves[0] as string);
  const rest = halves.length === 2 ? parse(halves[1] as string) : [];
  if (!head || !rest) return null;
  const right = [...rest, ...tail];
  const total = head.length + right.length;
  if (halves.length === 2 ? total > 7 : total !== 8) return null;
  const groups = [...head, ...new Array<number>(8 - total).fill(0), ...right];
  groups.forEach((g, i) => {
    out[i * 2] = g >> 8;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

export function familyOf(ip: string): Family | null {
  if (parseIPv4(ip)) return 4;
  if (parseIPv6(ip)) return 6;
  return null;
}

function inPrefix(addr: Uint8Array, prefix: number[], bits: number): boolean {
  for (let i = 0; i < bits; i++) {
    const byte = i >> 3;
    const mask = 0x80 >> (i & 7);
    if (((addr[byte] as number) & mask) !== ((prefix[byte] ?? 0) & mask)) return false;
  }
  return true;
}

const V4_BLOCKED: [number[], number, string][] = [
  [[0], 8, "this network"],
  [[10], 8, "private"],
  [[100, 64], 10, "shared address space"],
  [[127], 8, "loopback"],
  [[169, 254], 16, "link-local"],
  [[172, 16], 12, "private"],
  [[192, 0, 0], 24, "protocol assignments"],
  [[192, 0, 2], 24, "documentation"],
  [[192, 168], 16, "private"],
  [[198, 18], 15, "benchmarking"],
  [[198, 51, 100], 24, "documentation"],
  [[203, 0, 113], 24, "documentation"],
  [[224], 4, "multicast"],
  [[240], 4, "reserved"],
];

const V6_BLOCKED: [number[], number, string][] = [
  [[], 128, "unspecified"],
  [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128, "loopback"],
  [[0xfe, 0x80], 10, "link-local"],
  [[0xfe, 0xc0], 10, "site-local"],
  [[0xfc], 7, "private"],
  [[0xff], 8, "multicast"],
  [[0x20, 0x01, 0x0d, 0xb8], 32, "documentation"],
  [[0x01, 0x00], 64, "discard"],
];

export function forbiddenReason(ip: string): string | null {
  const v4 = parseIPv4(ip);
  if (v4) {
    for (const [prefix, bits, reason] of V4_BLOCKED) if (inPrefix(v4, prefix, bits)) return reason;
    return null;
  }
  const v6 = parseIPv6(ip);
  if (!v6) return "not an IP address";
  for (const [prefix, bits, reason] of V6_BLOCKED) if (inPrefix(v6, prefix, bits)) return reason;
  const mapped = inPrefix(v6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96);
  const nat64 = inPrefix(v6, [0, 0x64, 0xff, 0x9b], 96);
  if (mapped || nat64) return forbiddenReason(Array.from(v6.subarray(12)).join("."));
  return null;
}

export function sameAddress(a: string, b: string): boolean {
  const x = parseIPv4(a) ?? parseIPv6(a);
  const y = parseIPv4(b) ?? parseIPv6(b);
  return !!x && !!y && x.length === y.length && x.every((v, i) => v === y[i]);
}
