import { describe, expect, test } from "bun:test";
import {
  type DnsMessage,
  decodeMessage,
  encodeQuery,
  keyTag,
  nameToWire,
  RRType,
} from "../../src/dns/wire.ts";

const FIXTURES = `${import.meta.dir}/../fixtures/dns`;

async function fixture(name: string): Promise<DnsMessage> {
  const hex = (await Bun.file(`${FIXTURES}/${name}.hex`).text()).trim();
  return decodeMessage(Uint8Array.fromHex(hex));
}

function message(records: number[][]): Uint8Array {
  const head = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, records.length, 0, 0, 0, 0];
  return Uint8Array.from([...head, ...records.flat()]);
}

function record(owner: number[], type: number, rdata: number[]): number[] {
  return [
    ...owner,
    type >> 8,
    type & 0xff,
    0,
    1,
    0,
    0,
    0x0e,
    0x10,
    rdata.length >> 8,
    rdata.length & 0xff,
    ...rdata,
  ];
}

const wire = (name: string) => Array.from(nameToWire(name));
const upper = (name: string) => wire(name).map((c) => (c >= 0x61 && c <= 0x7a ? c - 32 : c));

describe("DNSSEC queries", () => {
  test("set DO and CD only when asked, and encode the root as one zero byte", () => {
    const plain = encodeQuery(1, "example.com", RRType.A);
    const signed = encodeQuery(1, "", RRType.DNSKEY, true);
    const flags = (q: Uint8Array) => new DataView(q.buffer).getUint16(2);
    expect(flags(plain) & 0x0010).toBe(0);
    expect(flags(signed) & 0x0010).toBe(0x0010);
    expect(signed[12]).toBe(0);
    expect(new DataView(signed.buffer).getUint16(13)).toBe(RRType.DNSKEY);
    const ttl = (q: Uint8Array) => new DataView(q.buffer).getUint32(q.length - 6);
    expect(ttl(plain)).toBe(0);
    expect(ttl(signed) & 0x8000).toBe(0x8000);
  });
});

describe("DNSSEC records from real answers", () => {
  test("root DNSKEY set: two KSKs with their known key tags, signed by one of them", async () => {
    const m = await fixture("root-dnskey");
    const keys = m.answers.flatMap((r) => (r.type === "DNSKEY" ? [r.dnskey] : []));
    expect(keys).toHaveLength(3);
    expect(keys.every((k) => k.protocol === 3 && k.algorithm === 8)).toBe(true);
    const ksks = keys.filter((k) => k.flags === 257).map((k) => k.keyTag);
    expect(ksks.sort()).toEqual([20326, 38696]);
    const sig = m.answers.find((r) => r.type === "RRSIG");
    expect(sig?.type === "RRSIG" && sig.rrsig).toMatchObject({
      typeCovered: RRType.DNSKEY,
      algorithm: 8,
      labels: 0,
      signer: "",
    });
    expect(sig?.type === "RRSIG" && ksks.includes(sig.rrsig.keyTag)).toBe(true);
  });

  test("DS for org and its signature by the root", async () => {
    const m = await fixture("org-ds");
    const ds = m.answers.find((r) => r.type === "DS");
    expect(ds?.type === "DS" && ds.ds.digestType).toBe(2);
    expect(ds?.type === "DS" && ds.ds.digest.length).toBe(32);
    const sig = m.answers.find((r) => r.type === "RRSIG");
    expect(sig?.type === "RRSIG" && sig.rrsig).toMatchObject({
      typeCovered: RRType.DS,
      labels: 1,
      signer: "",
    });
    expect(sig?.name).toBe("org");
  });

  test("RSA and ECDSA signatures over other record types", async () => {
    for (const [file, typeCovered, algorithm, length] of [
      ["rsa-signed-soa", RRType.SOA, 8, 128],
      ["ecdsa-signed-a", RRType.A, 13, 64],
    ] as const) {
      const m = await fixture(file);
      const sig = m.answers.find((r) => r.type === "RRSIG");
      expect(sig?.type === "RRSIG" && sig.rrsig).toMatchObject({ typeCovered, algorithm });
      expect(sig?.type === "RRSIG" && sig.rrsig.signer).toBe(sig?.name ?? "");
      expect(sig?.type === "RRSIG" && sig.rrsig.signature.length).toBe(length);
    }
  });

  test("NSEC denial from the root", async () => {
    const m = await fixture("root-nxdomain");
    expect(m.rcode).toBe(3);
    const nsec = m.authority.flatMap((r) => (r.type === "NSEC" ? [r] : []));
    expect(nsec).toHaveLength(2);
    expect(nsec.every((r) => r.nsec.types.includes(RRType.RRSIG))).toBe(true);
    expect(nsec.every((r) => r.nsec.types.includes(RRType.NSEC))).toBe(true);
  });

  test("NSEC3 denial from com", async () => {
    const m = await fixture("com-nxdomain");
    const nsec3 = m.authority.flatMap((r) => (r.type === "NSEC3" ? [r.nsec3] : []));
    expect(nsec3).toHaveLength(3);
    for (const n of nsec3) {
      expect(n.hashAlgorithm).toBe(1);
      expect(n.nextHashed).toHaveLength(20);
      expect(n.flags & 1).toBe(1);
    }
  });
});

describe("canonical RDATA", () => {
  test("names in MX and RRSIG are expanded and lowercased; NSEC keeps the case", () => {
    const owner = wire("example.test");
    const mx = record(owner, RRType.MX, [0, 10, 2, 0x4d, 0x58, 0xc0, 12]);
    const rrsig = record(owner, RRType.RRSIG, [
      0,
      1,
      13,
      2,
      0,
      0,
      0x0e,
      0x10,
      0x6a,
      0,
      0,
      0,
      0x69,
      0,
      0,
      0,
      0x12,
      0x34,
      ...upper("example.test"),
      9,
      9,
      9,
    ]);
    const nsec = record(owner, RRType.NSEC, [...upper("b.example.test"), 0, 1, 0x40]);
    const m = decodeMessage(message([mx, rrsig, nsec]));
    const [a, b, c] = m.answers;
    expect(a?.type === "MX" && a.mx.exchange).toBe("mx.example.test");
    expect(Array.from(a?.rdata ?? [])).toEqual([0, 10, ...wire("mx.example.test")]);
    expect(b?.type === "RRSIG" && b.rrsig.signer).toBe("example.test");
    expect(Array.from(b?.rdata ?? []).slice(18)).toEqual([...wire("example.test"), 9, 9, 9]);
    expect(c?.type === "NSEC" && c.nsec).toEqual({ next: "b.example.test", types: [RRType.A] });
    expect(Array.from(c?.rdata ?? [])).toEqual([...upper("b.example.test"), 0, 1, 0x40]);
    expect(m.answers.map((r) => r.rrtype)).toEqual([RRType.MX, RRType.RRSIG, RRType.NSEC]);
  });

  test("bad type bitmaps are refused", () => {
    const owner = wire("example.test");
    const reversed = record(owner, RRType.NSEC, [
      ...wire("b.example.test"),
      1,
      1,
      0x40,
      0,
      1,
      0x40,
    ]);
    expect(() => decodeMessage(message([reversed]))).toThrow("bad type bitmap");
    const empty = record(owner, RRType.NSEC, [...wire("b.example.test"), 0, 0]);
    expect(() => decodeMessage(message([empty]))).toThrow("bad type bitmap");
  });

  test("key tag of the root KSK-2017 RDATA is 20326", async () => {
    const m = await fixture("root-dnskey");
    const ksk = m.answers.find((r) => r.type === "DNSKEY" && r.dnskey.keyTag === 20326);
    expect(ksk && keyTag(ksk.rdata)).toBe(20326);
  });
});
