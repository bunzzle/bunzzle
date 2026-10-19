import { describe, expect, test } from "bun:test";
import { type DnsMessage, decodeMessage, type ResourceRecord } from "../../src/dns/wire.ts";
import { dsMatches } from "../../src/dnssec/crypto.ts";
import { verifyRrset } from "../../src/dnssec/rrset.ts";
import { a, ds, record, sign, zoneKey } from "../support/dnssec.ts";

const FIXTURES = `${import.meta.dir}/../fixtures/dns`;
const CAPTURED = Date.parse("2026-10-19T17:20:00Z");
const YEAR = 365 * 86_400_000;

async function fixture(name: string): Promise<DnsMessage> {
  const hex = (await Bun.file(`${FIXTURES}/${name}.hex`).text()).trim();
  return decodeMessage(Uint8Array.fromHex(hex));
}

const keysOf = (m: DnsMessage) => m.answers.flatMap((r) => (r.type === "DNSKEY" ? [r.dnskey] : []));

async function verifyAll(
  records: ResourceRecord[],
  zone: string,
  keys: ReturnType<typeof keysOf>,
  now = CAPTURED,
) {
  const out: string[] = [];
  for (const s of records.flatMap((r) => (r.type === "RRSIG" ? [r] : []))) {
    const set = records.filter((r) => r.rrtype === s.rrsig.typeCovered && r.name === s.name);
    const r = await verifyRrset(set, s.rrsig, zone, keys, now);
    out.push(r.ok ? "ok" : r.reason);
  }
  return out;
}

describe("real signatures", () => {
  test("RSA: root keys, the root's DS for org, org's 1024-bit zone key", async () => {
    const root = await fixture("root-dnskey");
    const org = await fixture("rsa-zone-dnskey");
    expect(await verifyAll(root.answers, "", keysOf(root))).toEqual(["ok"]);
    expect(await verifyAll((await fixture("org-ds")).answers, "", keysOf(root))).toEqual(["ok"]);
    expect(await verifyAll((await fixture("rsa-signed-soa")).answers, "org", keysOf(org))).toEqual([
      "ok",
    ]);
    expect(await verifyAll((await fixture("root-nxdomain")).authority, "", keysOf(root))).toEqual([
      "ok",
      "ok",
      "ok",
    ]);
  });

  test("ECDSA P-256: address records and NSEC3 denials", async () => {
    const zone = await fixture("ecdsa-zone-dnskey");
    const name = zone.answers[0]?.name as string;
    expect(await verifyAll((await fixture("ecdsa-signed-a")).answers, name, keysOf(zone))).toEqual([
      "ok",
    ]);
    const com = await fixture("nsec3-zone-dnskey");
    const denial = await verifyAll((await fixture("com-nxdomain")).authority, "com", keysOf(com));
    expect(denial).toEqual(["ok", "ok", "ok", "ok"]);
  });

  test("a captured signature expires", async () => {
    const root = await fixture("root-dnskey");
    expect(await verifyAll(root.answers, "", keysOf(root), CAPTURED + YEAR)).toEqual([
      "the signature has expired",
    ]);
  });

  test("the org DS matches the org key-signing key", async () => {
    const dsRec = (await fixture("org-ds")).answers.find((r) => r.type === "DS");
    const org = await fixture("rsa-zone-dnskey");
    const ksk = org.answers.find(
      (r) => r.type === "DNSKEY" && dsRec?.type === "DS" && r.dnskey.keyTag === dsRec.ds.keyTag,
    );
    expect(
      dsRec?.type === "DS" &&
        ksk?.type === "DNSKEY" &&
        dsMatches(dsRec.ds, "org", ksk.dnskey, ksk.rdata),
    ).toBe(true);
  });
});

describe("generated signatures", () => {
  for (const algorithm of [8, 10, 13, 14, 15]) {
    test(`algorithm ${algorithm} signs and verifies; any change breaks it`, async () => {
      const key = await zoneKey("example.test", algorithm);
      const set = [a("www.example.test", "192.0.2.1"), a("www.example.test", "192.0.2.2")];
      const sig = await sign(set, key);
      expect(
        await verifyRrset(set, sig.rrsig, "example.test", [key.record.dnskey], Date.now()),
      ).toEqual({ ok: true });
      const changed = [a("www.example.test", "192.0.2.1"), a("www.example.test", "192.0.2.3")];
      const r = await verifyRrset(
        changed,
        sig.rrsig,
        "example.test",
        [key.record.dnskey],
        Date.now(),
      );
      expect(r).toMatchObject({ ok: false, reason: expect.stringContaining("does not verify") });
    });
  }

  test("record order and duplicates do not matter", async () => {
    const key = await zoneKey("example.test");
    const x = a("www.example.test", "192.0.2.1");
    const y = a("www.example.test", "192.0.2.2");
    const sig = await sign([x, y], key);
    const keys = [key.record.dnskey];
    expect(await verifyRrset([y, x, y], sig.rrsig, "example.test", keys, Date.now())).toEqual({
      ok: true,
    });
  });

  test("a wildcard answer verifies against the wildcard owner", async () => {
    const key = await zoneKey("example.test");
    const signed = await sign([a("*.example.test", "192.0.2.1")], key);
    const answer = [a("anything.example.test", "192.0.2.1")];
    const keys = [key.record.dnskey];
    expect(await verifyRrset(answer, signed.rrsig, "example.test", keys, Date.now())).toEqual({
      ok: true,
    });
    const forged = { ...signed.rrsig, labels: 4 };
    expect(await verifyRrset(answer, forged, "example.test", keys, Date.now())).toMatchObject({
      ok: false,
      reason: "the signature has too many labels",
    });
  });

  test("signer, type, key and window are checked before the signature", async () => {
    const key = await zoneKey("example.test");
    const set = [a("www.example.test", "192.0.2.1")];
    const sig = (await sign(set, key)).rrsig;
    const keys = [key.record.dnskey];
    const now = Date.now();
    const check = (s: typeof sig, zone = "example.test", k = keys, t = now) =>
      verifyRrset(set, s, zone, k, t);
    expect(await check(sig, "other.test")).toMatchObject({
      reason: "signed by example.test, not by other.test",
    });
    expect(await check({ ...sig, typeCovered: 28 })).toMatchObject({
      reason: "the signature covers another type",
    });
    expect(await check({ ...sig, keyTag: (sig.keyTag + 1) & 0xffff })).toMatchObject({ ok: false });
    expect(await check(sig, "example.test", [{ ...key.record.dnskey, flags: 0 }])).toMatchObject({
      ok: false,
    });
    expect(await check(sig, "example.test", keys, now - 2 * 86_400_000)).toMatchObject({
      reason: "the signature is not valid yet",
    });
    const outside = [a("www.other.test", "192.0.2.1")];
    expect(await verifyRrset(outside, sig, "example.test", keys, now)).toMatchObject({ ok: false });
  });

  test("validity times wrap around 2^32 seconds", async () => {
    const key = await zoneKey("example.test");
    const set = [a("www.example.test", "192.0.2.1")];
    const sig = await sign(set, key, { inception: 0xffffff00, expiration: 0x00000100 });
    const keys = [key.record.dnskey];
    expect(await verifyRrset(set, sig.rrsig, "example.test", keys, 0xffffff80 * 1000)).toEqual({
      ok: true,
    });
    expect(
      await verifyRrset(set, sig.rrsig, "example.test", keys, 0x00000200 * 1000),
    ).toMatchObject({
      reason: "the signature has expired",
    });
  });

  test("RSA keys shorter than 1024 bits and unsupported algorithms never verify", async () => {
    const short = await zoneKey("example.test", 8, { bits: 768 });
    const set = [a("www.example.test", "192.0.2.1")];
    const sig = await sign(set, short);
    expect(
      await verifyRrset(set, sig.rrsig, "example.test", [short.record.dnskey], Date.now()),
    ).toMatchObject({ ok: false });
    const key = await zoneKey("example.test");
    const old = record(
      "example.test",
      48,
      Uint8Array.from([1, 1, 3, 5, ...key.record.dnskey.publicKey]),
    );
    const s2 = {
      ...(await sign(set, key)).rrsig,
      algorithm: 5,
      keyTag: old.type === "DNSKEY" ? old.dnskey.keyTag : 0,
    };
    expect(
      await verifyRrset(
        set,
        s2,
        "example.test",
        old.type === "DNSKEY" ? [old.dnskey] : [],
        Date.now(),
      ),
    ).toMatchObject({ ok: false });
  });

  test("DS digests SHA-256 and SHA-384 match; SHA-1 and a wrong owner do not", async () => {
    const key = await zoneKey("example.test");
    for (const type of [2, 4]) {
      expect(dsMatches(ds(key, type).ds, "example.test", key.record.dnskey, key.record.rdata)).toBe(
        true,
      );
    }
    expect(
      dsMatches(
        { ...ds(key).ds, digestType: 1 },
        "example.test",
        key.record.dnskey,
        key.record.rdata,
      ),
    ).toBe(false);
    expect(dsMatches(ds(key).ds, "other.test", key.record.dnskey, key.record.rdata)).toBe(false);
  });
});
