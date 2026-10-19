import { describe, expect, test } from "bun:test";
import { type DnsMessage, decodeMessage, type ResourceRecord, RRType } from "../../src/dns/wire.ts";
import { ROOT_ANCHORS, Validator } from "../../src/dnssec/validator.ts";
import { a, record, sign, zoneKey } from "../support/dnssec.ts";
import { world } from "../support/dnssec-world.ts";

const FIXTURES = `${import.meta.dir}/../fixtures/dns`;
const CAPTURED = Date.parse("2026-10-19T17:20:00Z");

const cname = (name: string, target: string) => {
  const labels = target.split(".");
  const wire = [...labels.flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0];
  return record(name, RRType.CNAME, Uint8Array.from(wire));
};

const standard = (records: ResourceRecord[] = [a("www.example.test", "192.0.2.1")]) =>
  world([[""], ["test"], ["example.test"]], records);

describe("chain of trust", () => {
  test("the real root keys match the built-in anchors, and org's SOA is secure", async () => {
    const files: Record<string, string> = {
      [`|${RRType.DNSKEY}`]: "root-dnskey",
      [`org|${RRType.DS}`]: "org-ds",
      [`org|${RRType.DNSKEY}`]: "rsa-zone-dnskey",
      [`org|${RRType.SOA}`]: "rsa-signed-soa",
    };
    const fetch = async (name: string, type: number): Promise<DnsMessage> => {
      const file = files[`${name}|${type}`];
      if (!file) throw new Error(`no fixture for ${name} ${type}`);
      return decodeMessage(
        Uint8Array.fromHex((await Bun.file(`${FIXTURES}/${file}.hex`).text()).trim()),
      );
    };
    const v = new Validator({ fetch, anchors: ROOT_ANCHORS, now: () => CAPTURED });
    expect(await v.validate("org", RRType.SOA)).toMatchObject({ status: "secure", reason: null });
  });

  test("a signed answer three zones deep is secure, with mixed algorithms", async () => {
    const w = await world(
      [
        ["", { algorithm: 8 }],
        ["test", { algorithm: 15 }],
        ["example.test", { algorithm: 14 }],
      ],
      [a("www.example.test", "192.0.2.1")],
    );
    const v = new Validator({ fetch: w.fetch, anchors: w.anchors });
    expect(await v.validate("www.example.test", RRType.A)).toMatchObject({ status: "secure" });
  });

  test("a changed record, a wrong anchor or an expired signature is bogus", async () => {
    const w = await standard();
    w.overrides.set(`www.example.test|${RRType.A}`, (m) => ({
      ...m,
      answers: m.answers.map((r) => (r.type === "A" ? a("www.example.test", "192.0.2.9") : r)),
    }));
    const tampered = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(tampered).toMatchObject({
      status: "bogus",
      reason: expect.stringContaining("does not verify"),
    });

    const other = await zoneKey("");
    const wrong = new Validator({
      fetch: (await standard()).fetch,
      anchors: [{ ...w.anchors[0], keyTag: other.record.dnskey.keyTag } as never],
    });
    expect(await wrong.validate("www.example.test", RRType.A)).toMatchObject({ status: "bogus" });

    const old = await world(
      [[""], ["test"], ["example.test", { sign: { inception: 1, expiration: 2 } }]],
      [a("www.example.test", "192.0.2.1")],
    );
    const expired = await new Validator({ fetch: old.fetch, anchors: old.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(expired).toMatchObject({ status: "bogus", reason: expect.stringContaining("expired") });
  });

  test("a DS that matches no key of the child is bogus", async () => {
    const w = await standard();
    const zone = w.zones.get("example.test");
    if (!zone) throw new Error("no zone");
    zone.ksk = await zoneKey("example.test");
    await w.build();
    const r = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(r).toMatchObject({
      status: "bogus",
      reason: "no DNSKEY of example.test matches its DS",
    });
  });

  test("a DS signed by the child itself is never trusted", async () => {
    const w = await standard();
    const child = w.zones.get("example.test");
    const parentSigned = await w.fetch("example.test", RRType.DS);
    const dsSet = parentSigned.answers.filter((r) => r.type === "DS");
    const selfSig = child ? await sign(dsSet, child.zsk) : null;
    w.overrides.set(`example.test|${RRType.DS}`, (m) => ({
      ...m,
      answers: [...dsSet, ...(selfSig ? [selfSig] : [])],
    }));
    const r = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(r).toMatchObject({
      status: "bogus",
      reason: "the DS for example.test is not signed by a parent zone",
    });
  });

  test("a DS set with only unsupported algorithms makes the zone insecure", async () => {
    const w = await standard();
    const test = w.zones.get("test");
    const zone = w.zones.get("example.test");
    if (!test || !zone) throw new Error("no zone");
    test.records = test.records.filter((r) => r.type !== "DS");
    const tag = zone.ksk.record.dnskey.keyTag;
    test.records.push(
      record(
        "example.test",
        RRType.DS,
        Uint8Array.from([tag >> 8, tag & 0xff, 5, 1, ...new Uint8Array(20)]),
      ),
    );
    await w.build();
    const r = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(r).toMatchObject({
      status: "insecure",
      reason: "example.test uses only unsupported algorithms",
    });
  });

  test("CNAME chains across zones: every link must be secure", async () => {
    const records = [
      cname("alias.example.test", "mail.other.test"),
      a("mail.other.test", "192.0.2.5"),
    ];
    const w = await world([[""], ["test"], ["example.test"], ["other.test"]], records);
    const v = new Validator({ fetch: w.fetch, anchors: w.anchors });
    const ok = await v.validate("alias.example.test", RRType.A);
    expect(ok.status).toBe("secure");
    expect(ok.message.answers.filter((r) => r.type !== "RRSIG").map((r) => r.type)).toEqual([
      "CNAME",
      "A",
    ]);
    w.overrides.set(`alias.example.test|${RRType.A}`, (m) => ({
      ...m,
      answers: m.answers.filter((r) => !(r.type === "RRSIG" && r.rrsig.typeCovered === RRType.A)),
    }));
    const r = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "alias.example.test",
      RRType.A,
    );
    expect(r).toMatchObject({ status: "bogus", reason: "mail.other.test is not signed" });
  });

  test("zone keys are cached; concurrent answers share one lookup", async () => {
    const w = await standard([
      a("www.example.test", "192.0.2.1"),
      a("mail.example.test", "192.0.2.2"),
    ]);
    const v = new Validator({ fetch: w.fetch, anchors: w.anchors });
    await Promise.all([
      v.validate("www.example.test", RRType.A),
      v.validate("mail.example.test", RRType.A),
    ]);
    const first = w.queries.length;
    expect(w.queries.filter((q) => q.type === RRType.DNSKEY)).toHaveLength(3);
    await v.validate("www.example.test", RRType.A);
    expect(w.queries.length).toBe(first + 1);
  });

  test("a signed zone full of keys with one key tag gets only a few tries", async () => {
    const w = await standard();
    const zone = w.zones.get("example.test");
    if (!zone) throw new Error("no zone");
    const tag = zone.zsk.record.dnskey.keyTag;
    const fakes = await Promise.all(
      Array.from({ length: 20 }, () => zoneKey("example.test", 13, { ksk: false })),
    );
    zone.records.unshift(
      ...fakes.map((k) => ({ ...k.record, dnskey: { ...k.record.dnskey, keyTag: tag } })),
    );
    await w.build();
    const r = await new Validator({ fetch: w.fetch, anchors: w.anchors }).validate(
      "www.example.test",
      RRType.A,
    );
    expect(r).toMatchObject({
      status: "bogus",
      reason: expect.stringContaining("does not verify"),
    });
  });

  test("a fetch that fails is bogus for that answer only, and not cached", async () => {
    const w = await standard();
    let fail = true;
    const fetch = async (name: string, type: number) => {
      if (fail && type === RRType.DNSKEY && name === "test") throw new Error("timeout");
      return w.fetch(name, type);
    };
    const v = new Validator({ fetch, anchors: w.anchors });
    expect(await v.validate("www.example.test", RRType.A)).toMatchObject({
      status: "bogus",
      reason: "timeout",
    });
    fail = false;
    expect(await v.validate("www.example.test", RRType.A)).toMatchObject({ status: "secure" });
  });
});
