import { describe, expect, test } from "bun:test";
import { type DnsMessage, decodeMessage, type ResourceRecord, RRType } from "../../src/dns/wire.ts";
import { canonicalCompare } from "../../src/dnssec/denial.ts";
import { ROOT_ANCHORS, Validator } from "../../src/dnssec/validator.ts";
import { a, record } from "../support/dnssec.ts";
import { type TestWorld, world, type ZoneOptions } from "../support/dnssec-world.ts";

const v = (w: TestWorld) => new Validator({ fetch: w.fetch, anchors: w.anchors });
const isProof = (r: ResourceRecord) =>
  r.type === "NSEC" ||
  r.type === "NSEC3" ||
  (r.type === "RRSIG" &&
    (r.rrsig.typeCovered === RRType.NSEC || r.rrsig.typeCovered === RRType.NSEC3));
const strip = (w: TestWorld, name: string, type: number) =>
  w.overrides.set(`${name}|${type}`, (m) => ({
    ...m,
    authority: m.authority.filter((r) => !isProof(r)),
  }));

test("canonical order: labels from the right, shorter first", () => {
  const names = [
    "z.example",
    "example",
    "*.z.example",
    "a.example",
    "yljkjljk.a.example",
    "zabc.a.example",
    "z.a.example",
    "\u0001.z.example",
  ];
  expect([...names].sort(canonicalCompare)).toEqual([
    "example",
    "a.example",
    "yljkjljk.a.example",
    "z.a.example",
    "zabc.a.example",
    "z.example",
    "\u0001.z.example",
    "*.z.example",
  ]);
});

for (const denial of ["nsec", "nsec3"] as const) {
  const z = (o: ZoneOptions = {}): ZoneOptions => ({ denial, ...o });
  const standard = (records: ResourceRecord[], child?: ZoneOptions) =>
    world(
      [
        ["", z()],
        ["test", z()],
        ["example.test", z()],
        ...(child ? [["child.example.test", z(child)] as [string, ZoneOptions]] : []),
      ],
      records,
    );

  describe(`${denial} proofs`, () => {
    test("NXDOMAIN, NODATA and empty non-terminals are proven", async () => {
      const w = await standard([
        a("www.example.test", "192.0.2.1"),
        a("a.b.example.test", "192.0.2.2"),
      ]);
      expect(await v(w).validate("nothing.example.test", RRType.A)).toMatchObject({
        status: "secure",
        message: { rcode: 3 },
      });
      expect(await v(w).validate("www.example.test", RRType.AAAA)).toMatchObject({
        status: "secure",
        message: { rcode: 0 },
      });
      expect(await v(w).validate("b.example.test", RRType.A)).toMatchObject({
        status: "secure",
        message: { rcode: 0 },
      });
    });

    test("a missing or forged proof, or a proof for the wrong answer, is bogus", async () => {
      const w = await standard([a("www.example.test", "192.0.2.1")]);
      strip(w, "nothing.example.test", RRType.A);
      expect(await v(w).validate("nothing.example.test", RRType.A)).toMatchObject({
        status: "bogus",
        reason: "the denial of nothing.example.test is not proven",
      });

      w.overrides.set(`www.example.test|${RRType.AAAA}`, (m) => ({
        ...m,
        authority: m.authority.map((r) =>
          r.type === "NSEC" || r.type === "NSEC3"
            ? { ...r, rdata: Uint8Array.from([...r.rdata.subarray(0, -1), 0xff]) }
            : r,
        ),
      }));
      expect((await v(w).validate("www.example.test", RRType.AAAA)).status).toBe("bogus");

      w.overrides.set(`www.example.test|${RRType.TXT}`, (m) => ({ ...m, rcode: 3 }));
      expect(await v(w).validate("www.example.test", RRType.TXT)).toMatchObject({
        status: "bogus",
        reason: "the denial of www.example.test does not match the answer",
      });
    });

    test("wildcard answers need a proof that the name itself does not exist", async () => {
      const w = await standard([a("*.example.test", "192.0.2.7")]);
      const ok = await v(w).validate("any.example.test", RRType.A);
      expect(ok.status).toBe("secure");
      expect(ok.message.answers.find((r) => r.type === "A")?.name).toBe("any.example.test");
      expect(await v(w).validate("any.example.test", RRType.AAAA)).toMatchObject({
        status: "secure",
      });
      strip(w, "other.example.test", RRType.A);
      expect(await v(w).validate("other.example.test", RRType.A)).toMatchObject({
        status: "bogus",
        reason: "other.example.test comes from a wildcard that is not proven",
      });
    });

    test("an unsigned delegation makes everything below it insecure, and is remembered", async () => {
      const w = await standard([a("www.child.example.test", "192.0.2.3")], { signed: false });
      const r = await v(w).validate("www.child.example.test", RRType.A);
      expect(r).toMatchObject({
        status: "insecure",
        reason: "child.example.test is delegated without DS",
      });
      const validator = v(w);
      await validator.validate("www.child.example.test", RRType.A);
      const before = w.queries.length;
      await validator.validate("mail.child.example.test", RRType.A);
      expect(w.queries.length - before).toBe(1);
    });

    test("a signed zone whose parent has no DS for it is insecure", async () => {
      const w = await standard([a("www.child.example.test", "192.0.2.3")], { delegated: false });
      expect(await v(w).validate("www.child.example.test", RRType.A)).toMatchObject({
        status: "insecure",
      });
    });

    test("an unsigned answer inside a signed zone is bogus", async () => {
      const w = await standard([a("www.example.test", "192.0.2.1")]);
      w.overrides.set(`www.example.test|${RRType.A}`, (m) => ({
        ...m,
        answers: m.answers.filter((r) => r.type !== "RRSIG"),
      }));
      expect(await v(w).validate("www.example.test", RRType.A)).toMatchObject({
        status: "bogus",
        reason: "www.example.test is not signed",
      });
    });

    test("the parent's delegation proof cannot deny names inside a signed child", async () => {
      const w = await standard([a("www.child.example.test", "192.0.2.3")], {});
      const parentProof = (await w.fetch("nothing.example.test", RRType.A)).authority.filter(
        isProof,
      );
      w.overrides.set(`gone.child.example.test|${RRType.A}`, (m) => ({
        ...m,
        rcode: 3,
        authority: parentProof,
      }));
      expect((await v(w).validate("gone.child.example.test", RRType.A)).status).toBe("bogus");
    });
  });
}

describe("nsec3 parameters", () => {
  test("salt and a few iterations are fine", async () => {
    const o: ZoneOptions = { denial: "nsec3", salt: Uint8Array.from([0xab, 0xcd]), iterations: 5 };
    const w = await world(
      [
        ["", o],
        ["test", o],
        ["example.test", o],
      ],
      [a("www.example.test", "192.0.2.1")],
    );
    expect(await v(w).validate("nothing.example.test", RRType.A)).toMatchObject({
      status: "secure",
    });
  });

  test("more than 50 iterations make the zone insecure", async () => {
    const o: ZoneOptions = { denial: "nsec3" };
    const w = await world(
      [
        ["", o],
        ["test", o],
        ["example.test", { ...o, iterations: 100 }],
      ],
      [a("www.example.test", "192.0.2.1")],
    );
    expect(await v(w).validate("nothing.example.test", RRType.A)).toMatchObject({
      status: "insecure",
      reason: "example.test uses too many NSEC3 iterations",
    });
  });

  test("opt-out leaves unsigned delegations out of the chain; they are insecure", async () => {
    const o: ZoneOptions = { denial: "nsec3", optOut: true };
    const w = await world(
      [
        ["", o],
        ["test", o],
        ["example.test", o],
        ["child.example.test", { signed: false }],
      ],
      [a("www.example.test", "192.0.2.1"), a("www.child.example.test", "192.0.2.3")],
    );
    expect(await v(w).validate("www.child.example.test", RRType.A)).toMatchObject({
      status: "insecure",
    });
    expect(await v(w).validate("www.example.test", RRType.A)).toMatchObject({ status: "secure" });
  });

  test("opt-out still proves an unsigned delegation when the zone has a wildcard", async () => {
    const o: ZoneOptions = { denial: "nsec3", optOut: true };
    const w = await world(
      [
        ["", o],
        ["test", o],
        ["example.test", o],
        ["child.example.test", { signed: false }],
      ],
      [a("*.example.test", "192.0.2.9"), a("www.child.example.test", "192.0.2.3")],
    );
    expect(await v(w).validate("www.child.example.test", RRType.A)).toMatchObject({
      status: "insecure",
    });
  });
});

test("a DNAME at an ancestor cannot be used to deny names below it", async () => {
  const w = await world(
    [
      ["", {}],
      ["test", {}],
      ["example.test", {}],
    ],
    [record("old.example.test", 39, Uint8Array.from([3, 110, 101, 119, 4, 116, 101, 115, 116, 0]))],
  );
  expect((await v(w).validate("x.old.example.test", RRType.A)).status).toBe("bogus");
});

test("real denials: the root NSEC proof is secure, com NSEC3 opt-out is insecure", async () => {
  const files: Record<string, string> = {
    [`|${RRType.DNSKEY}`]: "root-dnskey",
    [`bunzzle-no-such-tld|${RRType.A}`]: "root-nxdomain",
    [`com|${RRType.DS}`]: "nsec3-zone-ds",
    [`com|${RRType.DNSKEY}`]: "nsec3-zone-dnskey",
    [`bunzzle-no-such-name-4f2a.com|${RRType.A}`]: "com-nxdomain",
  };
  const fetch = async (name: string, type: number): Promise<DnsMessage> => {
    const file = files[`${name}|${type}`];
    if (!file) throw new Error(`no fixture for ${name} ${type}`);
    const hex = (await Bun.file(`${import.meta.dir}/../fixtures/dns/${file}.hex`).text()).trim();
    return decodeMessage(Uint8Array.fromHex(hex));
  };
  const v = new Validator({
    fetch,
    anchors: ROOT_ANCHORS,
    now: () => Date.parse("2026-10-19T17:20:00Z"),
  });
  expect(await v.validate("bunzzle-no-such-tld", RRType.A)).toMatchObject({
    status: "secure",
    message: { rcode: 3 },
  });
  expect(await v.validate("bunzzle-no-such-name-4f2a.com", RRType.A)).toMatchObject({
    status: "insecure",
  });
});
