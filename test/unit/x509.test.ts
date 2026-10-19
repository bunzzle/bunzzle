import { describe, expect, test } from "bun:test";
import type { TlsaData } from "../../src/dns/wire.ts";
import { verifyDane } from "../../src/smtp/dane.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { nameMatches, verifyChain } from "../../src/x509/verify.ts";
import { type Issued, type IssueOptions, issue, type KeyKind, sha256 } from "../support/x509.ts";

const MX = "mx.example.test";
const DAY = 86_400_000;

async function chainOf(kind: KeyKind = "p256", leaf: Partial<IssueOptions> = {}) {
  const root = await issue({ name: "Root", kind, ca: true, keyUsage: "sign-certs" });
  const int = await issue({ name: "Intermediate", issuer: root, ca: true, keyUsage: "sign-certs" });
  const end = await issue({ name: MX, issuer: int, kind: "p256", dns: [MX], ...leaf });
  return { root, int, leaf: end };
}

const tlsa = (usage: number, selector: number, matching: number, data: Uint8Array): TlsaData => ({
  usage,
  selector,
  matching,
  data,
});

function digest(matching: number, data: Uint8Array): Uint8Array {
  if (matching === 0) return data;
  if (matching === 1) return sha256(data);
  const h = new Bun.CryptoHasher("sha512");
  h.update(data);
  return new Uint8Array(h.digest());
}

const ta = (c: Issued, selector = 0, matching = 1) =>
  tlsa(2, selector, matching, digest(matching, selector === 0 ? c.der : c.spki));

const ders = (...c: Issued[]) => c.map((x) => x.der);

describe("certificate parsing", () => {
  test("reads names, dates, key usage and constraints", async () => {
    const { int, leaf } = await chainOf();
    const c = parseCertificate(leaf.der);
    expect(c.dnsNames).toEqual([MX]);
    expect(c.commonNames).toEqual([MX]);
    expect(c.ca).toBe(false);
    expect(c.notAfter).toBeGreaterThan(Date.now());
    const i = parseCertificate(int.der);
    expect(i.ca).toBe(true);
    expect(i.keyUsage ?? 0).toBeGreaterThan(0);
  });

  test("rejects truncated or trailing data", async () => {
    const { leaf } = await chainOf();
    expect(() => parseCertificate(leaf.der.subarray(0, 40))).toThrow();
    expect(() => parseCertificate(new Uint8Array([...leaf.der, 0]))).toThrow();
    expect(() => parseCertificate(new Uint8Array([0x30, 0x82, 0xff]))).toThrow();
  });
});

describe("names", () => {
  test("exact, one-label wildcard, never partial or deeper", () => {
    expect(nameMatches("mx.example.test", "MX.Example.Test.")).toBe(true);
    expect(nameMatches("*.example.test", "mx.example.test")).toBe(true);
    expect(nameMatches("*.example.test", "a.mx.example.test")).toBe(false);
    expect(nameMatches("*.example.test", "example.test")).toBe(false);
    expect(nameMatches("mx*.example.test", "mx1.example.test")).toBe(false);
    expect(nameMatches("*.test", "example.test")).toBe(false);
  });
});

describe("chain check", () => {
  for (const kind of ["rsa", "rsa-pss", "p256", "p384", "p521", "ed25519"] as const) {
    test(`verifies ${kind} signatures`, async () => {
      const { root, int, leaf } = await chainOf(kind);
      const r = await verifyDane([ta(root)], ders(leaf, int, root), [MX]);
      expect(r).toEqual({ ok: true, how: "dane-ta" });
    });
  }

  test("refuses SHA-1 and short RSA keys", async () => {
    for (const kind of ["rsa-sha1", "rsa-1024"] as const) {
      const { root, int, leaf } = await chainOf(kind);
      const r = await verifyDane([ta(root)], ders(leaf, int, root), [MX]);
      expect(r).toMatchObject({ ok: false });
    }
  });

  test("every selector and matching type of a trust anchor", async () => {
    const { root, int, leaf } = await chainOf();
    for (const [s, m] of [
      [0, 0],
      [0, 1],
      [0, 2],
      [1, 0],
      [1, 1],
      [1, 2],
    ] as const) {
      const r = await verifyDane([ta(root, s, m)], ders(leaf, int, root), [MX]);
      expect(r, `2 ${s} ${m}`).toEqual({ ok: true, how: "dane-ta" });
    }
  });

  test("the intermediate as anchor; the root need not be sent", async () => {
    const { int, leaf } = await chainOf();
    expect(await verifyDane([ta(int, 1, 1)], ders(leaf, int), [MX])).toMatchObject({ ok: true });
  });

  test("a full certificate or key in DNS works when the server omits it", async () => {
    const { int, leaf } = await chainOf();
    expect(await verifyDane([ta(int, 0, 0)], ders(leaf), [MX])).toMatchObject({ ok: true });
    expect(await verifyDane([ta(int, 1, 0)], ders(leaf), [MX])).toMatchObject({ ok: true });
  });

  test("a hash record needs its anchor in the chain", async () => {
    const { root, int, leaf } = await chainOf();
    const r = await verifyDane([ta(root)], ders(leaf, int), [MX]);
    expect(r).toEqual({
      ok: false,
      reason: "no certificate in the chain matches its DANE-TA records",
    });
  });

  test("a wrong anchor or a forged signature fails", async () => {
    const { root, int, leaf } = await chainOf();
    const other = await issue({ name: "Other", ca: true });
    expect(await verifyDane([ta(other)], ders(leaf, int, root), [MX])).toMatchObject({ ok: false });

    const fake = await issue({
      name: "Intermediate",
      issuer: root,
      ca: true,
    });
    const forged = await issue({ name: MX, issuer: fake, dns: [MX] });
    const r = await verifyDane([ta(root)], ders(forged, int, root), [MX]);
    expect(r).toMatchObject({ ok: false });
  });

  test("names: MX host or recipient domain, SAN before CN", async () => {
    const { root, int, leaf } = await chainOf("p256", { dns: ["example.test"] });
    expect(await verifyDane([ta(root)], ders(leaf, int, root), [MX])).toMatchObject({ ok: false });
    expect(await verifyDane([ta(root)], ders(leaf, int, root), [MX, "example.test"])).toMatchObject(
      {
        ok: true,
      },
    );
    const wild = await issue({ name: "x", issuer: int, dns: ["*.example.test"] });
    expect(await verifyDane([ta(root)], ders(wild, int, root), [MX])).toMatchObject({ ok: true });
    const cnOnly = await issue({ name: MX, issuer: int });
    expect(await verifyDane([ta(root)], ders(cnOnly, int, root), [MX])).toMatchObject({ ok: true });
    const sanWins = await issue({ name: MX, issuer: int, dns: ["other.test"] });
    expect(await verifyDane([ta(root)], ders(sanWins, int, root), [MX])).toMatchObject({
      ok: false,
    });
  });

  test("dates: leaf and intermediates checked, the anchor not", async () => {
    const now = Date.now();
    const old = { notBefore: now - 60 * DAY, notAfter: now - DAY };
    const root = await issue({ name: "Root", ca: true, ...old });
    const int = await issue({ name: "Intermediate", issuer: root, ca: true });
    const leaf = await issue({ name: MX, issuer: int, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf, int, root), [MX])).toMatchObject({ ok: true });

    const oldInt = await issue({ name: "Intermediate", issuer: root, ca: true, ...old });
    const r1 = await verifyDane([ta(root)], ders(leaf, oldInt, root), [MX]);
    expect(r1).toEqual({ ok: false, reason: "an intermediate certificate has expired" });

    const oldLeaf = await issue({ name: MX, issuer: int, dns: [MX], ...old });
    const r2 = await verifyDane([ta(root)], ders(oldLeaf, int, root), [MX]);
    expect(r2).toEqual({ ok: false, reason: "the server certificate has expired" });

    const future = await issue({ name: MX, issuer: int, dns: [MX], notBefore: now + DAY });
    expect(await verifyDane([ta(root)], ders(future, int, root), [MX])).toMatchObject({
      ok: false,
    });
  });

  test("issuers must be CAs allowed to sign, within their path length", async () => {
    const root = await issue({ name: "Root", ca: true });
    const notCa = await issue({ name: "Intermediate", issuer: root, ca: false });
    const leaf = await issue({ name: MX, issuer: notCa, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf, notCa, root), [MX])).toMatchObject({
      ok: false,
      reason: "an issuing certificate in the chain is not a CA",
    });

    const noSign = await issue({
      name: "Intermediate",
      issuer: root,
      ca: true,
      keyUsage: "digital-signature",
    });
    const leaf2 = await issue({ name: MX, issuer: noSign, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf2, noSign, root), [MX])).toMatchObject({
      ok: false,
    });

    const top = await issue({ name: "Top", issuer: root, ca: true, pathLen: 0 });
    const mid = await issue({ name: "Mid", issuer: top, ca: true });
    const leaf3 = await issue({ name: MX, issuer: mid, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf3, mid, top, root), [MX])).toEqual({
      ok: false,
      reason: "the chain is longer than an issuing certificate allows",
    });
  });

  test("unknown critical extensions and wrong key purposes fail", async () => {
    const { root, int } = await chainOf();
    const crit = await issue({ name: MX, issuer: int, dns: [MX], unknownCritical: true });
    expect(await verifyDane([ta(root)], ders(crit, int, root), [MX])).toMatchObject({ ok: false });
    const client = await issue({ name: MX, issuer: int, dns: [MX], eku: ["1.3.6.1.5.5.7.3.2"] });
    expect(await verifyDane([ta(root)], ders(client, int, root), [MX])).toMatchObject({
      ok: false,
    });
    const server = await issue({ name: MX, issuer: int, dns: [MX], eku: ["1.3.6.1.5.5.7.3.1"] });
    expect(await verifyDane([ta(root)], ders(server, int, root), [MX])).toMatchObject({ ok: true });
  });

  test("name constraints of the path apply", async () => {
    const root = await issue({ name: "Root", ca: true });
    const allowed = await issue({
      name: "Int",
      issuer: root,
      ca: true,
      permitted: ["example.test"],
    });
    const leaf = await issue({ name: MX, issuer: allowed, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf, allowed, root), [MX])).toMatchObject({
      ok: true,
    });
    const elsewhere = await issue({
      name: "Int",
      issuer: root,
      ca: true,
      permitted: ["other.test"],
    });
    const leaf2 = await issue({ name: MX, issuer: elsewhere, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf2, elsewhere, root), [MX])).toMatchObject({
      ok: false,
    });
    const banned = await issue({ name: "Int", issuer: root, ca: true, excluded: [MX] });
    const leaf3 = await issue({ name: MX, issuer: banned, dns: [MX] });
    expect(await verifyDane([ta(root)], ders(leaf3, banned, root), [MX])).toMatchObject({
      ok: false,
    });
  });

  test("DANE-EE still matches the leaf alone; no records means unauthenticated", async () => {
    const { leaf } = await chainOf();
    expect(await verifyDane([tlsa(3, 1, 1, sha256(leaf.spki))], ders(leaf), ["any.test"])).toEqual({
      ok: true,
      how: "dane-ee",
    });
    expect(await verifyDane([tlsa(1, 1, 1, sha256(leaf.spki))], ders(leaf), [MX])).toEqual({
      ok: true,
      how: "unauthenticated",
    });
    expect(await verifyDane([tlsa(3, 1, 1, new Uint8Array(32))], ders(leaf), [MX])).toMatchObject({
      ok: false,
    });
  });

  test("a long or looping chain ends", async () => {
    const root = await issue({ name: "Root", ca: true });
    let issuer = root;
    const all: Issued[] = [];
    for (let i = 0; i < 10; i++) {
      issuer = await issue({ name: `CA${i}`, issuer, ca: true });
      all.unshift(issuer);
    }
    const leaf = await issue({ name: MX, issuer, dns: [MX] });
    const certs = [leaf, ...all, root].map((c) => parseCertificate(c.der));
    const r = await verifyChain(certs, [{ spki: root.spki, subject: null }], [MX]);
    expect(r).toMatchObject({ ok: false });
  });
});
