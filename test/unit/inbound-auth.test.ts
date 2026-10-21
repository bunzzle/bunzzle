import { describe, expect, test } from "bun:test";
import { simpleBody, splitMessage } from "../../src/dkim/canonicalize.ts";
import { checkDkim } from "../../src/dkim/check.ts";
import { signData } from "../../src/dkim/sign.ts";
import { checkDmarc, organizationalDomain, parseDmarcRecord } from "../../src/dmarc/policy.ts";
import type { DnsAnswer, QueryType, Resolver } from "../../src/dns/resolver.ts";
import type { ResourceRecord } from "../../src/dns/wire.ts";
import { type AuthResults, fromDomain, refusal } from "../../src/inbound/auth.ts";
import { checkSpf, type SpfCheck } from "../../src/spf/check.ts";

interface Entry {
  TXT?: string[];
  A?: string[];
  AAAA?: string[];
  MX?: [number, string][];
  PTR?: string[];
  fail?: boolean;
}

function zone(entries: Record<string, Entry>): Resolver & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    async query(name: string, type: QueryType): Promise<DnsAnswer> {
      const n = name.toLowerCase();
      asked.push(`${type} ${n}`);
      const e = entries[n];
      const base = { name: n, type, authenticated: false, ttl: 300 };
      if (!e) return { ...base, rcode: 3, records: [] };
      if (e.fail) return { ...base, rcode: 2, records: [] };
      const rr = { name: n, ttl: 300, rrtype: 0, rdata: new Uint8Array() };
      let records: ResourceRecord[] = [];
      if (type === "TXT") records = (e.TXT ?? []).map((t) => ({ ...rr, type, strings: [t] }));
      if (type === "A") records = (e.A ?? []).map((address) => ({ ...rr, type, address }));
      if (type === "AAAA") records = (e.AAAA ?? []).map((address) => ({ ...rr, type, address }));
      if (type === "PTR") records = (e.PTR ?? []).map((target) => ({ ...rr, type, target }));
      if (type === "MX") {
        records = (e.MX ?? []).map(([preference, exchange]) => ({
          ...rr,
          type,
          mx: { preference, exchange },
        }));
      }
      return { ...base, rcode: 0, records };
    },
  };
}

const spf = (r: Resolver, ip: string, mailFrom = "a@example.org", helo: string | null = null) =>
  checkSpf(r, { ip, mailFrom, helo });

describe("SPF", () => {
  test("ip4, ip6, a, mx and the qualifiers", async () => {
    const r = zone({
      "example.org": {
        TXT: ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8:1::/48 a:web.example.org/30 mx ~all"],
        MX: [[10, "mx.example.org"]],
      },
      "web.example.org": { A: ["198.51.100.8"] },
      "mx.example.org": { A: ["203.0.113.5"] },
    });
    expect((await spf(r, "192.0.2.77")).result).toBe("pass");
    expect((await spf(r, "2001:db8:1:ff::1")).result).toBe("pass");
    expect((await spf(r, "198.51.100.10")).result).toBe("pass");
    expect((await spf(r, "198.51.100.12")).result).toBe("softfail");
    expect((await spf(r, "203.0.113.5")).result).toBe("pass");
    expect((await spf(r, "::ffff:192.0.2.1")).result).toBe("pass");
    expect(await spf(r, "8.8.8.8")).toEqual({
      result: "softfail",
      domain: "example.org",
      scope: "mailfrom",
      reason: null,
    });
  });

  test("include, redirect and the default neutral", async () => {
    const r = zone({
      "example.org": { TXT: ["v=spf1 include:_spf.mail.test -all"] },
      "_spf.mail.test": { TXT: ["v=spf1 ip4:192.0.2.1 -all"] },
      "redir.test": { TXT: ["v=spf1 redirect=example.org"] },
      "open.test": { TXT: ["v=spf1 ip4:192.0.2.9"] },
      "hollow.test": { TXT: ["v=spf1 include:nothing.test -all"] },
    });
    expect((await spf(r, "192.0.2.1")).result).toBe("pass");
    expect((await spf(r, "192.0.2.2")).result).toBe("fail");
    expect((await spf(r, "192.0.2.1", "x@redir.test")).result).toBe("pass");
    expect((await spf(r, "192.0.2.2", "x@open.test")).result).toBe("neutral");
    expect(await spf(r, "192.0.2.2", "x@hollow.test")).toMatchObject({
      result: "permerror",
      reason: "include of nothing.test found no SPF record",
    });
  });

  test("none, temperror, two records and syntax errors", async () => {
    const r = zone({
      "plain.test": { TXT: ["google-site-verification=x"] },
      "down.test": { fail: true },
      "two.test": { TXT: ["v=spf1 -all", "v=spf1 +all"] },
      "bad.test": { TXT: ["v=spf1 ip4:300.1.1.1 -all"] },
      "odd.test": { TXT: ["v=spf1 foo -all"] },
    });
    expect((await spf(r, "192.0.2.1", "x@plain.test")).result).toBe("none");
    expect((await spf(r, "192.0.2.1", "x@missing.test")).result).toBe("none");
    expect((await spf(r, "192.0.2.1", "x@down.test")).result).toBe("temperror");
    expect((await spf(r, "192.0.2.1", "x@two.test")).result).toBe("permerror");
    expect((await spf(r, "192.0.2.1", "x@bad.test")).result).toBe("permerror");
    expect((await spf(r, "192.0.2.1", "x@odd.test")).result).toBe("permerror");
  });

  test("more than 10 lookups or 2 empty lookups is a permerror", async () => {
    const many: Record<string, Entry> = {
      "example.org": {
        TXT: [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `a:h${i}.test`).join(" ")} -all`],
      },
    };
    for (let i = 0; i < 11; i++) many[`h${i}.test`] = { A: ["198.51.100.1"] };
    expect(await spf(zone(many), "192.0.2.1")).toMatchObject({
      result: "permerror",
      reason: "more than 10 DNS lookups",
    });
    const voids = zone({ "example.org": { TXT: ["v=spf1 a:x.test a:y.test a:z.test -all"] } });
    expect(await spf(voids, "192.0.2.1")).toMatchObject({
      result: "permerror",
      reason: "more than 2 lookups found nothing",
    });
  });

  test("macros in exists", async () => {
    const r = zone({
      "example.org": { TXT: ["v=spf1 exists:%{ir}.%{l1r-}._spf.%{d} -all"] },
      "1.2.0.192.alice._spf.example.org": { A: ["127.0.0.2"] },
    });
    expect((await spf(r, "192.0.2.1", "alice-bob@example.org")).result).toBe("pass");
    expect((await spf(r, "192.0.2.3", "alice-bob@example.org")).result).toBe("fail");
  });

  test("an empty MAIL FROM checks the HELO name", async () => {
    const r = zone({ "mx.sender.test": { TXT: ["v=spf1 ip4:192.0.2.1 -all"] } });
    expect(await spf(r, "192.0.2.1", "", "mx.sender.test")).toEqual({
      result: "pass",
      domain: "mx.sender.test",
      scope: "helo",
      reason: null,
    });
    expect((await spf(r, "192.0.2.1", "", null)).result).toBe("none");
  });
});

const RFC_MESSAGE = (await Bun.file(`${import.meta.dir}/../fixtures/rfc8463.eml`).text()).replace(
  /\r?\n/g,
  "\r\n",
);

const RFC_ZONE: Record<string, Entry> = {
  "brisbane._domainkey.football.example.com": {
    TXT: ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
  },
  "test._domainkey.football.example.com": {
    TXT: [
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
    ],
  },
};

async function ed25519() {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as unknown as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)).toBase64();
  return {
    pub,
    key: {
      domain: "sender.test",
      selector: "s1",
      algorithm: "ed25519-sha256" as const,
      privateKey: pair.privateKey,
    },
  };
}

const PLAIN = [
  "From: Ayse <ayse@sender.test>",
  "To: support@acme.test",
  "Subject: Hello",
  "",
  "Hi there.  ",
  "",
  "",
].join("\r\n");

async function signSimple(raw: string, extra: string, headers = "from:to:subject") {
  const { pub, key } = await ed25519();
  const { headers: hs, body } = splitMessage(raw);
  const bh = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder()
        .encode(simpleBody(body))
        .subarray(0, Number(/l=(\d+)/.exec(extra)?.[1] ?? Infinity)),
    ),
  ).toBase64();
  const unsigned = `DKIM-Signature: v=1; a=ed25519-sha256; c=simple/simple; d=sender.test; s=s1; h=${headers}; bh=${bh};${extra} b=`;
  let data = "";
  const names = headers.split(":");
  for (const n of names) {
    const h = hs.filter((x) => x.name.toLowerCase() === n).pop();
    if (h) data += `${h.raw}\r\n`;
  }
  const b = await signData(key, data + unsigned);
  return {
    signed: `${unsigned}${b}\r\n${raw}`,
    resolver: zone({ "s1._domainkey.sender.test": { TXT: [`v=DKIM1; k=ed25519; p=${pub}`] } }),
  };
}

describe("DKIM", () => {
  test("the RFC 8463 message passes with both keys from DNS", async () => {
    const results = await checkDkim(zone(RFC_ZONE), RFC_MESSAGE);
    expect(results).toEqual([
      {
        result: "pass",
        domain: "football.example.com",
        selector: "brisbane",
        reason: null,
        testing: false,
      },
      {
        result: "pass",
        domain: "football.example.com",
        selector: "test",
        reason: null,
        testing: false,
      },
    ]);
  });

  test("a changed body or header fails", async () => {
    const body = RFC_MESSAGE.replace("We lost the game.", "We won the game.");
    expect((await checkDkim(zone(RFC_ZONE), body)).map((r) => r.reason)).toEqual([
      "body hash mismatch",
      "body hash mismatch",
    ]);
    const subject = RFC_MESSAGE.replace("Is dinner ready?", "Is lunch ready?");
    expect((await checkDkim(zone(RFC_ZONE), subject)).map((r) => r.reason)).toEqual([
      "bad signature",
      "bad signature",
    ]);
  });

  test("missing, failing and revoked keys", async () => {
    const [missing] = await checkDkim(zone({}), RFC_MESSAGE);
    expect(missing).toMatchObject({
      result: "permerror",
      reason: "no key at brisbane._domainkey.football.example.com",
    });
    const down = await checkDkim(
      zone({ "brisbane._domainkey.football.example.com": { fail: true } }),
      RFC_MESSAGE,
    );
    expect(down[0]?.result).toBe("temperror");
    const revoked = await checkDkim(
      zone({ "brisbane._domainkey.football.example.com": { TXT: ["v=DKIM1; k=ed25519; p="] } }),
      RFC_MESSAGE,
    );
    expect(revoked[0]).toMatchObject({ result: "permerror", reason: "key revoked" });
  });

  test("simple/simple signatures pass and keep the trailing-line rule", async () => {
    const { signed, resolver } = await signSimple(PLAIN, "");
    expect((await checkDkim(resolver, signed))[0]?.result).toBe("pass");
    const moreLines = `${signed}\r\n\r\n`;
    expect((await checkDkim(resolver, moreLines))[0]?.result).toBe("pass");
    const spaced = signed.replace("Hi there.  ", "Hi there. ");
    expect((await checkDkim(resolver, spaced))[0]?.reason).toBe("body hash mismatch");
    const folded = signed.replace("Subject: Hello", "Subject:  Hello");
    expect((await checkDkim(resolver, folded))[0]?.reason).toBe("bad signature");
  });

  test("tags that are refused", async () => {
    const cases: [string, string, string][] = [
      [" x=1000000000;", "from:to:subject", "signature expired"],
      [" i=@other.test;", "from:to:subject", "i= is not within d="],
      [" l=3;", "from:to:subject", "the signature covers only part of the body"],
      ["", "to:subject", "From is not signed"],
    ];
    for (const [extra, headers, reason] of cases) {
      const { signed, resolver } = await signSimple(PLAIN, extra, headers);
      expect((await checkDkim(resolver, signed))[0]?.reason).toBe(reason);
    }
    const sha1 = RFC_MESSAGE.replace("a=rsa-sha256", "a=rsa-sha1");
    expect((await checkDkim(zone(RFC_ZONE), sha1))[1]).toMatchObject({
      result: "permerror",
      reason: "rsa-sha1 is not accepted",
    });
  });
});

const spfResult = (result: SpfCheck["result"], domain: string): SpfCheck => ({
  result,
  domain,
  scope: "mailfrom",
  reason: null,
});

const dkimPass = (domain: string) => [
  { result: "pass" as const, domain, selector: "s", reason: null, testing: false },
];

describe("DMARC", () => {
  const r = zone({
    "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=quarantine; np=reject"] },
    "news.example.com": { A: ["192.0.2.1"] },
    "_dmarc.strict.test": { TXT: ["v=DMARC1; p=reject; aspf=s; adkim=s"] },
    "_dmarc.trial.test": { TXT: ["v=DMARC1; p=reject; t=y"] },
    "_dmarc.down.test": { fail: true },
  });
  const from = (domain: string) => ({ domain });

  test("an aligned DKIM or SPF pass passes", async () => {
    expect(
      await checkDmarc(
        r,
        from("example.com"),
        spfResult("fail", "x.test"),
        dkimPass("example.com"),
      ),
    ).toEqual({
      result: "pass",
      domain: "example.com",
      policy: "reject",
      reason: null,
    });
    const viaSpf = await checkDmarc(
      r,
      from("example.com"),
      spfResult("pass", "bounce.example.com"),
      [],
    );
    expect(viaSpf.result).toBe("pass");
  });

  test("no aligned pass fails with the policy to apply", async () => {
    expect(
      await checkDmarc(
        r,
        from("example.com"),
        spfResult("pass", "other.test"),
        dkimPass("other.test"),
      ),
    ).toEqual({
      result: "fail",
      domain: "example.com",
      policy: "reject",
      reason: "no aligned SPF or DKIM pass",
    });
    const sub = await checkDmarc(r, from("news.example.com"), spfResult("fail", "x"), []);
    expect(sub).toMatchObject({ result: "fail", policy: "quarantine" });
    const gone = await checkDmarc(r, from("ghost.example.com"), spfResult("fail", "x"), []);
    expect(gone).toMatchObject({ result: "fail", policy: "reject" });
    const trial = await checkDmarc(r, from("trial.test"), spfResult("fail", "x"), []);
    expect(trial).toMatchObject({ result: "fail", policy: "quarantine" });
  });

  test("strict alignment needs the same domain", async () => {
    const res = await checkDmarc(
      r,
      from("strict.test"),
      spfResult("pass", "mail.strict.test"),
      dkimPass("mail.strict.test"),
    );
    expect(res.result).toBe("fail");
  });

  test("none, temperror and From problems", async () => {
    expect((await checkDmarc(r, from("nothing.test"), spfResult("fail", "x"), [])).result).toBe(
      "none",
    );
    expect((await checkDmarc(r, from("down.test"), spfResult("fail", "x"), [])).result).toBe(
      "temperror",
    );
    expect(await checkDmarc(r, { problem: "two" }, spfResult("pass", "x"), [])).toMatchObject({
      result: "permerror",
      reason: "two",
    });
  });

  test("organizational domain from the DNS tree walk", async () => {
    const t = zone({
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=none"] },
      "_dmarc.gov.example": { TXT: ["v=DMARC1; p=reject; psd=y"] },
      "_dmarc.own.example": { TXT: ["v=DMARC1; p=none; psd=n"] },
    });
    expect(await organizationalDomain(t, "a.b.example.com")).toBe("example.com");
    expect(await organizationalDomain(t, "a.b.agency.gov.example")).toBe("agency.gov.example");
    expect(await organizationalDomain(t, "x.own.example")).toBe("own.example");
    expect(await organizationalDomain(t, "a.unlisted.test")).toBe("a.unlisted.test");
  });

  test("record parsing", () => {
    expect(parseDmarcRecord("v=spf1 -all")).toBeNull();
    expect(parseDmarcRecord("v=DMARC1; p=bogus; pct=50")).toMatchObject({
      p: "none",
      testing: true,
    });
  });
});

describe("From domain and refusal", () => {
  test("exactly one From address", () => {
    expect(fromDomain('From: "Doe, Jane" <jane@Example.COM>\r\n\r\nx')).toEqual({
      domain: "example.com",
    });
    expect(fromDomain("From: a@x.test, b@y.test\r\n\r\nx")).toEqual({
      problem: "the From header must have exactly one address",
    });
    expect(fromDomain("From: a@x.test\r\nFrom: b@y.test\r\n\r\nx")).toEqual({
      problem: "the message must have exactly one From header",
    });
  });

  const auth = (patch: Partial<AuthResults>): AuthResults => ({
    spf: spfResult("pass", "sender.test"),
    dkim: [],
    dmarc: { result: "pass", domain: "sender.test", policy: "reject", reason: null },
    blocklists: [],
    ...patch,
  });

  test("refuses only what is turned on", () => {
    const dmarcFail = auth({
      dmarc: { result: "fail", domain: "sender.test", policy: "reject", reason: "x" },
    });
    expect(refusal(dmarcFail, [], "192.0.2.1")).toBeNull();
    expect(refusal(dmarcFail, ["dmarc"], "192.0.2.1")).toEqual({
      code: 550,
      text: "5.7.1 Rejected by the DMARC policy of sender.test",
    });
    const quarantine = auth({
      dmarc: { result: "fail", domain: "sender.test", policy: "quarantine", reason: "x" },
    });
    expect(refusal(quarantine, ["dmarc"], "192.0.2.1")).toBeNull();
    const pending = auth({
      dmarc: { result: "temperror", domain: "sender.test", policy: null, reason: "x" },
    });
    expect(refusal(pending, ["dmarc"], "192.0.2.1")?.code).toBe(451);
    const spfFail = auth({ spf: spfResult("fail", "sender.test") });
    expect(refusal(spfFail, ["spf"], "192.0.2.1")).toEqual({
      code: 550,
      text: "5.7.23 SPF check failed for sender.test",
    });
    const listed = auth({
      blocklists: [
        { list: "spamhaus", name: "Spamhaus ZEN", status: "listed", detail: "x", removal: null },
      ],
    });
    expect(refusal(listed, ["blocklist"], "192.0.2.1")).toEqual({
      code: 554,
      text: "5.7.1 192.0.2.1 is listed on Spamhaus ZEN",
    });
  });
});
