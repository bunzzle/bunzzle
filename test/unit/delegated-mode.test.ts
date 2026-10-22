import { describe, expect, test } from "bun:test";
import type { Logger } from "../../src/core/log.ts";
import {
  delegatedRecords,
  domainRecords,
  labelClash,
  slotKeys,
  zoneLabel,
} from "../../src/domains/delegated.ts";
import { evaluate, lookupRecords } from "../../src/domains/domains.ts";
import { delegatedDomains, zonePublisher } from "../../src/roles/core-zone.ts";

const ZONE = "dz.mail.example.net";
const OWNER = `${zoneLabel("shop.example")}.${ZONE}`;
const SCOPE = ["shop.example", ZONE];
const RSA = { selector: "bza-r", algorithm: "rsa-sha256" as const, publicKey: "M".repeat(392) };
const ED = { selector: "bza-e", algorithm: "ed25519-sha256" as const, publicKey: "E".repeat(44) };

function quietLog() {
  const lines: { level: string; msg: string }[] = [];
  const at = (level: string) => (msg: string) => lines.push({ level, msg });
  const log = { debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error") };
  return { log: log as unknown as Logger, lines };
}

function dns(answers: Record<string, string[]>) {
  const asked: string[] = [];
  const lookup = async (queries: { name: string; type: string }[]) => {
    const out: Record<string, string[]> = {};
    for (const q of queries) {
      const key = `${q.type}:${q.name}`;
      asked.push(key);
      out[key] = answers[key] ?? [];
    }
    return out;
  };
  return { lookup, asked };
}

describe("zone names", () => {
  test("every domain gets its own 80-bit label; slot names hang under it", () => {
    const labels = new Set<string>();
    for (let i = 0; i < 200_000; i++) labels.add(zoneLabel(`d${i}.example`));
    expect(labels.size).toBe(200_000);
    expect(zoneLabel("shop.example")).toMatch(/^[a-z2-7]{16}$/);
    const a = delegatedRecords("a.example", ZONE, null)
      .filter((r) => r.type === "CNAME")
      .map((r) => r.value);
    const b = delegatedRecords("b.example", ZONE, null)
      .filter((r) => r.type === "CNAME")
      .map((r) => r.value);
    expect(a.filter((v) => b.includes(v))).toEqual([]);
  });

  test("a domain whose label is taken is found", () => {
    expect(labelClash("shop.example", ["a.example", "shop.example"])).toBeNull();
    expect(labelClash("shop.example", ["a.example", "SHOP.example"])).toBe("SHOP.example");
  });
});

describe("delegated records", () => {
  test("four DKIM CNAMEs, SPF include, DMARC and the return path CNAME", () => {
    const records = delegatedRecords("shop.example", ZONE, "mx.mail.example.net");
    expect(records.map((r) => [r.record, r.type, r.name, r.value, r.required])).toEqual([
      ["DKIM", "CNAME", "bza-r._domainkey.shop.example", `bza-r.${OWNER}`, true],
      ["DKIM", "CNAME", "bzb-r._domainkey.shop.example", `bzb-r.${OWNER}`, true],
      ["DKIM", "CNAME", "bza-e._domainkey.shop.example", `bza-e.${OWNER}`, true],
      ["DKIM", "CNAME", "bzb-e._domainkey.shop.example", `bzb-e.${OWNER}`, true],
      ["SPF", "TXT", "shop.example", `v=spf1 include:_spf.${ZONE} ~all`, false],
      [
        "DMARC",
        "TXT",
        "_dmarc.shop.example",
        "v=DMARC1; p=none; rua=mailto:dmarc@bounce.shop.example;",
        false,
      ],
      ["RETURN_PATH", "CNAME", "bounce.shop.example", OWNER, false],
    ]);
  });

  test("no return path without an inbound host", () => {
    const records = delegatedRecords("shop.example", ZONE, null);
    expect(records.some((r) => r.record.startsWith("RETURN_PATH"))).toBe(false);
  });

  test("the mode picks the records; records mode without a zone", () => {
    const keys = [RSA, ED];
    const delegated = domainRecords(
      { name: "shop.example", mode: "delegated" },
      keys,
      "192.0.2.10",
      null,
      ZONE,
    );
    expect(delegated.filter((r) => r.type === "CNAME").length).toBe(4);
    const records = domainRecords(
      { name: "shop.example", mode: "records" },
      keys,
      "192.0.2.10",
      null,
      ZONE,
    );
    expect(records.some((r) => r.type === "CNAME")).toBe(false);
    expect(records.find((r) => r.record === "DKIM")?.name).toBe("bza-r._domainkey.shop.example");
  });

  test("slot keys only when every selector is a slot", () => {
    expect(slotKeys([RSA, ED])).toEqual({ "bza-r": RSA, "bza-e": ED });
    expect(slotKeys([RSA, { ...ED, selector: "bz202610e" }])).toBeNull();
  });
});

describe("verification through the CNAME chain", () => {
  const records = delegatedRecords("shop.example", ZONE, "mx.mail.example.net");
  const all = (extra: Record<string, string[]> = {}) => ({
    "CNAME:bza-r._domainkey.shop.example": [`bza-r.${OWNER}`],
    "CNAME:bzb-r._domainkey.shop.example": [`BZB-R.${OWNER}.`],
    "CNAME:bza-e._domainkey.shop.example": [`bza-e.${OWNER}`],
    "CNAME:bzb-e._domainkey.shop.example": [`bzb-e.${OWNER}`],
    ...extra,
  });

  test("direct CNAMEs verify, case and trailing dot ignored", async () => {
    const d = dns(all());
    const checked = evaluate(records, await lookupRecords(records, d.lookup, SCOPE), null);
    expect(checked.status).toBe("verified");
    expect(checked.records.find((r) => r.name === "bounce.shop.example")?.status).toBe("missing");
  });

  test("a chain through the customer's own names verifies", async () => {
    const d = dns(
      all({
        "CNAME:bza-r._domainkey.shop.example": ["dkim1.shop.example"],
        "CNAME:dkim1.shop.example": ["Dkim2.Mail.Shop.Example."],
        "CNAME:dkim2.mail.shop.example": [`bza-r.${OWNER}`],
      }),
    );
    const checked = evaluate(records, await lookupRecords(records, d.lookup, SCOPE), null);
    const r = checked.records.find((x) => x.name === "bza-r._domainkey.shop.example");
    expect(r?.status).toBe("verified");
    expect(r?.found).toBe(`dkim1.shop.example -> dkim2.mail.shop.example -> bza-r.${OWNER}`);
    expect(checked.status).toBe("verified");
  });

  test.each([
    ["first", { "CNAME:bza-r._domainkey.shop.example": [`dkim.cdn.example`] }, "dkim.cdn.example"],
    [
      "middle",
      {
        "CNAME:bza-r._domainkey.shop.example": ["dkim1.shop.example"],
        "CNAME:dkim1.shop.example": ["dkim2.cdn.example"],
        "CNAME:dkim2.cdn.example": [`bza-r.${OWNER}`],
      },
      "dkim1.shop.example -> dkim2.cdn.example",
    ],
    [
      "last before the target",
      {
        "CNAME:bza-r._domainkey.shop.example": ["dkim1.shop.example"],
        "CNAME:dkim1.shop.example": ["dkim2.shop.example"],
        "CNAME:dkim2.shop.example": ["evilshop.example"],
        "CNAME:evilshop.example": [`bza-r.${OWNER}`],
      },
      "dkim1.shop.example -> dkim2.shop.example -> evilshop.example",
    ],
    [
      "in one answer",
      { "CNAME:bza-r._domainkey.shop.example": ["dkim.cdn.example", `bza-r.${OWNER}`] },
      "dkim.cdn.example",
    ],
  ])("a hop outside the domain and the zone fails the chain (%s)", async (_, hops, chain) => {
    const d = dns(all(hops));
    const checked = evaluate(records, await lookupRecords(records, d.lookup, SCOPE), null);
    const r = checked.records.find((x) => x.name === "bza-r._domainkey.shop.example");
    expect(r?.status).toBe("mismatch");
    expect(r?.found).toBe(chain);
    expect(checked.status).toBe("pending");
    expect(d.asked.filter((k) => k.includes("cdn") || k.includes("evil"))).toEqual([]);
  });

  test("a wrong target is a mismatch and keeps the domain pending", async () => {
    const d = dns(all({ "CNAME:bzb-e._domainkey.shop.example": [`bza-e.${OWNER}`] }));
    const checked = evaluate(records, await lookupRecords(records, d.lookup, SCOPE), null);
    const r = checked.records.find((x) => x.name === "bzb-e._domainkey.shop.example");
    expect(r?.status).toBe("mismatch");
    expect(r?.found).toBe(`bza-e.${OWNER}`);
    expect(checked.status).toBe("pending");
  });

  test("a CNAME loop stops after a few hops", async () => {
    const d = dns(
      all({
        "CNAME:bza-r._domainkey.shop.example": ["a.loop.shop.example"],
        "CNAME:a.loop.shop.example": ["b.loop.shop.example"],
        "CNAME:b.loop.shop.example": ["a.loop.shop.example"],
      }),
    );
    const checked = evaluate(records, await lookupRecords(records, d.lookup, SCOPE), null);
    expect(checked.records[0]?.status).toBe("mismatch");
    expect(d.asked.filter((k) => k.includes("loop")).length).toBe(2);
  });

  test("a long chain is cut at eight names", async () => {
    const hops: Record<string, string[]> = {
      "CNAME:bza-r._domainkey.shop.example": ["h0.shop.example"],
    };
    for (let i = 0; i < 20; i++) hops[`CNAME:h${i}.shop.example`] = [`h${i + 1}.shop.example`];
    hops["CNAME:h8.shop.example"] = [`bza-r.${OWNER}`];
    const d = dns(all(hops));
    const found = await lookupRecords(records, d.lookup, SCOPE);
    expect(found["CNAME:bza-r._domainkey.shop.example"]?.length).toBe(8);
    expect(d.asked.filter((k) => /CNAME:h\d/.test(k)).length).toBe(7);
    const checked = evaluate(records, found, null);
    expect(checked.records[0]?.status).toBe("mismatch");
  });

  test("the SPF suggestion checks for the include", () => {
    const spf = records.filter((r) => r.record === "SPF");
    const ok = evaluate(spf, { "TXT:shop.example": [`v=spf1 mx include:_spf.${ZONE} -all`] }, []);
    expect(ok.records[0]?.status).toBe("verified");
    const other = evaluate(spf, { "TXT:shop.example": ["v=spf1 ip4:192.0.2.10 ~all"] }, []);
    expect(other.records[0]?.status).toBe("mismatch");
  });
});

describe("delegated domains for the zone", () => {
  test("keys are cached, refreshed after five minutes and dropped with the domain", async () => {
    let t = 0;
    let names = ["shop.example"];
    const fetched: string[] = [];
    const quiet = quietLog();
    const list = delegatedDomains({
      names: () => names,
      keys: async (domain) => {
        fetched.push(domain);
        return [RSA, ED];
      },
      log: quiet.log,
      now: () => t,
    });
    expect(await list()).toEqual([{ name: "shop.example", keys: { "bza-r": RSA, "bza-e": ED } }]);
    await list();
    expect(fetched.length).toBe(1);
    t += 300_000;
    await list();
    expect(fetched.length).toBe(2);
    names = [];
    expect(await list()).toEqual([]);
  });

  test("a failed key lookup fails the list until it worked once, then the old keys stay", async () => {
    let t = 0;
    let down = true;
    const list = delegatedDomains({
      names: () => ["shop.example"],
      keys: async () => {
        if (down) throw new Error("signer is down");
        return [RSA];
      },
      log: quietLog().log,
      now: () => t,
    });
    await expect(list()).rejects.toThrow("signer is down");
    down = false;
    await list();
    down = true;
    t += 600_000;
    expect(await list()).toEqual([{ name: "shop.example", keys: { "bza-r": RSA } }]);
  });

  test("keys outside the slots are left out with a warning", async () => {
    const quiet = quietLog();
    const list = delegatedDomains({
      names: () => ["shop.example"],
      keys: async () => [{ ...RSA, selector: "bz202610r" }],
      log: quiet.log,
    });
    expect(await list()).toEqual([{ name: "shop.example", keys: {} }]);
    expect(quiet.lines.filter((l) => l.level === "warn").length).toBe(1);
  });

  test("the publisher pushes nothing when the domain list fails", async () => {
    const calls: string[] = [];
    const quiet = quietLog();
    const pub = zonePublisher({
      ns: {
        call: async (method: string) => {
          calls.push(method);
          return { serial: null } as never;
        },
      } as never,
      zone: ZONE,
      ttl: 300,
      sourceIps: ["192.0.2.10"],
      inboundHost: null,
      domains: async () => {
        throw new Error("signer is down");
      },
      log: quiet.log,
    });
    expect(await pub.tick()).toBeNull();
    expect(calls).toEqual([]);
    expect(quiet.lines.filter((l) => l.level === "warn").length).toBe(1);
  });
});
