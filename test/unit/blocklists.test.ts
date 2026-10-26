import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import type { DnsAnswer, Resolver } from "../../src/dns/resolver.ts";
import { blocklists, checkBlocklists, listName } from "../../src/ips/blocklists.ts";
import { choose } from "../../src/ips/warmup.ts";

const answer = (name: string, rcode: number, addresses: string[] = []): DnsAnswer => ({
  name,
  type: "A",
  rcode,
  authenticated: false,
  ttl: 300,
  records: addresses.map((address) => ({
    name,
    ttl: 300,
    rrtype: 1,
    rdata: new Uint8Array(),
    type: "A" as const,
    address,
  })),
});

const V6_TEST = `${listName("::ffff:7f00:2")}.`;

function resolver(
  entries: Record<string, string[] | "fail" | number>,
): Resolver & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    async query(name) {
      asked.push(name);
      const zone = name.split(".").slice(4).join(".");
      const key = name in entries ? name : `*.${zone}`;
      const test = name.startsWith("2.0.0.127.") || name.startsWith(V6_TEST);
      const e = entries[key] ?? (test ? ["127.0.0.2"] : undefined);
      if (e === "fail") throw new Error("timed out");
      if (typeof e === "number") return answer(name, e);
      return e ? answer(name, 0, e) : answer(name, 3);
    },
  };
}

const IP = "203.0.113.7";
const lists = blocklists(null);

describe("blocklists", () => {
  test("names in the list zone: reversed IPv4 octets, IPv6 nibbles", () => {
    expect(listName(IP)).toBe("7.113.0.203");
    expect(listName("2001:db8::1")).toBe(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
    );
    expect(listName("not an ip")).toBeNull();
  });

  test("clean on every list", async () => {
    const r = await checkBlocklists(resolver({}), IP, lists);
    expect(r.map((l) => l.status)).toEqual(["clean", "clean", "clean", "clean", "clean"]);
  });

  test("listed, with the list's meaning and removal page", async () => {
    const r = await checkBlocklists(
      resolver({
        "7.113.0.203.zen.spamhaus.org": ["127.0.0.4", "127.0.0.10"],
        "7.113.0.203.bl.spamcop.net": ["127.0.0.2"],
      }),
      IP,
      lists,
    );
    expect(r.find((l) => l.list === "spamhaus")).toEqual({
      list: "spamhaus",
      name: "Spamhaus ZEN",
      status: "listed",
      detail:
        "XBL: an infected or exploited host; PBL: the network owner says this IP should not send email directly",
      removal: "https://check.spamhaus.org/",
    });
    expect(r.find((l) => l.list === "spamcop")).toMatchObject({
      status: "listed",
      detail: "listed (127.0.0.2)",
    });
  });

  test("a list that refuses this resolver is not counted as a listing", async () => {
    const r = await checkBlocklists(
      resolver({
        "2.0.0.127.zen.spamhaus.org": ["127.255.255.254"],
        "7.113.0.203.zen.spamhaus.org": ["127.255.255.254"],
      }),
      IP,
      lists,
    );
    expect(r[0]).toMatchObject({ status: "unusable", removal: null });
    expect(r[0]?.detail).toContain("BUNZZLE_SPAMHAUS_KEY_FILE");
  });

  test("a refusal code on the IP itself is not a listing either", async () => {
    const r = await checkBlocklists(
      resolver({ "7.113.0.203.zen.spamhaus.org": ["127.255.255.255"] }),
      IP,
      lists,
    );
    expect(r[0]).toMatchObject({ status: "unusable", detail: "unexpected answer 127.255.255.255" });
  });

  test("a resolver that answers names that do not exist makes the list unusable", async () => {
    const hijack = ["198.51.100.80"];
    const r = await checkBlocklists(
      resolver({
        "2.0.0.127.bl.spamcop.net": hijack,
        "1.0.0.127.b.barracudacentral.org": ["127.0.0.2"],
        "7.113.0.203.bl.mailspike.net": hijack,
      }),
      IP,
      lists,
    );
    const by = (id: string) => r.find((l) => l.list === id);
    expect(by("spamcop")).toMatchObject({
      status: "unusable",
      detail: "the resolver does not return the list's test entry 127.0.0.2",
    });
    expect(by("barracuda")).toMatchObject({
      status: "unusable",
      detail: "the resolver answers for names that do not exist",
    });
    expect(by("mailspike")).toMatchObject({
      status: "unusable",
      detail: "unexpected answer 198.51.100.80",
    });
    expect(r.some((l) => l.status === "listed")).toBe(false);
  });

  test("failed lookups are reported, not treated as clean", async () => {
    const r = await checkBlocklists(
      resolver({ "7.113.0.203.psbl.surriel.com": "fail", "2.0.0.127.bl.spamcop.net": 2 }),
      IP,
      lists,
    );
    expect(r.find((l) => l.list === "psbl")).toMatchObject({
      status: "unusable",
      detail: "the lookup failed: timed out",
    });
    expect(r.find((l) => l.list === "spamcop")).toMatchObject({
      status: "unusable",
      detail: "the lookup failed (rcode 2)",
    });
  });

  test("IPv6 is checked only on lists that support it; a key moves Spamhaus to its key zone", async () => {
    const dns = resolver({});
    const r = await checkBlocklists(dns, "2001:db8::1", blocklists("k3y"));
    expect(r.map((l) => l.list)).toEqual(["spamhaus"]);
    expect(r[0]?.status).toBe("clean");
    expect(dns.asked.every((n) => n.endsWith(".k3y.zen.dq.spamhaus.net"))).toBe(true);
    expect(dns.asked.slice(0, 2)).toEqual([
      `${listName("::ffff:7f00:2")}.k3y.zen.dq.spamhaus.net`,
      `${listName("::ffff:7f00:1")}.k3y.zen.dq.spamhaus.net`,
    ]);
    expect(dns.asked.some((n) => n.startsWith("2.0.0.127."))).toBe(false);
  });

  test("an IPv6 list without the IPv6 test entry is unusable", async () => {
    const dns = resolver({ [`${listName("::ffff:7f00:2")}.zen.spamhaus.org`]: 3 });
    const r = await checkBlocklists(dns, "2001:db8::1", lists);
    expect(r[0]?.status).toBe("unusable");
    expect(r[0]?.detail).toContain("::ffff:7f00:2");
  });

  test("an IPv4-mapped IPv6 address is checked as IPv4 on every list", async () => {
    const dns = resolver({});
    const r = await checkBlocklists(dns, `::ffff:${IP}`, lists);
    expect(r).toHaveLength(lists.length);
    expect(dns.asked).toContain("7.113.0.203.psbl.surriel.com");
  });

  test("IP choice skips listed IPs while an unlisted one is left", () => {
    const db = openDatabase({ path: ":memory:" });
    const ips = ["192.0.2.1", "192.0.2.2"].map((ip) => ({ ip, pool: "main", established: true }));
    const pick = (listed: string[]) =>
      choose(
        db,
        ips,
        "transactional",
        "example.test",
        null,
        1,
        Date.now(),
        () => null,
        (ip) => listed.includes(ip),
      );
    expect(pick(["192.0.2.1"])).toEqual({ source: "192.0.2.2" });
    expect(pick(["192.0.2.2"])).toEqual({ source: "192.0.2.1" });
    expect("source" in pick(["192.0.2.1", "192.0.2.2"])).toBe(true);
  });

  test("an assigned pool is the only one used; a pool without IPs makes mail wait", () => {
    const db = openDatabase({ path: ":memory:" });
    const ips = [
      { ip: "192.0.2.1", pool: "main", established: true },
      { ip: "192.0.2.2", pool: "bulk", established: true },
      { ip: "192.0.2.3", pool: "acme", established: true },
    ];
    const pick = (lane: "transactional" | "bulk", pool: string | null) =>
      choose(
        db,
        ips,
        lane,
        "example.test",
        null,
        1,
        Date.now(),
        () => null,
        () => false,
        pool,
      );
    expect(pick("transactional", null)).toEqual({ source: "192.0.2.1" });
    expect(pick("bulk", null)).toEqual({ source: "192.0.2.2" });
    expect(pick("transactional", "acme")).toEqual({ source: "192.0.2.3" });
    expect(pick("bulk", "acme")).toEqual({ source: "192.0.2.3" });
    expect(pick("transactional", "gone")).toEqual({
      wait: { delayMs: 300_000, reason: "no source IP is configured in the pool gone", aged: true },
    });
  });
});
