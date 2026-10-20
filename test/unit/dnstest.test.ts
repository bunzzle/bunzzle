import { describe, expect, test } from "bun:test";
import { UsageError } from "../../src/cli/args.ts";
import { type DnsTestDeps, dnsTestCommand } from "../../src/cli/dnstest.ts";
import { loadConfig } from "../../src/config.ts";
import type { DnsAnswer, QueryType, Resolver } from "../../src/dns/resolver.ts";
import type { RecordData, ResourceRecord } from "../../src/dns/wire.ts";
import type { CfRecord, CfResult } from "../../src/net/cloudflare.ts";
import type { DnsProvider } from "../../src/net/providers.ts";
import { planRemove, planUpsert, txtText } from "../../src/net/rdata.ts";

const rr = (name: string, data: RecordData): ResourceRecord => ({
  name,
  ttl: 300,
  rrtype: 0,
  rdata: new Uint8Array(),
  ...data,
});

const answer = (name: string, type: QueryType, records: ResourceRecord[]): DnsAnswer => ({
  name,
  type,
  rcode: records.length ? 0 : 3,
  authenticated: false,
  records,
  ttl: 300,
});

class FakeProvider implements DnsProvider {
  readonly values = new Map<string, string[]>();
  readFails = false;
  forgets = false;
  removeFails = false;
  async upsert(rec: CfRecord): Promise<CfResult> {
    const current = this.values.get(rec.name) ?? [];
    if (this.readFails && current.length > 0) return { ok: false, error: "read refused" };
    const plan = planUpsert(rec, this.forgets ? [] : current);
    if (plan.values) this.values.set(rec.name, plan.values);
    return { ok: true, action: plan.action };
  }
  async remove(rec: CfRecord): Promise<CfResult> {
    if (this.removeFails) return { ok: false, error: "delete refused" };
    const plan = planRemove(rec, this.values.get(rec.name) ?? []);
    if (plan.values) this.values.set(rec.name, plan.values);
    return { ok: true, action: plan.action };
  }
}

function setup(
  o: { lagMs?: Record<string, number>; nameServers?: string[]; stale?: string[] } = {},
) {
  const provider = new FakeProvider();
  const lines: string[] = [];
  let clock = 0;
  const hosts = o.nameServers ?? ["ns2.provider.test.", "ns1.provider.test."];
  const ipOf = (host: string) => `192.0.2.${hosts.indexOf(host) + 1}`;
  const resolver: Resolver = {
    async query(name, type) {
      if (type === "NS" && name === "example.test") {
        return answer(
          name,
          type,
          hosts.map((h) => rr(name, { type: "NS", target: h })),
        );
      }
      if (type === "A" && hosts.includes(name)) {
        return answer(name, type, [rr(name, { type: "A", address: ipOf(name) })]);
      }
      return answer(name, type, []);
    },
  };
  const serverResolver = (ip: string): Resolver => ({
    async query(name, type) {
      const host = hosts.find((h) => ipOf(h) === ip) ?? "";
      const visible = clock >= (o.lagMs?.[host] ?? 0);
      const values = visible ? (provider.values.get(name) ?? []) : (o.stale ?? []);
      return answer(
        name,
        type,
        values.map((v) => rr(name, { type: "TXT", strings: txtText(v).match(/.{1,255}/g) ?? [] })),
      );
    },
  });
  const deps: DnsTestDeps = {
    opened: { name: "desec", provider },
    resolver,
    serverResolver,
    token: "ab".repeat(144),
    print: (line) => lines.push(line),
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
  };
  return { provider, lines, deps };
}

const config = loadConfig({});

describe("bunzzle dns-test", () => {
  test("publishes, reads back, waits for every name server, then removes", async () => {
    const ok = setup({ lagMs: { "ns2.provider.test.": 4_000 } });
    expect(await dnsTestCommand(["example.test"], config, ok.deps)).toBe(0);
    expect(ok.lines).toEqual([
      "provider: desec",
      "  [ok]   published TXT _bunzzle-test.example.test (301 characters)",
      "  [ok]   read it back from desec",
      "  [ok]   served by ns1.provider.test., ns2.provider.test. after 4 s",
      "  [ok]   removed TXT _bunzzle-test.example.test",
      "\ndesec works",
    ]);
    expect(ok.provider.values.get("_bunzzle-test.example.test")).toEqual([]);
  });

  test("finds the name servers of the parent zone", async () => {
    const { lines, deps } = setup();
    expect(await dnsTestCommand(["Mail.Example.test."], config, deps)).toBe(0);
    expect(lines[1]).toContain("_bunzzle-test.mail.example.test ");
    expect(lines[3]).toBe("  [ok]   served by ns1.provider.test., ns2.provider.test. after 0 s");
  });

  test("names the servers that never serve the record and still removes it", async () => {
    const { provider, lines, deps } = setup({ lagMs: { "ns1.provider.test.": 10 * 60_000 } });
    expect(await dnsTestCommand(["example.test"], config, deps)).toBe(1);
    expect(lines).toContain("  [FAIL] not served by ns1.provider.test. after 120 s");
    expect(lines).toContain("  [ok]   removed TXT _bunzzle-test.example.test");
    expect(provider.values.get("_bunzzle-test.example.test")).toEqual([]);
  });

  test("does not count an old value on a lagging server", async () => {
    const { lines, deps } = setup({
      lagMs: { "ns2.provider.test.": 10 * 60_000 },
      stale: ['"bunzzle-test=old"'],
    });
    expect(await dnsTestCommand(["example.test"], config, deps)).toBe(1);
    expect(lines).toContain("  [FAIL] not served by ns2.provider.test. after 120 s");
  });

  test("reports a provider that cannot read back its own value", async () => {
    const forgets = setup();
    forgets.provider.forgets = true;
    expect(await dnsTestCommand(["example.test"], config, forgets.deps)).toBe(1);
    expect(forgets.lines).toContain(
      "  [FAIL] read it back from desec: the value did not match (created)",
    );

    const refuses = setup();
    refuses.provider.readFails = true;
    expect(await dnsTestCommand(["example.test"], config, refuses.deps)).toBe(1);
    expect(refuses.lines).toContain("  [FAIL] read it back from desec: read refused");
  });

  test("stops at a failed publish and reports a failed remove", async () => {
    const { provider, lines, deps } = setup();
    provider.upsert = async () => ({ ok: false, error: "deSEC: Invalid token." });
    expect(await dnsTestCommand(["example.test"], config, deps)).toBe(1);
    expect(lines).toEqual([
      "provider: desec",
      "  [FAIL] publish TXT _bunzzle-test.example.test: deSEC: Invalid token.",
    ]);

    const stuck = setup();
    stuck.provider.removeFails = true;
    expect(await dnsTestCommand(["example.test"], config, stuck.deps)).toBe(1);
    expect(stuck.lines).toContain("  [FAIL] remove TXT _bunzzle-test.example.test: delete refused");

    const gone = setup();
    gone.provider.remove = async () => ({ ok: true, action: "absent" });
    expect(await dnsTestCommand(["example.test"], config, gone.deps)).toBe(1);
    expect(gone.lines).toContain(
      "  [FAIL] remove TXT _bunzzle-test.example.test: it was already gone",
    );
  });

  test("needs a domain, a provider and name servers", async () => {
    const { deps } = setup();
    expect(dnsTestCommand([], config, deps)).rejects.toThrow(UsageError);
    expect(dnsTestCommand(["--json"], config, deps)).rejects.toThrow(UsageError);
    const none = setup();
    expect(await dnsTestCommand(["example.test"], config, { ...none.deps, opened: null })).toBe(1);
    expect(none.lines[0]).toStartWith("no DNS provider is set");
    const lost = setup();
    expect(await dnsTestCommand(["other.test"], config, lost.deps)).toBe(1);
    expect(lost.lines).toContain("  [FAIL] no name servers found for other.test");
    expect(lost.lines).toContain("  [ok]   removed TXT _bunzzle-test.other.test");
  });
});
