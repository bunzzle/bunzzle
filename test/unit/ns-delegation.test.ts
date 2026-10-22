import { expect, test } from "bun:test";
import type { Logger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { type Delegation, delegationProblems } from "../../src/dns/delegation.ts";
import { delegationAt } from "../../src/dns/probe.ts";
import type { DnsAnswer, QueryType, Resolver, Server } from "../../src/dns/resolver.ts";
import type { DnsMessage, ResourceRecord } from "../../src/dns/wire.ts";
import { collect, render } from "../../src/metrics/metrics.ts";
import { delegationCheck } from "../../src/roles/core-ns.ts";

const ZONE = "dz.mail.example.net";
const NAMES = ["ns1.mail.example.net", "ns2.mail.example.net"];
const LISTEN = ["192.0.2.1", "192.0.2.2"];

const rr = (name: string, data: Record<string, unknown>) =>
  ({ name, ttl: 300, rdata: new Uint8Array(), ...data }) as ResourceRecord;

function resolver(records: Record<string, ResourceRecord[]>): Resolver {
  return {
    async query(name: string, type: QueryType): Promise<DnsAnswer> {
      return {
        name,
        type,
        rcode: 0,
        authenticated: false,
        ttl: 300,
        records: (records[`${type} ${name}`] ?? []) as DnsAnswer["records"],
      };
    },
    message: async () => {
      throw new Error("not used");
    },
  };
}

const parent = resolver({
  "NS example.net": [rr("example.net", { type: "NS", target: "a.parent-ns.test" })],
  "A a.parent-ns.test": [rr("a.parent-ns.test", { type: "A", address: "198.51.100.1" })],
  "A ns2.mail.example.net": [rr("ns2.mail.example.net", { type: "A", address: "192.0.2.2" })],
});

function referral(ns: string[], glue: [string, string][]) {
  const asked: string[] = [];
  const ask = async (server: Server, name: string, type: QueryType): Promise<DnsMessage> => {
    asked.push(`${server.host}:${server.port} ${type} ${name}`);
    return {
      id: 1,
      rcode: 0,
      truncated: false,
      authenticated: false,
      authoritative: false,
      question: { name, type: 2 },
      answers: [],
      authority: ns.map((n) => rr(ZONE, { type: "NS", target: n })),
      additional: glue.map(([n, ip]) => rr(n, { type: "A", address: ip })),
    };
  };
  return { ask, asked };
}

test("the parent is found by walking up, then one of its servers is asked directly", async () => {
  const r = referral(NAMES, [["ns1.mail.example.net", "192.0.2.1"]]);
  const d = await delegationAt(`${ZONE}.`, parent, r.ask);
  expect(r.asked).toEqual([`198.51.100.1:53 NS ${ZONE}`]);
  expect(d).toEqual({
    parent: "example.net",
    asked: "a.parent-ns.test",
    ns: NAMES,
    glue: { "ns1.mail.example.net": ["192.0.2.1"] },
    addresses: { "ns1.mail.example.net": ["192.0.2.1"], "ns2.mail.example.net": ["192.0.2.2"] },
    error: null,
  });
  expect(delegationProblems(d, ZONE, NAMES, LISTEN)).toEqual([]);
});

test("no parent and no answer are reported as errors", async () => {
  expect((await delegationAt(ZONE, resolver({}), referral([], []).ask)).error).toBe(
    "no parent zone with NS records found",
  );
  const silent = async (): Promise<DnsMessage> => {
    throw new Error("timeout");
  };
  expect((await delegationAt(ZONE, parent, silent)).error).toBe(
    "no answer from the servers of example.net",
  );
});

test("each difference from the settings is one problem", () => {
  const base: Delegation = {
    parent: "example.net",
    asked: "a.parent-ns.test",
    ns: ["ns1.mail.example.net", "ns3.other.test"],
    glue: {},
    addresses: { "ns1.mail.example.net": ["203.0.113.9"], "ns3.other.test": ["192.0.2.1"] },
    error: null,
  };
  expect(delegationProblems(base, ZONE, NAMES, LISTEN)).toEqual([
    "ns2.mail.example.net is missing from the NS set",
    "ns3.other.test is in the NS set but not in BUNZZLE_NS_NAMES",
    "ns1.mail.example.net points to 203.0.113.9, which is not in BUNZZLE_NS_LISTEN",
  ]);
  const inZone = ["ns1.dz.mail.example.net"];
  expect(
    delegationProblems(
      { ...base, ns: inZone, addresses: { "ns1.dz.mail.example.net": ["192.0.2.1"] } },
      ZONE,
      inZone,
      LISTEN,
    ),
  ).toEqual(["ns1.dz.mail.example.net has no glue at example.net"]);
  expect(delegationProblems({ ...base, ns: [], addresses: {} }, ZONE, NAMES, LISTEN)[0]).toBe(
    `example.net does not delegate ${ZONE}`,
  );
});

test("a mismatch raises one event, is checked hourly, and is ok after two good checks", async () => {
  let t = 0;
  let ns = ["ns1.mail.example.net"];
  const events: string[] = [];
  const lookups: number[] = [];
  const check = delegationCheck({
    zone: ZONE,
    names: NAMES,
    listen: LISTEN,
    lookup: async () => {
      lookups.push(t);
      return {
        parent: "example.net",
        asked: "a",
        ns,
        glue: {},
        addresses: Object.fromEntries(ns.map((n, i) => [n, [LISTEN[i] ?? ""]])),
        error: null,
      };
    },
    raise: async (kind) => {
      events.push(kind);
    },
    log: { error: () => {}, info: () => {} } as unknown as Logger,
    now: () => t,
  });
  const hour = 3_600_000;
  await check.poll();
  await check.poll();
  expect(events).toEqual(["ns.delegation_mismatch"]);
  const db = openDatabase({ path: ":memory:" });
  const text = render(collect(db, null, [], t, t, undefined, null, check.view()));
  expect(text).toContain("bunzzle_ns_delegation_ok 0");
  expect(text).toContain("bunzzle_ns_delegation_problems 1");
  for (const good of [true, false, true, false, true, true]) {
    t += hour;
    ns = good ? NAMES : ["ns1.mail.example.net"];
    await check.poll();
  }
  expect(events).toEqual(["ns.delegation_mismatch", "ns.delegation_ok"]);
  expect(check.view()?.mismatched).toBe(false);
  t += hour;
  await check.poll();
  t += 86_400_000 - hour;
  await check.poll();
  expect(lookups).toEqual([0, 1, 2, 3, 4, 5, 6, 30].map((h) => h * hour));
});
