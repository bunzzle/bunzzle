import { expect, test } from "bun:test";
import type { Logger } from "../../src/core/log.ts";
import { measureNs } from "../../src/dns/probe.ts";
import type { QueryType, Server } from "../../src/dns/resolver.ts";
import type { DnsMessage, ResourceRecord } from "../../src/dns/wire.ts";
import { nsProbe } from "../../src/roles/core-ns.ts";

const ZONE = "dz.mail.example.net";

function world() {
  const w = {
    t: 1_000_000,
    serial: 100,
    down: new Set<string>(),
    dead: false,
    pushed: { serial: 100, at: 1_000_000 } as { serial: number; at: number } | null,
    events: [] as { kind: string; ns: unknown }[],
    errors: [] as string[],
  };
  const reply = (name: string, type: number, answers: ResourceRecord[]): DnsMessage => ({
    id: 1,
    rcode: 0,
    truncated: false,
    authenticated: false,
    authoritative: true,
    question: { name, type },
    answers,
    authority: [],
  });
  const ask = async (server: Server, name: string, type: QueryType, proto: "udp" | "tcp") => {
    if (w.down.has(`${server.host}/${proto}`)) throw new Error("timeout");
    if (type === "SOA") {
      return reply(name, 6, [
        {
          name,
          type: "SOA",
          ttl: 300,
          rdata: new Uint8Array(),
          soa: { mname: `ns1.${ZONE}`, serial: w.serial, minimum: 300 },
        } as ResourceRecord,
      ]);
    }
    return reply(name, 16, [
      {
        name,
        type: "TXT",
        ttl: 300,
        rdata: new Uint8Array(),
        strings: [String(w.serial)],
      } as ResourceRecord,
    ]);
  };
  const quiet = () => {};
  const probe = nsProbe({
    targets: async () => {
      if (w.dead) throw new Error("ns.sock: Failed to connect");
      return [
        { host: "192.0.2.1", port: 53 },
        { host: "192.0.2.2", port: 53 },
      ];
    },
    pushed: () => w.pushed,
    measure: (server) => measureNs(server, ZONE, ask),
    raise: async (kind, data) => {
      w.events.push({ kind, ns: data["ns"] });
    },
    log: {
      debug: quiet,
      info: quiet,
      warn: quiet,
      error: (msg: string) => w.errors.push(msg),
    } as unknown as Logger,
    now: () => w.t,
  });
  return { w, probe };
}

test("every listener is asked over UDP and TCP; healthy listeners raise nothing", async () => {
  const { w, probe } = world();
  await probe.tick();
  expect(probe.view().map((v) => [v.ns, v.udp, v.tcp, v.serial, v.healthy])).toEqual([
    ["192.0.2.1", true, true, 100, true],
    ["192.0.2.2", true, true, 100, true],
  ]);
  expect(w.events).toEqual([]);
});

test("three failed probes in a row raise one ns.unhealthy, recovery raises ns.healthy", async () => {
  const { w, probe } = world();
  w.down.add("192.0.2.2/tcp");
  await probe.tick();
  await probe.tick();
  expect(w.events).toEqual([]);
  await probe.tick();
  await probe.tick();
  expect(w.events).toEqual([{ kind: "ns.unhealthy", ns: "192.0.2.2" }]);
  expect(w.errors).toEqual(["ns is unhealthy"]);
  expect(probe.view().find((v) => v.ns === "192.0.2.2")?.udp).toBe(true);
  w.down.clear();
  await probe.tick();
  expect(w.events.at(-1)).toEqual({ kind: "ns.healthy", ns: "192.0.2.2" });
});

test("a serial more than 120 s behind the pushed one is unhealthy at once", async () => {
  const { w, probe } = world();
  w.pushed = { serial: 101, at: w.t };
  w.t += 120_000;
  await probe.tick();
  expect(probe.view()[0]?.lagSeconds).toBe(120);
  expect(w.events).toEqual([]);
  w.t += 1_000;
  await probe.tick();
  expect(probe.view()[0]?.lagSeconds).toBe(121);
  expect(w.events.map((e) => e.kind)).toEqual(["ns.unhealthy", "ns.unhealthy"]);
});

test("servesAtLeast needs every listener up on both protocols at that serial", async () => {
  const { w, probe } = world();
  expect(probe.servesAtLeast(100)).toBe(false);
  await probe.tick();
  expect(probe.servesAtLeast(100)).toBe(true);
  expect(probe.servesAtLeast(101)).toBe(false);
  w.down.add("192.0.2.1/udp");
  await probe.tick();
  expect(probe.servesAtLeast(100)).toBe(false);
});

test("poll probes once a minute while all is up, every 10 s while a listener is down", async () => {
  const { w, probe } = world();
  await probe.poll();
  expect(probe.view().length).toBe(2);
  w.serial = 101;
  w.t += 59_000;
  await probe.poll();
  expect(probe.view()[0]?.serial).toBe(100);
  w.t += 1_000;
  await probe.poll();
  expect(probe.view()[0]?.serial).toBe(101);
  w.down.add("192.0.2.1/udp");
  w.t += 60_000;
  await probe.poll();
  w.t += 9_000;
  await probe.poll();
  expect(probe.view()[0]?.failures).toBe(1);
  w.t += 1_000;
  await probe.poll();
  expect(probe.view()[0]?.failures).toBe(2);
});

test("a dead ns role counts as a failure on every known listener", async () => {
  const { w, probe } = world();
  await probe.tick();
  w.dead = true;
  await probe.tick();
  await probe.tick();
  expect(w.events).toEqual([]);
  await probe.tick();
  expect(probe.view().map((v) => [v.ns, v.udp, v.tcp, v.failures])).toEqual([
    ["192.0.2.1", false, false, 3],
    ["192.0.2.2", false, false, 3],
  ]);
  expect(w.events.map((e) => e.kind)).toEqual(["ns.unhealthy", "ns.unhealthy"]);
  w.dead = false;
  await probe.tick();
  expect(w.events.map((e) => e.kind).slice(2)).toEqual(["ns.healthy", "ns.healthy"]);
});
