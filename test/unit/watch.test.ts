import { expect, test } from "bun:test";
import { recordAdminEvent, SYSTEM_PROJECT } from "../../src/accounts/projects.ts";
import type { Logger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { bimiCheck, dmarcEnforced } from "../../src/domains/bimi.ts";
import { collect, render } from "../../src/metrics/metrics.ts";
import { domainWatch, listingWatch } from "../../src/roles/core-watch.ts";

const HOUR = 3_600_000;
const quiet = () => {};
const log = { debug: quiet, info: quiet, warn: quiet, error: quiet } as unknown as Logger;

function recorder(db: ReturnType<typeof openDatabase>) {
  const events: string[] = [];
  const raise = async (kind: string, data: Record<string, unknown>) => {
    events.push(
      `${kind} ${String(data["ip"] ?? data["domain"])}${data["list"] ? ` ${data["list"]}` : ""}`,
    );
    recordAdminEvent(db, { kind, project: SYSTEM_PROJECT, actor: "core", data }, Date.now());
  };
  return { events, raise };
}

const ip = (address: string, ...lists: [string, "clean" | "listed" | "unusable"][]) => ({
  ip: address,
  listings: lists.map(([list, status]) => ({ list, name: list, status, removal: null })),
});

test("a listing raises one event when it starts and one when it ends", async () => {
  const db = openDatabase({ path: ":memory:" });
  const { events, raise } = recorder(db);
  const w = listingWatch({ db, raise, log });
  await w.update([ip("192.0.2.1", ["zen", "clean"], ["psbl", "clean"])]);
  await w.update([ip("192.0.2.1", ["zen", "listed"], ["psbl", "clean"])]);
  await w.update([ip("192.0.2.1", ["zen", "listed"], ["psbl", "clean"])]);
  await w.update([ip("192.0.2.1", ["zen", "unusable"], ["psbl", "clean"])]);
  expect(w.view()).toEqual([
    { ip: "192.0.2.1", list: "zen", listed: true },
    { ip: "192.0.2.1", list: "psbl", listed: false },
  ]);
  await w.update([ip("192.0.2.1", ["zen", "clean"], ["psbl", "clean"])]);
  await w.update([{ ip: "192.0.2.2", listings: null }]);
  expect(events).toEqual(["ip.listed 192.0.2.1 zen", "ip.delisted 192.0.2.1 zen"]);
});

test("after a restart a listing that was already raised is not raised again", async () => {
  const db = openDatabase({ path: ":memory:" });
  const { events, raise } = recorder(db);
  await listingWatch({ db, raise, log }).update([ip("192.0.2.1", ["zen", "listed"])]);
  const again = listingWatch({ db, raise, log });
  await again.update([ip("192.0.2.1", ["zen", "listed"])]);
  expect(again.view()).toEqual([{ ip: "192.0.2.1", list: "zen", listed: true }]);
  await again.update([ip("192.0.2.1", ["zen", "clean"])]);
  expect(events).toEqual(["ip.listed 192.0.2.1 zen", "ip.delisted 192.0.2.1 zen"]);
});

function domains(start: Record<string, boolean>) {
  const db = openDatabase({ path: ":memory:" });
  const { events, raise } = recorder(db);
  const world = {
    t: Date.UTC(2026, 9, 26),
    verified: { ...start } as Record<string, boolean>,
    problems: new Map<string, string[] | null>(),
    checked: [] as string[],
  };
  const make = () =>
    domainWatch({
      db,
      domains: () => Object.entries(world.verified).map(([name, verified]) => ({ name, verified })),
      problems: async (d) => {
        world.checked.push(`${(world.t - Date.UTC(2026, 9, 26)) / HOUR}h ${d}`);
        return world.problems.has(d) ? (world.problems.get(d) ?? null) : [];
      },
      raise,
      log,
      now: () => world.t,
    });
  return { world, events, make, w: make() };
}

test("a domain raises domain.dns_problem after two bad checks and domain.dns_ok after two good ones", async () => {
  const { world, events, w } = domains({ "shop.example": true, "new.example": false });
  await w.tick();
  expect(world.checked).toEqual(["0h shop.example"]);
  world.t += 5 * HOUR;
  await w.tick();
  world.t += HOUR;
  world.problems.set("shop.example", ["TXT _dmarc.shop.example is missing"]);
  world.verified["shop.example"] = false;
  await w.tick();
  expect(events).toEqual([]);
  world.t += HOUR;
  await w.tick();
  expect(events).toEqual(["domain.dns_problem shop.example"]);
  expect(w.view()).toEqual([
    {
      domain: "shop.example",
      problems: ["TXT _dmarc.shop.example is missing"],
      alerted: true,
      checkedAt: world.t,
    },
  ]);
  world.t += HOUR;
  world.problems.set("shop.example", null);
  await w.tick();
  world.problems.delete("shop.example");
  for (let i = 0; i < 2; i++) {
    world.t += HOUR;
    await w.tick();
  }
  expect(events).toEqual(["domain.dns_problem shop.example", "domain.dns_ok shop.example"]);
  expect(world.checked).toEqual([
    "0h shop.example",
    "6h shop.example",
    "7h shop.example",
    "8h shop.example",
    "9h shop.example",
    "10h shop.example",
  ]);
});

test("a domain alert survives a restart and a removed domain is dropped", async () => {
  const { world, events, make, w } = domains({ "shop.example": true });
  world.problems.set("shop.example", ["CNAME bounce.shop.example is wrong"]);
  await w.tick();
  world.t += HOUR;
  await w.tick();
  world.verified["shop.example"] = false;
  const again = make();
  world.problems.delete("shop.example");
  await again.tick();
  world.t += HOUR;
  await again.tick();
  expect(events).toEqual(["domain.dns_problem shop.example", "domain.dns_ok shop.example"]);
  delete world.verified["shop.example"];
  await again.tick();
  expect(again.view()).toEqual([]);
});

test("watch metrics are rendered for IPs and domains", async () => {
  const db = openDatabase({ path: ":memory:" });
  const t = Date.now();
  const text = render(
    collect(db, null, [], t, t, undefined, null, null, null, null, {
      listings: [{ ip: "192.0.2.1", list: "zen", listed: true }],
      domains: [{ domain: "shop.example", problems: ["a", "b"], alerted: true, checkedAt: t }],
    }),
  );
  expect(text).toContain('bunzzle_ip_listed{ip="192.0.2.1",list="zen"} 1');
  expect(text).toContain('bunzzle_domain_dns_problems{domain="shop.example"} 2');
  expect(text).toContain('bunzzle_domain_dns_ok{domain="shop.example"} 0');
  expect(render(collect(db, null, [], t, t))).not.toContain("bunzzle_ip_listed");
});

test("DMARC counts for BIMI only when it quarantines or rejects all mail", () => {
  expect(dmarcEnforced("v=DMARC1; p=reject")).toBe(true);
  expect(dmarcEnforced("v=DMARC1; p=quarantine; pct=100; sp=reject")).toBe(true);
  expect(dmarcEnforced("v=DMARC1; p=quarantine; pct=50")).toBe(false);
  expect(dmarcEnforced("v=DMARC1; p=reject; sp=none")).toBe(false);
  expect(dmarcEnforced("v=DMARC1; p=none")).toBe(false);
  expect(dmarcEnforced(null)).toBe(false);
});

test("BIMI is checked only when a record is published", () => {
  const reject = "v=DMARC1; p=reject; rua=mailto:d@example.com";
  const logo = "https://example.com/logo.svg";
  const vmc = "https://example.com/vmc.pem";
  expect(bimiCheck([], reject)).toBeNull();
  expect(bimiCheck(["v=spf1 -all"], reject)).toBeNull();
  expect(bimiCheck([`v=BIMI1; l=${logo}; a=${vmc}`], reject)).toEqual({
    status: "ok",
    detail: `logo ${logo}, mark certificate ${vmc}`,
  });
  expect(bimiCheck([`v=BIMI1; l=${logo}`], reject)?.status).toBe("warn");
  expect(bimiCheck(["v=BIMI1; l=; a=;"], null)?.status).toBe("ok");
  expect(bimiCheck([`v=BIMI1; l=http://example.com/logo.svg; a=${vmc}`], reject)?.status).toBe(
    "fail",
  );
  expect(bimiCheck([`v=BIMI1; l=${logo}; a=ftp://example.com/vmc.pem`], reject)?.status).toBe(
    "fail",
  );
  expect(bimiCheck([`v=BIMI1; l=${logo}; a=${vmc}`], "v=DMARC1; p=none")).toEqual({
    status: "fail",
    detail:
      'no logo is shown until DMARC is p=quarantine or p=reject for all mail: found "v=DMARC1; p=none"',
  });
  expect(bimiCheck([`v=BIMI1; l=${logo}`, `v=BIMI1; l=${logo}`], reject)?.status).toBe("fail");
});
