import { afterAll, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import type { Logger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { DKIM_SLOTS, domainRecords, isSlot, zoneLabel } from "../../src/domains/delegated.ts";
import {
  type DomainMode,
  dkimValue,
  findDomain,
  saveDomain,
  zoneDomainNames,
} from "../../src/domains/domains.ts";
import type { RpcClient } from "../../src/ipc/rpc.ts";
import { type RotationDeps, rotation } from "../../src/roles/core-rotation.ts";
import { domainProblems } from "../../src/roles/core-watch.ts";
import { Signer } from "../../src/signer/signer.ts";

const DAY = 86_400_000;
const ZONE = "dz.mail.example.net";
const DOMAIN = "shop.example";
const OWNER = `${zoneLabel(DOMAIN)}.${ZONE}`;
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-slots-${crypto.randomUUID()}`;

afterAll(async () => {
  await Bun.$`rm -rf ${dir}`.quiet();
});

const fake = (methods: Record<string, (p: never) => unknown>) =>
  ({
    call: async (name: string, params: never) => methods[name]?.(params),
  }) as unknown as RpcClient;

async function setup(mode: DomainMode, firstBase: string, extra: Partial<RotationDeps> = {}) {
  const world = {
    t: Date.UTC(2026, 9, 22),
    lag: false,
    cnames: new Set<string>(),
    txt: new Map<string, string>(),
    asked: [] as string[],
    removed: [] as string[],
  };
  const signer = await Signer.create({
    master: await masterKeyFrom(generateMasterKey()),
    keystorePath: `${dir}/${crypto.randomUUID()}/epochs.json`,
    dkimKeyFiles: [],
    dkimDir: `${dir}/${crypto.randomUUID()}/dkim`,
    clock: { now: () => world.t },
  });
  const keys = await signer.ensureKeys(DOMAIN, firstBase);
  for (const k of keys) {
    if (!isSlot(k.selector)) world.txt.set(`${k.selector}._domainkey.${DOMAIN}`, dkimValue(k));
  }
  if (mode === "delegated") for (const slot of DKIM_SLOTS) world.cnames.add(slot);
  const answer = (q: { name: string; type: string }): string[] => {
    world.asked.push(`${q.type}:${q.name}`);
    const slot = q.name.split(".")[0] ?? "";
    if (!q.name.endsWith(`._domainkey.${DOMAIN}`)) return [];
    if (q.type === "CNAME") return world.cnames.has(slot) ? [`${slot}.${OWNER}`] : [];
    const txt = world.txt.get(q.name);
    if (txt) return [txt];
    if (!world.cnames.has(slot)) return [];
    const key = signer.publicKeys(DOMAIN)?.find((k) => k.selector === slot);
    if (!key || (world.lag && key.state === "next")) return [];
    return [dkimValue(key)];
  };

  const db = openDatabase({ path: ":memory:" });
  const writer = new Writer(db);
  await writer.run((w) =>
    saveDomain(
      w,
      {
        project: DEFAULT_PROJECT,
        name: DOMAIN,
        mode,
        status: "verified",
        records: domainRecords({ name: DOMAIN, mode }, keys, "192.0.2.1", null, ZONE),
        createdAt: world.t,
        checkedAt: world.t,
      },
      world.t,
    ),
  );
  const quiet = () => {};
  const r = rotation({
    db,
    writer,
    log: { debug: quiet, info: quiet, warn: quiet, error: quiet } as unknown as Logger,
    signer: fake({
      keyStates: ({ domain }: { domain: string }) => signer.publicKeys(domain) ?? [],
      rotateStart: ({ domain, selectorBase }: { domain: string; selectorBase: string }) =>
        signer.rotateStart(domain, selectorBase),
      promote: ({ domain }: { domain: string }) => signer.promote(domain),
      dropRetiring: ({ domain }: { domain: string }) => signer.dropRetiring(domain),
      signCanary: ({ domain, which }: { domain: string; which: "active" | "next" }) =>
        signer.signCanary(domain, which),
    }),
    delivery: fake({
      dns: ({ queries }: { queries: { name: string; type: string }[] }) =>
        Object.fromEntries(queries.map((q) => [`${q.type}:${q.name}`, answer(q)])),
    }),
    dns: fake({
      publish: (p: { op: string; record?: { name: string; content: string } }) => {
        if (p.op === "upsert" && p.record) world.txt.set(p.record.name, p.record.content);
        if (p.op === "remove" && p.record) {
          world.txt.delete(p.record.name);
          world.removed.push(p.record.name);
        }
        return { enabled: true, ok: true };
      },
    }),
    sourceIp: "192.0.2.1",
    inboundHost: null,
    nsZone: ZONE,
    rotateDays: () => 90,
    now: () => world.t,
    ...extra,
  });
  const states = () =>
    (signer.publicKeys(DOMAIN) ?? []).map((k) => `${k.selector}:${k.state}`).sort();
  const domain = () => findDomain(db, DOMAIN);
  const served = () => zoneDomainNames(db).includes(DOMAIN);
  return { world, signer, r, states, domain, served };
}

test("delegated keys rotate between the two slots without touching the customer's DNS", async () => {
  const { world, signer, r, states } = await setup("delegated", "bza-");

  expect(await r.step(DOMAIN, false)).toBe("keys are current");
  expect(await r.step(DOMAIN, true)).toBe("new keys created");
  expect(states()).toEqual(["bza-e:active", "bza-r:active", "bzb-e:next", "bzb-r:next"]);

  world.lag = true;
  expect(await r.step(DOMAIN, false)).toBe("waiting for the new DKIM records in DNS");
  world.lag = false;
  world.asked.length = 0;
  expect(await r.step(DOMAIN, false)).toBe("switched to new keys");
  expect(world.asked).toContain(`TXT:bzb-r._domainkey.${DOMAIN}`);
  expect(world.asked).toContain(`TXT:bzb-e._domainkey.${DOMAIN}`);
  expect(states()).toEqual(["bza-e:retiring", "bza-r:retiring", "bzb-e:active", "bzb-r:active"]);
  expect(await signer.signCanary(DOMAIN, "active")).toMatch(/s=bzb-r;/);

  expect(await r.step(DOMAIN, true)).toBe("waiting for the old keys to leave their slot");
  world.t += 6 * DAY;
  expect(await r.step(DOMAIN, false)).toBe("keys are current");
  world.t += DAY;
  expect(await r.step(DOMAIN, false)).toBe("old keys removed");
  expect(states()).toEqual(["bzb-e:active", "bzb-r:active"]);

  expect(await r.step(DOMAIN, true)).toBe("new keys created");
  expect(states()).toEqual(["bza-e:next", "bza-r:next", "bzb-e:active", "bzb-r:active"]);
  expect(world.txt.size).toBe(0);
});

test("a domain switches to delegated and back while it stays verified and keeps signing", async () => {
  const { world, signer, r, states, domain, served } = await setup("records", "bz20261001");
  expect(served()).toBe(false);

  const started = await r.switchMode(DOMAIN, "delegated");
  expect(started.mode).toBe("delegated");
  expect(started.status).toBe("verified");
  expect(served()).toBe(true);
  expect(states()).toEqual([
    "bz20261001e:active",
    "bz20261001r:active",
    "bza-e:next",
    "bza-r:next",
  ]);
  await expect(r.switchMode(DOMAIN, "records")).rejects.toThrow("still running");

  expect(await r.step(DOMAIN, false)).toBe("waiting for the new DKIM records in DNS");
  world.cnames.add("bza-r");
  world.cnames.add("bza-e");
  expect(await r.step(DOMAIN, false)).toBe("waiting for the new DKIM records in DNS");
  expect(domain()?.status).toBe("verified");
  expect(await signer.signCanary(DOMAIN, "active")).toMatch(/s=bz20261001r;/);

  world.cnames.add("bzb-r");
  world.cnames.add("bzb-e");
  expect(await r.step(DOMAIN, false)).toBe("switched to new keys");
  expect(domain()?.status).toBe("verified");
  expect(states()).toEqual([
    "bz20261001e:retiring",
    "bz20261001r:retiring",
    "bza-e:active",
    "bza-r:active",
  ]);
  world.t += 7 * DAY;
  expect(await r.step(DOMAIN, false)).toBe("old keys removed");
  expect(world.removed.sort()).toEqual([
    `bz20261001e._domainkey.${DOMAIN}`,
    `bz20261001r._domainkey.${DOMAIN}`,
  ]);

  const back = await r.switchMode(DOMAIN, "records");
  expect(back.mode).toBe("records");
  expect(back.status).toBe("verified");
  expect(states()).toEqual([
    "bz20261029e:next",
    "bz20261029r:next",
    "bza-e:active",
    "bza-r:active",
  ]);
  expect(world.txt.has(`bz20261029r._domainkey.${DOMAIN}`)).toBe(true);
  expect(await r.step(DOMAIN, false)).toBe("switched to new keys");
  expect(domain()?.status).toBe("verified");
  expect(served()).toBe(true);
  world.t += 7 * DAY;
  expect(await r.step(DOMAIN, false)).toBe("old keys removed");
  expect(states()).toEqual(["bz20261029e:active", "bz20261029r:active"]);
  expect(served()).toBe(false);
  expect(world.removed.length).toBe(2);
});

test("only a verified domain without a running rotation can switch", async () => {
  const { r, domain } = await setup("records", "bz20261001");
  expect((await r.switchMode(DOMAIN, "records")).mode).toBe("records");
  await r.step(DOMAIN, true);
  await expect(r.switchMode(DOMAIN, "delegated")).rejects.toThrow("still running");
  expect(domain()?.mode).toBe("records");
});

test("slot keys switch only once every NS serves them", async () => {
  let serving = false;
  const asked: string[] = [];
  const { r, states } = await setup("delegated", "bza-", {
    zoneServes: (domain, keys) => {
      asked.push(`${domain} ${keys.map((k) => k.selector).join(",")}`);
      return serving;
    },
  });
  await r.step(DOMAIN, true);
  expect(await r.step(DOMAIN, false)).toBe("waiting for every NS to serve the new keys");
  expect(asked).toEqual([`${DOMAIN} bzb-r,bzb-e`]);
  serving = true;
  expect(await r.step(DOMAIN, false)).toBe("switched to new keys");
  expect(states()).toContain("bzb-r:active");
});

test("inspect reads DNS without saving, and the watcher lists the problems", async () => {
  const { world, r, domain } = await setup("records", "bza-");
  for (const name of [...world.txt.keys()]) world.txt.delete(name);
  const seen = await r.inspect(DOMAIN, await r.keys(DOMAIN));
  expect(seen?.status).toBe("pending");
  expect(domain()?.status).toBe("verified");
  const problems = await domainProblems(r, DOMAIN);
  expect(problems).toEqual([
    ...["bza-r", "bzb-r", "bza-e", "bzb-e"].map(
      (s) => `CNAME ${s}._domainkey.${DOMAIN} is missing`,
    ),
    "DKIM signatures do not verify: bza-r: no key; bza-e: no key",
  ]);
  expect(await domainProblems(r, "other.example")).toBeNull();
});
