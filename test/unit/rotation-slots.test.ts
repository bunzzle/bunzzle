import { afterAll, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import type { Logger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { delegatedRecords, zoneLabel } from "../../src/domains/delegated.ts";
import { dkimValue, saveDomain } from "../../src/domains/domains.ts";
import type { RpcClient } from "../../src/ipc/rpc.ts";
import { rotation } from "../../src/roles/core-rotation.ts";
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

test("delegated keys rotate between the two slots without touching the customer's DNS", async () => {
  let t = Date.UTC(2026, 9, 22);
  const signer = await Signer.create({
    master: await masterKeyFrom(generateMasterKey()),
    keystorePath: `${dir}/epochs.json`,
    dkimKeyFiles: [],
    dkimDir: `${dir}/dkim`,
    clock: { now: () => t },
  });
  await signer.ensureKeys(DOMAIN, "bza-");

  let lag = false;
  const asked: string[] = [];
  const answer = (q: { name: string; type: string }): string[] => {
    asked.push(`${q.type}:${q.name}`);
    const slot = q.name.split(".")[0] ?? "";
    if (q.type === "CNAME" && q.name.endsWith(`._domainkey.${DOMAIN}`)) return [`${slot}.${OWNER}`];
    if (q.type !== "TXT" || !q.name.endsWith(`._domainkey.${DOMAIN}`)) return [];
    const key = signer.publicKeys(DOMAIN)?.find((k) => k.selector === slot);
    if (!key || (lag && key.state === "next")) return [];
    return [dkimValue(key)];
  };
  const published: unknown[] = [];

  const db = openDatabase({ path: ":memory:" });
  const writer = new Writer(db);
  await writer.run((w) =>
    saveDomain(
      w,
      {
        project: DEFAULT_PROJECT,
        name: DOMAIN,
        mode: "delegated",
        status: "verified",
        records: delegatedRecords(DOMAIN, ZONE, null),
        createdAt: t,
        checkedAt: t,
      },
      t,
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
      publish: (p: unknown) => {
        published.push(p);
        return { enabled: true, ok: true };
      },
    }),
    sourceIp: "192.0.2.1",
    inboundHost: null,
    nsZone: ZONE,
    rotateDays: () => 90,
    now: () => t,
  });
  const states = () =>
    (signer.publicKeys(DOMAIN) ?? []).map((k) => `${k.selector}:${k.state}`).sort();

  expect(await r.step(DOMAIN, false)).toBe("keys are current");
  expect(await r.step(DOMAIN, true)).toBe("new keys created");
  expect(states()).toEqual(["bza-e:active", "bza-r:active", "bzb-e:next", "bzb-r:next"]);

  lag = true;
  expect(await r.step(DOMAIN, false)).toBe("waiting for the new DKIM records in DNS");
  lag = false;
  asked.length = 0;
  expect(await r.step(DOMAIN, false)).toBe("switched to new keys");
  expect(asked).toContain(`TXT:bzb-r._domainkey.${DOMAIN}`);
  expect(asked).toContain(`TXT:bzb-e._domainkey.${DOMAIN}`);
  expect(states()).toEqual(["bza-e:retiring", "bza-r:retiring", "bzb-e:active", "bzb-r:active"]);
  expect(await signer.signCanary(DOMAIN, "active")).toMatch(/s=bzb-r;/);

  expect(await r.step(DOMAIN, true)).toBe("waiting for the old keys to leave their slot");
  t += 6 * DAY;
  expect(await r.step(DOMAIN, false)).toBe("keys are current");
  t += DAY;
  expect(await r.step(DOMAIN, false)).toBe("old keys removed");
  expect(states()).toEqual(["bzb-e:active", "bzb-r:active"]);

  expect(await r.step(DOMAIN, true)).toBe("new keys created");
  expect(states()).toEqual(["bza-e:next", "bza-r:next", "bzb-e:active", "bzb-r:active"]);
  expect(published).toEqual([]);
});
