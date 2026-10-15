import { Database } from "bun:sqlite";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { generateKeyFile, sealKeyFile } from "../../src/dkim/keys.ts";
import { RpcClient, RpcError } from "../../src/ipc/rpc.ts";
import { verifyDkim } from "../support/dkim-verify.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { alive, type Served, startServe } from "../support/serve.ts";

const N = 300;
const KILLS = [
  "delivery",
  "core",
  "signer",
  "delivery",
  "api",
  "core",
  "inbound",
  "signer",
  "delivery",
  "core",
  "signer",
  "delivery",
];
const keysDir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-roles-keys-${crypto.randomUUID()}`;
const masterText = generateMasterKey();
const keyFile = await generateKeyFile("bunzzle.test", "t1");

let dns: FakeDns;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};

async function verifiedDomain(core: RpcClient, name: string) {
  const d = await core.call<{ records: { record: string; name: string; value: string }[] }>(
    "addDomain",
    { name },
  );
  for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
  const v = await core.call<{ status: string }>("verifyDomain", { name });
  expect(v.status).toBe("verified");
}
let mx: FakeMx;
let served: Served;

beforeAll(async () => {
  await Bun.$`mkdir -p ${keysDir}/dkim`.quiet();
  const sealed = await sealKeyFile(keyFile, await masterKeyFrom(masterText));
  await Bun.write(`${keysDir}/dkim/bunzzle.test.json`, JSON.stringify(sealed));
  dns = await startFakeDns(zone);
  let greetings = 0;
  mx = startFakeMx({
    finalDelayMs: 500,
    greeting: () =>
      ++greetings % 17 === 0
        ? "451 4.3.0 Temporary local problem\r\n"
        : "220 mx.example.test ESMTP\r\n",
  });
  served = await startServe({
    BUNZZLE_MASTER_KEY: masterText,
    BUNZZLE_KEYS_DIR: keysDir,
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
});

afterAll(async () => {
  if (served.proc.exitCode === null) await served.stop();
  dns.stop();
  mx.stop();
  await Bun.$`rm -rf ${keysDir}`.quiet();
});

const message = (i: number) =>
  `From: Bunzzle <hello@bunzzle.test>\r\nTo: user${i}@example.test\r\nSubject: email-${i}\r\nMessage-ID: <e${i}@bunzzle.test>\r\n\r\nHello ${i}\r\n`;

async function callRetrying<T>(client: RpcClient, method: string, params: unknown): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await client.call<T>(method, params, { timeoutMs: 5_000 });
    } catch (err) {
      if (!(err instanceof RpcError) || err.code === "invalid" || attempt > 200) throw err;
      await Bun.sleep(25);
    }
  }
}

test(
  "no email is lost or silently duplicated while roles are killed at random",
  async () => {
    const core = new RpcClient(`${served.dir}/run/core.sock`);
    await verifiedDomain(core, "bunzzle.test");
    let kills = 0;
    const killer = (async () => {
      for (const role of KILLS) {
        await Bun.sleep(600);
        const pid = served.pids.get(role);
        if (pid && alive(pid)) {
          process.kill(pid, "SIGKILL");
          kills++;
        }
      }
    })();

    const ids = Array.from({ length: N }, (_, i) => `e${i}`);
    for (let i = 0; i < N; i += 20) {
      await Promise.all(
        ids.slice(i, i + 20).map((id, j) =>
          callRetrying(core, "enqueue", {
            id,
            from: "hello@bunzzle.test",
            recipients: [`user${i + j}@example.test`],
            data: message(i + j),
          }),
        ),
      );
    }

    const delivered = async () => {
      const rows = await Promise.all(
        ids.map((id) =>
          callRetrying<{ status: string }[]>(core, "status", { id }).then((r) => r[0]?.status),
        ),
      );
      return rows.filter((s) => s === "delivered").length;
    };
    await killer;
    const end = Date.now() + 120_000;
    let done = 0;
    while (Date.now() < end) {
      done = await delivered();
      if (done === N) break;
      await Bun.sleep(250);
    }
    core.close();
    expect(kills).toBeGreaterThanOrEqual(10);
    expect(done).toBe(N);

    const counts = new Map<string, number>();
    for (const s of mx.sessions) {
      for (const m of s.messages) {
        const id = /Subject: email-(\d+)/.exec(m)?.[1];
        if (id !== undefined) counts.set(`e${id}`, (counts.get(`e${id}`) ?? 0) + 1);
      }
    }
    expect(ids.filter((id) => !counts.has(id))).toEqual([]);

    const dbPath = `${served.dir}/data/bunzzle.db`;
    served.proc.kill("SIGTERM");
    expect(await served.proc.exited).toBe(0);
    const db = new Database(dbPath, { readonly: true });
    const risk = new Map(
      db
        .query<{ message_id: string; n: number }, []>(
          "SELECT message_id, count(*) AS n FROM events WHERE kind = 'duplicate_risk' GROUP BY message_id",
        )
        .all()
        .map((r) => [r.message_id, r.n]),
    );
    const reconciled =
      db
        .query<{ n: number }, []>("SELECT count(*) AS n FROM events WHERE kind = 'reconciled'")
        .get()?.n ?? 0;
    db.close();
    expect(reconciled).toBeGreaterThan(0);
    const unrecorded = [...counts].filter(([id, n]) => n - 1 > (risk.get(id) ?? 0));
    expect(unrecorded).toEqual([]);

    const sample = mx.sessions.flatMap((s) => s.messages)[0] ?? "";
    const verdicts = await verifyDkim(
      sample,
      Object.fromEntries(
        keyFile.keys.map((k) => [
          k.selector,
          { algorithm: k.algorithm, key: Uint8Array.fromBase64(k.publicKey) },
        ]),
      ),
    );
    expect(verdicts.every((v) => v.ok)).toBe(true);
    console.log(
      `roles test: ${N} emails, ${kills} roles killed, ${[...counts.values()].reduce((a, b) => a + b, 0)} deliveries, ${risk.size} recorded duplicate risks, ${reconciled} resends avoided by reconciliation`,
    );
  },
  { timeout: 240_000 },
);

test("core refuses email from a domain the signer has no key for", async () => {
  const again = await startServe({
    BUNZZLE_MASTER_KEY: masterText,
    BUNZZLE_KEYS_DIR: keysDir,
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
  });
  const core = new RpcClient(`${again.dir}/run/core.sock`);
  const err = await core
    .call("enqueue", {
      from: "ceo@other.test",
      recipients: ["x@example.test"],
      data: "From: ceo@other.test\r\nSubject: x\r\n\r\nx\r\n",
    })
    .then(
      () => null,
      (e: RpcError) => e,
    );
  core.close();
  await again.stop();
  expect(err?.code).toBe("unverified-domain");
  expect(err?.message).toContain("other.test domain is not registered");
});
