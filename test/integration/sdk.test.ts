import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Bunzzle, BunzzleError } from "../../sdk/typescript/index.js";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let client: Bunzzle;

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  const proc = Bun.spawn(
    ["bun", MAIN, "keys", "create", "--name", "sdk", "--scope", "full", "--rate-limit", "1000"],
    {
      cwd: served.dir,
      env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
      stdout: "pipe",
    },
  );
  const apiKey = (await new Response(proc.stdout).text()).trim().split("\n").at(-1) ?? "";
  client = new Bunzzle({ apiKey, baseUrl: served.url });
}, 30_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("TypeScript SDK against a running server", () => {
  test("domain, send, read back", async () => {
    const d = await client.createDomain({ name: "acme.test" });
    expect(d.status).toBe("pending");
    for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
    expect((await client.verifyDomain("acme.test")).status).toBe("verified");

    const { id } = await client.sendEmail(
      { from: "Acme <hello@acme.test>", to: "user@example.test", subject: "Hi", text: "Hi" },
      { idempotencyKey: "sdk-1" },
    );
    const again = await client.sendEmail(
      { from: "Acme <hello@acme.test>", to: "user@example.test", subject: "Hi", text: "Hi" },
      { idempotencyKey: "sdk-1" },
    );
    expect(again.id).toBe(id);
    let email = await client.getEmail(id);
    for (let i = 0; i < 50 && email.last_event !== "delivered"; i++) {
      await Bun.sleep(100);
      email = await client.getEmail(id);
    }
    expect(email.last_event).toBe("delivered");
    const list = await client.listEmails({ to: "user@example.test", limit: 1 });
    expect(list.data[0]?.id).toBe(id);
  });

  test("path values with : and + reach the server", async () => {
    await client.createSuppression({ email: "a+b@example.test" });
    expect((await client.deleteSuppression("a+b@example.test")).removed).toBe(1);
    await client.suspendDelivery({ target: "domain:example.test", reason: "sdk test" });
    await client.resumeDelivery("domain:example.test");
    expect(await client.getMetrics()).toContain("# EOF");
  });

  test("refusals throw BunzzleError with the API's error", async () => {
    const err = await client
      .sendEmail({ from: "x@nope.test", to: "user@example.test", subject: "s", text: "t" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BunzzleError);
    expect(err).toMatchObject({ statusCode: 403 });
  });
});
