import { expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { startFakeDns } from "../support/fake-dns.ts";
import { startServe } from "../support/serve.ts";

test("serve stops with a clear reason when ns cannot listen on its port", async () => {
  const blocker = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  const dns = await startFakeDns({});
  try {
    const start = startServe({
      BUNZZLE_MASTER_KEY: generateMasterKey(),
      BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
      BUNZZLE_SOURCE_IPS: "127.0.0.1",
      BUNZZLE_EHLO_NAME: "out.bunzzle.test",
      BUNZZLE_NS_ZONE: "dz.mail.test",
      BUNZZLE_NS_NAMES: "ns1.mail.test",
      BUNZZLE_NS_LISTEN: "127.0.0.1",
      BUNZZLE_NS_PORT: String(blocker.port),
    });
    const err = await start.then(
      async (s) => {
        await s.stop();
        return null;
      },
      (e: Error) => e,
    );
    expect(err?.message).toContain('"msg":"ns cannot listen"');
    expect(err?.message).toContain('"code":"EADDRINUSE"');
    expect(err?.message).toContain("another program already uses this port for UDP or TCP");
  } finally {
    blocker.stop(true);
    dns.stop();
  }
}, 60_000);
