import { describe, expect, test } from "bun:test";
import {
  type DeliverRequest,
  type DeliveryTransport,
  rememberingTransport,
} from "../../src/delivery/transport.ts";
import type { DeliveryReport } from "../../src/smtp/deliver.ts";
import type { RecipientStatus } from "../../src/smtp/session.ts";

function fake(statuses: RecipientStatus[]) {
  let sends = 0;
  let release: (() => void) | null = null;
  const inner: DeliveryTransport = {
    lookup: async (domain) => ({ kind: "defer", domain, code: "dns-temporary", reason: "x" }),
    deliver: async (req): Promise<DeliveryReport> => {
      const status = statuses[sends++] ?? "delivered";
      if (status === "deferred") await new Promise<void>((r) => (release = r));
      return {
        domain: req.domain,
        destination: req.destination,
        provider: null,
        policy: null,
        sessions: [],
        recipients: req.recipients.map((address) => ({
          address,
          status: status === "deferred" ? "delivered" : status,
          phase: "dot",
          code: 250,
          enhanced: "2.0.0",
          reply: "250 ok",
        })),
      };
    },
  };
  return { inner, sends: () => sends, release: () => release?.() };
}

const req = (key: string, recall: string | null = null): DeliverRequest => ({
  key,
  recall,
  messageId: "m",
  domain: "example.test",
  destination: { kind: "defer", domain: "example.test", code: "dns-temporary", reason: "x" },
  from: "a@bunzzle.test",
  recipients: ["x@example.test"],
  smtpUtf8: false,
  requireTls: false,
  body: { epoch: 1, wrapped: new Uint8Array(), body: new Uint8Array() },
});

describe("rememberingTransport", () => {
  test("a resend after a lost reply returns the remembered result instead of sending again", async () => {
    const f = fake(["delivered"]);
    const t = rememberingTransport(f.inner);
    await t.deliver(req("j#1"));
    const again = await t.deliver(req("j#2", "j#1"));
    expect(again.recalled).toBe(true);
    expect(again.recipients[0]?.status).toBe("delivered");
    expect(f.sends()).toBe(1);
  });

  test("a resend while the first attempt is still in its SMTP session waits for it", async () => {
    const f = fake(["deferred"]);
    const t = rememberingTransport(f.inner);
    const first = t.deliver(req("j#1"));
    const second = t.deliver(req("j#2", "j#1"));
    f.release();
    expect((await second).recalled).toBe(true);
    expect((await first).recipients[0]?.status).toBe("delivered");
    expect(f.sends()).toBe(1);
  });

  test("a remembered unknown result is no answer: it sends again", async () => {
    const f = fake(["unknown", "delivered"]);
    const t = rememberingTransport(f.inner);
    await t.deliver(req("j#1"));
    const again = await t.deliver(req("j#2", "j#1"));
    expect(again.recalled).toBeUndefined();
    expect(f.sends()).toBe(2);
  });

  test("nothing remembered (delivery restarted): it sends", async () => {
    const f = fake(["delivered"]);
    const t = rememberingTransport(f.inner);
    expect((await t.deliver(req("j#2", "j#1"))).recalled).toBeUndefined();
    expect(f.sends()).toBe(1);
  });

  test("memory is bounded and expires", async () => {
    let now = 0;
    const f = fake([]);
    const t = rememberingTransport(f.inner, { maxEntries: 2, ttlMs: 1_000, now: () => now });
    await t.deliver(req("a#1"));
    await t.deliver(req("b#1"));
    await t.deliver(req("c#1"));
    expect((await t.deliver(req("a#2", "a#1"))).recalled).toBeUndefined();
    now = 5_000;
    expect((await t.deliver(req("c#2", "c#1"))).recalled).toBeUndefined();
  });

  test("results the core has recorded are forgotten; unrecorded ones are kept for recall", async () => {
    const f = fake([]);
    const t = rememberingTransport(f.inner);
    await t.deliver(req("a#1"));
    await t.deliver(req("b#1"));
    await t.deliver(req("c#1"));
    t.forget(["a#1"]);
    await t.deliver({ ...req("d#1"), settled: ["b#1"] });
    expect(t.remembered).toBe(2);
    expect((await t.deliver(req("c#2", "c#1"))).recalled).toBe(true);
    expect((await t.deliver(req("a#2", "a#1"))).recalled).toBeUndefined();
  });

  test("old results expire even when nobody asks for them", async () => {
    let now = 0;
    const f = fake([]);
    const t = rememberingTransport(f.inner, { ttlMs: 1_000, now: () => now });
    for (let i = 0; i < 100; i++) await t.deliver(req(`m${i}#1`));
    expect(t.remembered).toBe(100);
    now = 5_000;
    t.forget([]);
    expect(t.remembered).toBe(0);
  });
});
