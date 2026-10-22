import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { reportMail, reportXml, zip } from "../support/dmarc.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";
import { deliverMail, smtpTalk } from "../support/smtp-client.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let token: string;
let secret: string;
let hookId: string;
let apiPort: number;
const hooks: {
  type: string;
  data: Record<string, unknown>;
  valid: boolean;
  at: number;
  msgId: string;
}[] = [];
let receiver: ReturnType<typeof Bun.serve>;

async function verify(id: string, ts: string, body: string, sig: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    Uint8Array.fromBase64(secret.replace(/^whsec_/, "")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${ts}.${body}`)),
  );
  return sig.split(" ").includes(`v1,${mac.toBase64()}`);
}

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  return { stdout, code };
}

const api = (path: string, init: RequestInit = {}) =>
  fetch(`${served.url}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  });

async function send(extra: Record<string, unknown> = {}): Promise<string> {
  const r = await api("/emails", {
    method: "POST",
    body: JSON.stringify({
      from: "Acme <hello@acme.test>",
      to: ["user@example.test"],
      subject: "Hi",
      text: "Hello",
      ...extra,
    }),
  });
  expect(r.status).toBe(200);
  return ((await r.json()) as { id: string }).id;
}

async function until<T>(f: () => T | Promise<T>, ok: (v: T) => boolean, ms = 10_000): Promise<T> {
  const end = Date.now() + ms;
  let v = await f();
  while (!ok(v) && Date.now() < end) {
    await Bun.sleep(50);
    v = await f();
  }
  return v;
}

const hook = (type: string, recipient?: string) =>
  until(
    () => hooks.find((h) => h.type === type && (!recipient || h.data["recipient"] === recipient)),
    (h) => h !== undefined,
  );

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  receiver = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const body = await req.text();
      const valid = await verify(
        req.headers.get("webhook-id") ?? "",
        req.headers.get("webhook-timestamp") ?? "",
        body,
        req.headers.get("webhook-signature") ?? "",
      );
      const parsed = JSON.parse(body) as { type: string; data: Record<string, unknown> };
      hooks.push({ ...parsed, valid, at: Date.now(), msgId: req.headers.get("webhook-id") ?? "" });
      return new Response("ok");
    },
  });
  const probe = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  apiPort = probe.port;
  probe.stop(true);
  served = await startServe({
    BUNZZLE_PORT: String(apiPort),
    BUNZZLE_PUBLIC_URL: `http://127.0.0.1:${apiPort}`,
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_INBOUND_HOSTNAME: "in.bunzzle.test",
    BUNZZLE_INBOUND_HOST: "127.0.0.1",
    BUNZZLE_INBOUND_PORT: "0",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  const k = await cli("keys", "create", "--name", "t", "--scope", "full");
  token = k.stdout.trim().split("\n").at(-1) ?? "";
  await cli("domains", "add", "acme.test");
  const d = (await (await api("/domains/acme.test")).json()) as {
    records: { record: string; name: string; type: string; value: string }[];
  };
  for (const r of d.records) {
    if (r.record === "DKIM") zone[r.name] = { TXT: [r.value] };
  }
  zone["bounce.acme.test"] = { MX: [[10, "in.bunzzle.test"]], TXT: ["v=spf1 a mx ~all"] };
  const v = await cli("domains", "verify", "acme.test");
  expect(v.stdout).toContain("[ok] RETURN_PATH_MX");
  const w = (await (
    await api("/webhooks", {
      method: "POST",
      body: JSON.stringify({ endpoint: `http://127.0.0.1:${receiver.port}/hooks` }),
    })
  ).json()) as { id: string; signing_secret: string };
  secret = w.signing_secret;
  hookId = w.id;
  expect(secret).toMatch(/^whsec_/);
}, 30_000);

afterAll(async () => {
  await served.stop();
  receiver.stop(true);
  dns.stop();
  mx.stop();
});

const lastMessage = () => mx.sessions.flatMap((s) => s.messages).at(-1) ?? "";
const mailFromOf = (i = -1) =>
  mx.sessions.flatMap((s) => s.commands.filter((c) => c.startsWith("MAIL FROM"))).at(i) ?? "";

describe("signed return path and webhooks", () => {
  test("mail goes out with a signed return path; a signed delivered webhook arrives", async () => {
    const id = await send();
    const h = await hook("email.delivered");
    expect(h).toMatchObject({
      valid: true,
      data: { email_id: id, recipient: "user@example.test" },
    });
    expect(mailFromOf()).toMatch(/^MAIL FROM:<b-[a-z2-7]{40,}@bounce\.acme\.test>/);
    expect(lastMessage()).toMatch(/X-Bunzzle-Ref: [a-z2-7]+/);
    expect(lastMessage()).toContain("Feedback-ID: transactional:acme.test:bunzzle");
    expect(lastMessage()).not.toContain("List-Unsubscribe");
  });

  test("an asynchronous bounce: webhook within seconds, recipient bounced and suppressed", async () => {
    const id = await send({ to: ["gone@example.test"] });
    await hook("email.delivered", "gone@example.test");
    const returnPath = /<(b-[^>]+)>/.exec(mailFromOf())?.[1] as string;
    const ref = /X-Bunzzle-Ref: ([a-z2-7]+)/.exec(lastMessage())?.[1];
    const dsn = `From: MAILER-DAEMON@mx.example.test
Subject: Undelivered Mail Returned to Sender
Content-Type: multipart/report; report-type=delivery-status; boundary="b1"

--b1
Content-Type: text/plain

Sorry.

--b1
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.test

Final-Recipient: rfc822; gone@example.test
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 5.1.1 User unknown

--b1
Content-Type: text/rfc822-headers

X-Bunzzle-Ref: ${ref}

--b1--
`;
    const sentAt = Date.now();
    const talk = await deliverMail(served.inboundPort as number, returnPath, dsn);
    expect(talk.replies[3]).toStartWith("250");
    expect(talk.replies[5]).toStartWith("250 2.0.0");
    const h = await hook("email.bounced", "gone@example.test");
    expect(h?.valid).toBe(true);
    expect(h?.data["bounce"]).toMatchObject({ class: "user-unknown", async: true });
    expect((h?.at ?? 0) - sentAt).toBeLessThan(3_000);
    const view = (await (await api(`/emails/${id}`)).json()) as {
      recipients: { email: string; status: string }[];
    };
    expect(view.recipients[0]?.status).toBe("bounced");
    const list = (await (await api("/suppressions")).json()) as {
      data: { email: string; reason: string; scope: string }[];
    };
    expect(list.data).toContainEqual(
      expect.objectContaining({ email: "gone@example.test", reason: "hard-bounce", scope: "all" }),
    );
    const again = await send({ to: ["gone@example.test"] });
    const s = await hook("email.suppressed", "gone@example.test");
    expect(s?.data["email_id"]).toBe(again);
  });

  test("a forged bounce is refused at RCPT and changes nothing", async () => {
    const fake = await smtpTalk(served.inboundPort as number, [
      "EHLO x",
      "MAIL FROM:<>",
      `RCPT TO:<b-${"a".repeat(44)}@bounce.acme.test>`,
      "RCPT TO:<postmaster@acme.test>",
      "QUIT",
    ]);
    expect(fake.replies[3]).toStartWith("550");
    expect(fake.replies[4]).toStartWith("550");
  });

  test("an out-of-office reply to the return path is ignored", async () => {
    await send({ to: ["away@example.test"] });
    await hook("email.delivered", "away@example.test");
    const returnPath = /<(b-[^>]+)>/.exec(mailFromOf())?.[1] as string;
    const talk = await deliverMail(
      served.inboundPort as number,
      returnPath,
      "From: away@example.test\nSubject: Automatic reply: Hi\nAuto-Submitted: auto-replied\n\nOut until Monday.\n",
    );
    expect(talk.replies[5]).toStartWith("250");
    await Bun.sleep(500);
    expect(
      hooks.some((h) => h.type === "email.bounced" && h.data["recipient"] === "away@example.test"),
    ).toBe(false);
  });
});

describe("one-click unsubscribe and complaints (bulk lane)", () => {
  test("bulk mail carries one-click unsubscribe; clicking it stops bulk, password resets still go out", async () => {
    await send({ to: ["reader@example.test"], lane: "bulk", subject: "Weekly news" });
    await hook("email.delivered", "reader@example.test");
    const msg = lastMessage();
    expect(msg).toContain("List-Unsubscribe-Post: List-Unsubscribe=One-Click");
    const link = /List-Unsubscribe: <(http:[^>]+)>, <mailto:u-[a-z2-7]+@bounce\.acme\.test>/.exec(
      msg.replace(/\r\n[ \t]+/g, " "),
    )?.[1] as string;
    expect(link).toContain(`127.0.0.1:${apiPort}/u/`);
    expect(msg).toMatch(/h=[^;]*list-unsubscribe:list-unsubscribe-post/i);

    const page = await fetch(link);
    expect(await page.text()).toContain('<form method="post">');
    const click = await fetch(link, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "List-Unsubscribe=One-Click",
    });
    expect(click.status).toBe(200);
    expect((await hook("email.unsubscribed", "reader@example.test"))?.valid).toBe(true);

    const news = await send({ to: ["reader@example.test"], lane: "bulk", subject: "More news" });
    const suppressed = await hook("email.suppressed", "reader@example.test");
    expect(suppressed?.data["email_id"]).toBe(news);
    const before = hooks.filter(
      (h) => h.type === "email.delivered" && h.data["recipient"] === "reader@example.test",
    ).length;
    await send({ to: ["reader@example.test"], subject: "Reset your password" });
    const after = await until(
      () =>
        hooks.filter(
          (h) => h.type === "email.delivered" && h.data["recipient"] === "reader@example.test",
        ).length,
      (n) => n > before,
    );
    expect(after).toBe(before + 1);
    expect((await fetch(`${served.url}/u/${"a".repeat(44)}`, { method: "POST" })).status).toBe(404);
  });

  test("an ARF complaint to the feedback address suppresses bulk mail for that reader", async () => {
    await send({ to: ["angry@example.test"], lane: "bulk", subject: "Promo" });
    await hook("email.delivered", "angry@example.test");
    const ref = /X-Bunzzle-Ref: ([a-z2-7]+)/.exec(lastMessage())?.[1];
    const arf = `From: feedback@provider.example.test
Subject: complaint
Content-Type: multipart/report; report-type=feedback-report; boundary="p"

--p
Content-Type: text/plain

Abuse report.

--p
Content-Type: message/feedback-report

Feedback-Type: abuse
Version: 1

--p
Content-Type: message/rfc822

X-Bunzzle-Ref: ${ref}
From: hello@acme.test
To: angry@example.test
Subject: Promo

hi
--p--
`;
    const talk = await deliverMail(served.inboundPort as number, "fbl@bounce.acme.test", arf);
    expect(talk.replies[5]).toStartWith("250");
    expect((await hook("email.complained", "angry@example.test"))?.valid).toBe(true);
    const list = (await (await api("/suppressions")).json()) as {
      data: { email: string; reason: string; scope: string }[];
    };
    expect(list.data).toContainEqual(
      expect.objectContaining({ email: "angry@example.test", reason: "complaint", scope: "bulk" }),
    );
  });

  test("every webhook was correctly signed", () => {
    expect(hooks.length).toBeGreaterThan(5);
    expect(hooks.every((h) => h.valid)).toBe(true);
  });

  test("each delivery lists its attempts; a resend arrives again with the same webhook-id", async () => {
    type Delivery = {
      id: string;
      state: string;
      attempts: { status: number | null; duration_ms: number }[];
    };
    const list = async (query = "") =>
      (
        (await (await api(`/webhooks/${hookId}/deliveries?limit=100${query}`)).json()) as {
          data: Delivery[];
        }
      ).data;
    const all = await list();
    expect(all.length).toBe(hooks.length);
    const done = all.find((d) => d.state === "done") as Delivery;
    expect(done.attempts).toEqual([expect.objectContaining({ status: 200 })]);
    expect(done.attempts[0]?.duration_ms).toBeGreaterThanOrEqual(0);
    expect(await list("&failed=true")).toEqual([]);
    expect((await list(`&limit=1&before=${all[0]?.id}`))[0]?.id).toBe(all[1]?.id);

    const msgId = `msg_${done.id}`;
    const before = hooks.filter((h) => h.msgId === msgId).length;
    const r = await api(`/webhooks/${hookId}/deliveries/${done.id}/resend`, { method: "POST" });
    expect(await r.json()).toEqual({ resent: 1 });
    await until(
      () => hooks.filter((h) => h.msgId === msgId).length,
      (n) => n === before + 1,
    );
    await until(
      async () => (await list()).find((d) => d.id === done.id)?.attempts.length,
      (n) => n === 2,
    );

    const total = hooks.length;
    const range = await api(`/webhooks/${hookId}/resend`, {
      method: "POST",
      body: JSON.stringify({
        from: new Date(Date.now() - 3_600_000).toISOString(),
        to: new Date(Date.now() + 60_000).toISOString(),
      }),
    });
    const job = (await range.json()) as { id: string; state: string; resent: number };
    expect(job).toMatchObject({ state: "queued", resent: 0 });
    const busy = await api(`/webhooks/${hookId}/resend`, {
      method: "POST",
      body: JSON.stringify({ from: new Date(0).toISOString(), to: new Date().toISOString() }),
    });
    expect(busy.status).toBe(409);
    const finished = await until(
      async () =>
        (await (await api(`/webhooks/${hookId}/resends/${job.id}`)).json()) as {
          state: string;
          resent: number;
        },
      (r) => r.state === "done",
      20_000,
    );
    expect(finished.resent).toBe(all.length);
    await until(
      () => hooks.length,
      (n) => n >= total + all.length,
      20_000,
    );
    expect((await api(`/webhooks/${hookId}/deliveries?from=yesterday`)).status).toBe(422);
    expect((await api("/webhooks/nope/deliveries")).status).toBe(404);
  });
});

describe("DMARC aggregate reports", () => {
  const today = Math.floor(Date.now() / 86_400_000) * 86_400 - 86_400;
  const mail = (domain: string, id: string) =>
    reportMail(
      "application/zip",
      `mail.example!${domain}!${today}!${today + 86_399}.zip`,
      zip("report.xml", new TextEncoder().encode(reportXml(domain, today, id))),
    );

  test("a report to the domain's report address is stored and summarized", async () => {
    const talk = await deliverMail(
      served.inboundPort as number,
      "dmarc@bounce.acme.test",
      mail("acme.test", "r-1"),
    );
    expect(talk.replies[5]).toStartWith("250");
    const again = await deliverMail(
      served.inboundPort as number,
      "dmarc@bounce.acme.test",
      mail("acme.test", "r-1"),
    );
    expect(again.replies[5]).toStartWith("250");
    const r = (await (await api("/domains/acme.test/dmarc?days=7")).json()) as {
      data: { messages: number; dmarc_pass: number; sources: { source_ip: string }[] }[];
    };
    expect(r.data.length).toBe(1);
    expect(r.data[0]?.messages).toBe(45);
    expect(r.data[0]?.dmarc_pass).toBe(42);
    expect(r.data[0]?.sources.map((x) => x.source_ip)).toEqual(["203.0.113.5", "198.51.100.7"]);
    const shown = await cli("domains", "reports", "acme.test");
    expect(shown.stdout).toContain("[FAIL] 198.51.100.7");
  });

  test("a report about another domain, or to an unknown domain, is refused", async () => {
    const other = await deliverMail(
      served.inboundPort as number,
      "dmarc@bounce.acme.test",
      mail("other.test", "r-2"),
    );
    expect(other.replies[5]).toStartWith("5");
    const unknown = await smtpTalk(served.inboundPort as number, [
      "EHLO reporter.example.test",
      "MAIL FROM:<noreply@mail.example>",
      "RCPT TO:<dmarc@bounce.nobody.test>",
      "QUIT",
    ]);
    expect(unknown.replies[3]).toStartWith("5");
    expect((await api("/domains/acme.test/dmarc?days=500")).status).toBe(422);
  });
});
