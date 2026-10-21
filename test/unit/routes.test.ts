import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import { buildPayload } from "../../src/inbound/payload.ts";
import {
  claimRouted,
  createRoute,
  deleteRoute,
  findRoute,
  outcomeOf,
  pruneRouted,
  queueRouted,
  retryAfterMs,
  retryFailed,
  settleRouted,
  splitRouteAddress,
} from "../../src/inbound/routes.ts";
import { toBinary } from "../../src/mime/parse.ts";

const sealed = { epoch: 1, wrapped: new Uint8Array([1]), body: new Uint8Array([2]) };

function setup() {
  const db = openDatabase({ path: ":memory:" });
  const exact = createRoute(db, "support@acme.test", "https://a.test/x", "parsed", 1);
  const any = createRoute(db, "*@acme.test", "https://a.test/any", "raw", 1);
  return { db, exact: exact?.id as string, any: any?.id as string };
}

describe("route addresses", () => {
  test("exact address first, then without +tag, then the domain wildcard", () => {
    const { db, exact, any } = setup();
    expect(findRoute(db, "Support@ACME.test")?.id).toBe(exact);
    expect(findRoute(db, "support+billing@acme.test")?.id).toBe(exact);
    expect(findRoute(db, "sales@acme.test")?.id).toBe(any);
    expect(findRoute(db, "support@other.test")).toBeNull();
    expect(findRoute(db, "*@acme.test")).toBeNull();
    createRoute(db, "support+vip@acme.test", "https://a.test/vip", "parsed", 1);
    expect(findRoute(db, "support+vip@acme.test")?.address).toBe("support+vip@acme.test");
  });

  test("one active route per address; a removed route frees it and stops matching", () => {
    const { db, exact } = setup();
    expect(createRoute(db, "support@acme.test", "https://b.test", "raw", 2)).toBeNull();
    expect(deleteRoute(db, exact, 3)).toBe(true);
    expect(deleteRoute(db, exact, 3)).toBe(false);
    expect(findRoute(db, "support@acme.test")?.address).toBe("*@acme.test");
    expect(createRoute(db, "support@acme.test", "https://b.test", "raw", 4)).not.toBeNull();
  });

  test("only plain local parts or * are routes", () => {
    expect(splitRouteAddress(" Help@Acme.Test ")).toEqual({ local: "help", domain: "acme.test" });
    expect(splitRouteAddress("*@acme.test")).toEqual({ local: "*", domain: "acme.test" });
    expect(splitRouteAddress("a b@acme.test")).toBeNull();
    expect(splitRouteAddress("a..b@acme.test")).toBeNull();
    expect(splitRouteAddress("@acme.test")).toBeNull();
    expect(splitRouteAddress(`${"a".repeat(65)}@acme.test`)).toBeNull();
  });
});

describe("route deliveries", () => {
  test("Retry-After in seconds or as a date, kept between 1 s and 6 h", () => {
    expect(retryAfterMs("120", 0)).toBe(120_000);
    expect(retryAfterMs("0", 0)).toBe(1_000);
    expect(retryAfterMs("999999", 0)).toBe(6 * 3_600_000);
    const now = Date.parse("2026-10-20T10:00:00Z");
    expect(retryAfterMs("Tue, 20 Oct 2026 10:05:00 GMT", now)).toBe(300_000);
    expect(retryAfterMs("soon", now)).toBeNull();
    expect(retryAfterMs(undefined, now)).toBeNull();
  });

  test("2xx is done; 408, 429, 5xx and network errors retry; other 4xx fail", () => {
    expect(outcomeOf({ ok: true, status: 204 }, 0)).toEqual({ ok: true });
    for (const status of [408, 429, 500, 503]) {
      expect(outcomeOf({ ok: true, status }, 0)).toMatchObject({ ok: false, retry: true });
    }
    expect(outcomeOf({ ok: true, status: 429, retryAfter: "30" }, 0)).toMatchObject({
      retryAfterMs: 30_000,
    });
    expect(outcomeOf({ ok: true, status: 400, retryAfter: "30" }, 0)).toEqual({
      ok: false,
      error: "endpoint answered 400",
      retry: false,
      retryAfterMs: null,
    });
    expect(outcomeOf({ ok: false, error: "connection refused" }, 0)).toMatchObject({
      retry: true,
    });
  });

  test("success drops the sealed payload; Retry-After sets the next try; failures keep it for a retry", () => {
    const { db, exact } = setup();
    queueRouted(db, exact, "d1", sealed, 10, 1_000);
    queueRouted(db, exact, "d2", sealed, 10, 1_000);
    const due = claimRouted(db, 1_000, 10);
    expect(due.map((d) => d.id)).toEqual(["d1", "d2"]);
    expect(due[0]?.url).toBe("https://a.test/x");
    expect(claimRouted(db, 1_000, 10)).toEqual([]);

    expect(settleRouted(db, due[0] as never, { ok: true }, 2_000)).toBe("done");
    const body = db.query<{ body: Uint8Array | null }, [string]>(
      "SELECT body FROM route_deliveries WHERE id = ?",
    );
    expect(body.get("d1")?.body).toBeNull();

    const later = { ok: false as const, error: "429", retry: true, retryAfterMs: 60_000 };
    expect(settleRouted(db, due[1] as never, later, 2_000)).toBe("retry");
    expect(claimRouted(db, 61_999, 10)).toEqual([]);
    const again = claimRouted(db, 62_000, 10);
    expect(again.map((d) => [d.id, d.attempt])).toEqual([["d2", 2]]);

    const refused = { ok: false as const, error: "400", retry: false, retryAfterMs: null };
    expect(settleRouted(db, again[0] as never, refused, 63_000)).toBe("failed");
    expect(body.get("d2")?.body).not.toBeNull();
    expect(retryFailed(db, exact, 64_000)).toBe(1);
    expect(claimRouted(db, 64_000, 10).map((d) => [d.id, d.attempt])).toEqual([["d2", 1]]);
  });

  test("gives up after the last retry; old rows go with retention; removed routes are not sent", () => {
    const { db, exact, any } = setup();
    queueRouted(db, exact, "d1", sealed, 10, 0);
    const down = { ok: false as const, error: "500", retry: true, retryAfterMs: null };
    let result = "";
    for (let i = 0; i < 20 && result !== "failed"; i++) {
      const [d] = claimRouted(db, Number.MAX_SAFE_INTEGER, 1);
      result = settleRouted(db, d as never, down, i);
    }
    expect(result).toBe("failed");
    expect(
      db.query<{ attempt: number }, []>("SELECT attempt FROM route_deliveries").get()?.attempt,
    ).toBe(8);
    pruneRouted(db, 100);
    expect(db.query("SELECT 1 FROM route_deliveries").all()).toEqual([]);

    queueRouted(db, any, "d3", sealed, 10, 0);
    deleteRoute(db, any, 1);
    expect(claimRouted(db, 10, 10)).toEqual([]);
  });
});

const envelope = {
  id: "0199f3a4-7c1e-7d55-9a21-3b6f0c9e4d12",
  receivedAt: Date.parse("2026-10-20T10:00:00Z"),
  mailFrom: "ayse@example.org",
  rcptTo: ["support@acme.test"],
  remoteIp: "192.0.2.7",
  tls: true,
  auth: null,
};

const message = (lines: string[]) => toBinary(new TextEncoder().encode(lines.join("\r\n")));

describe("route payload", () => {
  const raw = message([
    "From: Ayşe <ayse@example.org>",
    "To: support@acme.test",
    "Subject: =?UTF-8?B?w4dvayBnw7x6ZWw=?= ve şimdi",
    "Message-ID: <m1@example.org>",
    "In-Reply-To: <m0@acme.test>",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b"',
    "",
    "--b",
    'Content-Type: multipart/alternative; boundary="c"',
    "",
    "--c",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Merhaba dünya",
    "--c",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<p>Merhaba dünya</p>",
    "--c--",
    "--b",
    "Content-Type: image/png",
    "Content-ID: <logo@x>",
    "Content-Transfer-Encoding: base64",
    "",
    "iVBORw0KGgo=",
    "--b",
    'Content-Type: application/pdf; name="fatura.pdf"',
    'Content-Disposition: attachment; filename="fatura.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    "JVBERg==",
    "--b",
    "Content-Type: message/rfc822",
    "",
    "Subject: inner",
    "",
    "inner body",
    "--b--",
    "",
  ]);

  test("parsed: envelope, decoded headers, text and html, every attachment", () => {
    const p = JSON.parse(buildPayload(raw, envelope, "parsed"));
    expect(p).toMatchObject({
      id: envelope.id,
      received_at: "2026-10-20T10:00:00.000Z",
      mail_from: "ayse@example.org",
      rcpt_to: ["support@acme.test"],
      remote_ip: "192.0.2.7",
      tls: true,
      from: "Ayşe <ayse@example.org>",
      to: "support@acme.test",
      subject: "Çok güzel ve şimdi",
      message_id: "<m1@example.org>",
      in_reply_to: "<m0@acme.test>",
      cc: null,
      automated: false,
      text: "Merhaba dünya",
      html: "<p>Merhaba dünya</p>",
    });
    expect(p.headers).toContainEqual(["subject", "Çok güzel ve şimdi"]);
    expect(p.attachments).toEqual([
      {
        filename: null,
        content_type: "image/png",
        content_id: "logo@x",
        size: 8,
        content: "iVBORw0KGgo=",
      },
      {
        filename: "fatura.pdf",
        content_type: "application/pdf",
        content_id: null,
        size: 4,
        content: "JVBERg==",
      },
      {
        filename: "message.eml",
        content_type: "message/rfc822",
        content_id: null,
        size: 28,
        content: new TextEncoder().encode("Subject: inner\r\n\r\ninner body").toBase64(),
      },
    ]);
  });

  test("raw: the message bytes unchanged", () => {
    const p = JSON.parse(buildPayload(raw, envelope, "raw"));
    expect(p.text).toBeUndefined();
    expect(Uint8Array.fromBase64(p.raw)).toEqual(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
  });

  test("automated mail is marked", () => {
    const plain = (h: string) =>
      JSON.parse(buildPayload(message([h, "Subject: x", "", "x"]), envelope, "parsed")).automated;
    expect(plain("Auto-Submitted: auto-replied")).toBe(true);
    expect(plain("Auto-Submitted: no")).toBe(false);
    expect(plain("Precedence: bulk")).toBe(true);
    expect(plain("List-Id: <news.example.org>")).toBe(true);
    expect(
      JSON.parse(
        buildPayload(message(["Subject: x", "", "x"]), { ...envelope, mailFrom: "" }, "parsed"),
      ).automated,
    ).toBe(true);
  });
});
