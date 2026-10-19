import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import type { RpcClient } from "../../src/ipc/rpc.ts";
import { parseMime, walkParts } from "../../src/mime/parse.ts";
import { sendTlsReports } from "../../src/tlsrpt/job.ts";
import {
  Aggregator,
  type AttemptSession,
  parseTlsRpt,
  reportMail,
  sessionResult,
} from "../../src/tlsrpt/report.ts";

const session = (over: Partial<AttemptSession>): AttemptSession => ({
  host: "mx1.example.test",
  address: "192.0.2.10",
  phase: "done",
  error: null,
  tls: { status: "verified", error: null },
  ...over,
});
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 9, 19, 3, 0, 0);
const silent = { debug() {}, info() {}, warn() {}, error() {}, child: () => silent } as never;

describe("TLS reports", () => {
  test("sessions map to RFC 8460 result types", () => {
    expect(sessionResult(session({}))).toBe("success");
    const unverified = (error: string) => session({ tls: { status: "unverified", error } });
    expect(sessionResult(unverified("CERT_HAS_EXPIRED"))).toBe("certificate-expired");
    expect(sessionResult(unverified("ERR_TLS_CERT_ALTNAME_INVALID"))).toBe(
      "certificate-host-mismatch",
    );
    expect(sessionResult(unverified("DEPTH_ZERO_SELF_SIGNED_CERT"))).toBe(
      "certificate-not-trusted",
    );
    expect(sessionResult(unverified("SOMETHING_ELSE"))).toBe("validation-failure");
    expect(sessionResult(session({ tls: { status: "none", error: null } }))).toBe(
      "starttls-not-supported",
    );
    expect(
      sessionResult(
        session({ phase: "connect", error: "refused", tls: { status: "none", error: null } }),
      ),
    ).toBeNull();
    expect(
      sessionResult(
        session({
          phase: "starttls",
          error: "TLS handshake failed",
          tls: { status: "none", error: null },
        }),
      ),
    ).toBe("validation-failure");
  });

  test("aggregate per domain and policy, with failure details", () => {
    const agg = new Aggregator();
    const sts = { mode: "enforce", id: "20261001", mx: ["*.example.test"], maxAge: 86400 };
    agg.add({ target: "example.test", source: "203.0.113.5", sts, sessions: [session({})] });
    agg.add({
      target: "example.test",
      source: "203.0.113.5",
      sts,
      sessions: [session({ tls: { status: "unverified", error: "CERT_HAS_EXPIRED" } })],
    });
    agg.add({
      target: "example.test",
      source: "203.0.113.5",
      sts,
      sessions: [session({ tls: { status: "unverified", error: "CERT_HAS_EXPIRED" } })],
    });
    agg.add({ target: "plain.test", source: "default", sts: null, sessions: [session({})] });
    const r = agg.report("example.test", {
      org: "out.bunzzle.test",
      contact: "mailto:ops@acme.test",
      start: Date.UTC(2026, 9, 18),
      end: Date.UTC(2026, 9, 18, 23, 59, 59),
      id: "2026-10-18.example.test@out.bunzzle.test",
    });
    expect(r).toEqual({
      "organization-name": "out.bunzzle.test",
      "date-range": {
        "start-datetime": "2026-10-18T00:00:00Z",
        "end-datetime": "2026-10-18T23:59:59Z",
      },
      "contact-info": "mailto:ops@acme.test",
      "report-id": "2026-10-18.example.test@out.bunzzle.test",
      policies: [
        {
          policy: {
            "policy-type": "sts",
            "policy-string": [
              "version: STSv1",
              "mode: enforce",
              "mx: *.example.test",
              "max_age: 86400",
            ],
            "policy-domain": "example.test",
            "mx-host": ["*.example.test"],
          },
          summary: { "total-successful-session-count": 1, "total-failure-session-count": 2 },
          "failure-details": [
            {
              "result-type": "certificate-expired",
              "sending-mta-ip": "203.0.113.5",
              "receiving-mx-hostname": "mx1.example.test",
              "receiving-ip": "192.0.2.10",
              "failed-session-count": 2,
            },
          ],
        },
      ],
    });
    expect(
      agg.report("plain.test", { org: "o", contact: "c", start: 0, end: 1, id: "x" })?.policies[0]
        ?.policy,
    ).toEqual({
      "policy-type": "no-policy-found",
      "policy-domain": "plain.test",
    });
  });

  test("the reporting record", () => {
    expect(
      parseTlsRpt(["v=TLSRPTv1; rua=mailto:tls@example.test,https://r.example.test/tls"]),
    ).toEqual({
      mailto: ["tls@example.test"],
      https: ["https://r.example.test/tls"],
    });
    expect(parseTlsRpt(["v=TLSRPTv1;rua=http://insecure.test"])).toBeNull();
    expect(parseTlsRpt(["v=spf1 -all"])).toBeNull();
    expect(
      parseTlsRpt(["v=TLSRPTv1; rua=mailto:a@b.test", "v=TLSRPTv1; rua=mailto:c@d.test"]),
    ).toBeNull();
  });

  test("the report email carries the gzipped JSON", () => {
    const agg = new Aggregator();
    agg.add({ target: "example.test", source: null, sts: null, sessions: [session({})] });
    const report = agg.report("example.test", {
      org: "o.test",
      contact: "c",
      start: 0,
      end: 1,
      id: "r1",
    });
    const raw = reportMail(report as never, "example.test", {
      from: "tlsrpt@acme.test",
      to: "tls@example.test",
      submitter: "o.test",
      messageId: "<m@acme.test>",
      date: "Mon, 19 Oct 2026 00:00:00 +0000",
    });
    const root = parseMime(raw);
    expect(root.type).toBe("multipart/report");
    expect(root.params.get("report-type")).toBe("tlsrpt");
    expect(root.headers.get("tls-report-domain")).toEqual(["example.test"]);
    const part = walkParts(root).find((p) => p.type === "application/tlsrpt+gzip");
    expect(part?.filename).toBe("o.test!example.test!0!0!r1.json.gz");
    expect(
      JSON.parse(
        new TextDecoder().decode(Bun.gunzipSync(part?.content as Uint8Array<ArrayBuffer>)),
      ),
    ).toEqual(report as object);
  });

  test("the daily job reports yesterday once, by HTTPS and by email", async () => {
    const db = openDatabase({ path: ":memory:" });
    db.run(
      "INSERT INTO messages (id, type, payload, metadata, created_at) VALUES ('m1', 'email', '{}', '{}', 0)",
    );
    const attempt = (target: string, at: number) =>
      db.run(
        "INSERT INTO events (message_id, kind, data, source, occurred_at) VALUES ('m1', 'attempt', ?, 'delivery', ?)",
        [JSON.stringify({ target, source: "203.0.113.5", sts: null, sessions: [session({})] }), at],
      );
    attempt("example.test", T0 - DAY);
    attempt("quiet.test", T0 - DAY);
    attempt("example.test", T0);
    const posts: { url: string; body: string }[] = [];
    const mails: string[] = [];
    const delivery = {
      async call(method: string, params: Record<string, unknown>) {
        if (method === "dns") {
          return {
            "TXT:_smtp._tls.example.test": [
              "v=TLSRPTv1; rua=https://r.example.test/tls,mailto:tls@example.test",
            ],
          };
        }
        posts.push(params as { url: string; body: string });
        return { ok: true, status: 200 };
      },
    } as unknown as RpcClient;
    const writer = { run: async <T>(fn: (d: typeof db) => T) => fn(db) } as never;
    const deps = {
      db,
      writer,
      log: silent,
      delivery,
      org: "out.bunzzle.test",
      contact: "mailto:ops@acme.test",
      from: "tlsrpt@acme.test",
      enqueue: async (_f: string, to: string) => {
        mails.push(to);
        return "id";
      },
      now: () => T0,
    };
    expect(await sendTlsReports(deps)).toEqual({ day: "2026-10-18", sent: 2 });
    expect(posts.map((p) => p.url)).toEqual(["https://r.example.test/tls"]);
    expect(
      JSON.parse(posts[0]?.body ?? "{}").policies[0].summary["total-successful-session-count"],
    ).toBe(1);
    expect(mails).toEqual(["tls@example.test"]);
    expect(await sendTlsReports(deps)).toBeNull();
  });
});
