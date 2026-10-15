import { describe, expect, test } from "bun:test";
import { classifyReport, LIMITS, ParseError, parseMessage } from "../../src/inbound/parse.ts";

const REF = "bae2kmxj4wl5wq3ru6gkfyzcjauwrwfqgbydiyc7zt";
const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");

const postfixDsn = crlf(`Return-Path: <>
From: MAILER-DAEMON@mx.example.test (Mail Delivery System)
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="ABC123/mx.example.test"

This is a MIME-encapsulated message.

--ABC123/mx.example.test
Content-Description: Notification
Content-Type: text/plain; charset=us-ascii

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients.

--ABC123/mx.example.test
Content-Description: Delivery report
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.test
Arrival-Date: Thu, 15 Oct 2026 10:00:00 +0000

Final-Recipient: rfc822; Nobody@Example.test
Original-Recipient: rfc822;nobody@example.test
Action: failed
Status: 5.1.1
Remote-MTA: dns; inner.example.test
Diagnostic-Code: smtp; 550 5.1.1 <nobody@example.test>: Recipient address
    rejected: User unknown in virtual mailbox table

--ABC123/mx.example.test
Content-Description: Undelivered Message Headers
Content-Type: text/rfc822-headers

From: Acme <hello@acme.test>
To: nobody@example.test
Subject: Your sign-in link
X-Bunzzle-Ref: ${REF}

--ABC123/mx.example.test--
`);

const arf = crlf(`From: staff@hotmail.test
Subject: complaint about message from 203.0.113.7
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="part1"

--part1
Content-Type: text/plain

This is an email abuse report.

--part1
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: SomeGenerator/1.0
Version: 1
Original-Rcpt-To: <Reader@Example.test>

--part1
Content-Type: message/rfc822

From: Acme <hello@acme.test>
To: reader@example.test
Subject: Weekly news
X-Bunzzle-Ref: ${REF}
Content-Type: text/plain

Hello
--part1--
`);

describe("classifyReport", () => {
  test("a Postfix DSN: per-recipient status, diagnostic folded lines, ref from the original headers", () => {
    const r = classifyReport(postfixDsn);
    expect(r).toEqual({
      kind: "dsn",
      ref: REF,
      recipients: [
        {
          address: "nobody@example.test",
          action: "failed",
          status: "5.1.1",
          diagnostic:
            "550 5.1.1 <nobody@example.test>: Recipient address rejected: User unknown in virtual mailbox table",
          remoteMta: "inner.example.test",
        },
      ],
    });
  });

  test("an ARF complaint with the original message attached", () => {
    expect(classifyReport(arf)).toEqual({
      kind: "arf",
      ref: REF,
      feedbackType: "abuse",
      originalRcpt: "reader@example.test",
    });
  });

  test("out-of-office replies are recognised, not counted as bounces", () => {
    const ooo = crlf(`From: reader@example.test
Subject: Automatic reply: Your sign-in link
Auto-Submitted: auto-replied

I am out of the office until Monday.
`);
    expect(classifyReport(ooo).kind).toBe("auto-reply");
    const vacation = crlf("From: x@example.test\nSubject: Out of Office\n\nback soon\n");
    expect(classifyReport(vacation).kind).toBe("auto-reply");
  });

  test("a non-standard bounce: code and address pulled from the text", () => {
    const qmail = crlf(`From: MAILER-DAEMON@old.example.test
Subject: failure notice

Hi. This is the qmail-send program at old.example.test.
I'm afraid I wasn't able to deliver your message to the following addresses.

<gone@example.test>:
203.0.113.9 does not like recipient.
Remote host said: 550 5.1.1 Mailbox does not exist
Giving up on 203.0.113.9.

--- Below this line is a copy of the message.

X-Bunzzle-Ref: ${REF}
From: hello@acme.test
`);
    const r = classifyReport(qmail);
    expect(r).toMatchObject({ kind: "bounce", ref: REF, status: "5.1.1" });
    if (r.kind !== "bounce") throw new Error("expected bounce");
    expect(r.diagnostic).toContain("550 5.1.1 Mailbox does not exist");
    expect(r.addresses).toContain("gone@example.test");
  });

  test("anything else is unknown", () => {
    expect(classifyReport(crlf("From: a@b.test\nSubject: hello\n\nhi\n")).kind).toBe("unknown");
  });
});

describe("limits on untrusted input", () => {
  test("deep MIME nesting and header floods are refused", () => {
    let nested = "Content-Type: text/plain\r\n\r\nx";
    for (let i = 0; i < 10; i++) {
      nested = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n${nested}\r\n--b${i}--\r\n`;
    }
    expect(() => parseMessage(nested)).toThrow(ParseError);
    const flood = `${"X-A: 1\r\n".repeat(LIMITS.maxHeaders + 1)}\r\nbody`;
    expect(() => parseMessage(flood)).toThrow("too many headers");
  });

  test("base64 and quoted-printable parts are decoded", () => {
    const m = crlf(`Content-Type: multipart/mixed; boundary="x"

--x
Content-Type: text/plain
Content-Transfer-Encoding: base64

${btoa("Remote host said: 550 5.1.1 no")}
--x
Content-Type: text/plain
Content-Transfer-Encoding: quoted-printable

caf=C3=A9 =
ok
--x--
`);
    const p = parseMessage(m);
    expect(p.parts.map((x) => x.body.trim())).toEqual([
      "Remote host said: 550 5.1.1 no",
      "café ok",
    ]);
  });
});
