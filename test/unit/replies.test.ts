import { describe, expect, test } from "bun:test";
import { classify, type ReplyInput, retryHint } from "../../src/replies/classify.ts";
import type { Phase } from "../../src/smtp/session.ts";

function reply(phase: Phase, line: string, provider: string | null = null): ReplyInput {
  const m = /^(\d{3})[ -](?:([245]\.\d{1,3}\.\d{1,3}) )?/.exec(line);
  return {
    phase,
    code: m ? Number(m[1]) : null,
    enhanced: m?.[2] ?? null,
    text: line,
    provider,
  };
}

const cases: [Phase, string, string | null, string, string, string, boolean][] = [
  ["dot", "250 2.0.0 Ok: queued as 12345", null, "accepted", "none", "done", false],
  [
    "rcpt",
    "550 5.1.1 <nobody@example.test>: Recipient address rejected: User unknown in virtual mailbox table",
    null,
    "user-unknown",
    "recipient",
    "fail-recipient",
    true,
  ],
  [
    "rcpt",
    "550-5.1.1 The email account that you tried to reach does not exist. Please try double-checking the recipient's email address for typos",
    "google",
    "user-unknown",
    "recipient",
    "fail-recipient",
    true,
  ],
  [
    "rcpt",
    "550 5.2.1 The email account that you tried to reach is disabled.",
    "google",
    "mailbox-disabled",
    "recipient",
    "fail-recipient",
    true,
  ],
  [
    "rcpt",
    "552 5.2.2 The email account that you tried to reach is over quota",
    "google",
    "mailbox-full",
    "recipient",
    "retry",
    false,
  ],
  [
    "rcpt",
    "450 4.2.0 <grey@example.test>: Recipient address rejected: Greylisted, see https://postgrey.schweikert.ch/help/example.test.html",
    null,
    "greylisted",
    "infrastructure",
    "retry",
    false,
  ],
  [
    "rcpt",
    "554 5.7.1 Service unavailable; Client host [203.0.113.7] blocked using zen.spamhaus.org",
    null,
    "ip-blocked",
    "reputation",
    "pause-path",
    false,
  ],
  ["greeting", "554 5.7.1 Go away", null, "refused-at-greeting", "reputation", "pause-path", false],
  [
    "greeting",
    "421 4.7.0 Too many connections from your IP, slow down",
    null,
    "rate-limited",
    "rate",
    "slow-path",
    false,
  ],
  [
    "dot",
    "421-4.7.28 Our system has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited.",
    "google",
    "rate-limited",
    "rate",
    "slow-path",
    false,
  ],
  [
    "dot",
    "550-5.7.1 Our system has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been blocked.",
    "google",
    "ip-blocked",
    "reputation",
    "pause-path",
    false,
  ],
  [
    "dot",
    "550-5.7.1 Our system has detected that this message is likely unsolicited mail.",
    "google",
    "spam",
    "message",
    "fail-message",
    false,
  ],
  [
    "dot",
    "550-5.7.26 Unauthenticated email from bunzzle.com is not accepted due to domain's DMARC policy.",
    "google",
    "auth",
    "sender",
    "fail-message",
    false,
  ],
  [
    "dot",
    "550-5.7.25 The IP address sending this message does not have a PTR record setup",
    "google",
    "no-ptr",
    "reputation",
    "pause-path",
    false,
  ],
  [
    "rcpt",
    "550 5.4.1 Recipient address rejected: Access denied. AS(201806281)",
    "microsoft",
    "user-unknown",
    "recipient",
    "fail-recipient",
    true,
  ],
  [
    "rcpt",
    "550 5.5.0 Requested action not taken: mailbox unavailable",
    "microsoft",
    "user-unknown",
    "recipient",
    "fail-recipient",
    true,
  ],
  [
    "rcpt",
    "550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3150).",
    "microsoft",
    "ip-blocked",
    "reputation",
    "pause-path",
    false,
  ],
  [
    "rcpt",
    "451 4.7.650 The mail server [203.0.113.7] has been temporarily rate limited due to IP reputation.",
    "microsoft",
    "rate-limited",
    "rate",
    "slow-path",
    false,
  ],
  [
    "mail",
    "421 4.7.0 [TSS04] Messages from 203.0.113.7 temporarily deferred due to unexpected volume or user complaints",
    "yahoo",
    "rate-limited",
    "rate",
    "slow-path",
    false,
  ],
  [
    "rcpt",
    "554 5.7.1 <x@other.test>: Relay access denied",
    null,
    "relay-denied",
    "recipient",
    "fail-recipient",
    false,
  ],
  [
    "mail",
    "553 5.1.8 <a@bunzzle.com>: Sender address rejected: Domain not found",
    null,
    "bad-sender-domain",
    "sender",
    "fail-message",
    false,
  ],
  ["mail", "550 5.7.1 Sender rejected", null, "policy", "message", "fail-message", false],
  ["dot", "552 5.3.4 Message too big", null, "too-big", "message", "fail-message", false],
  ["rcpt", "550 Rejected", null, "rejected", "recipient", "fail-recipient", false],
  ["rcpt", "451 4.3.0 Local error", null, "mail-system", "infrastructure", "retry", false],
  ["ehlo", "550 5.1.1 weird", null, "unavailable", "infrastructure", "retry", false],
  [
    "connect",
    "connect to 192.0.2.1:25: refused",
    null,
    "unavailable",
    "infrastructure",
    "retry",
    false,
  ],
];

describe("classify", () => {
  test.each(cases)("%s %s", (phase, line, provider, cls, scope, action, suppress) => {
    expect(classify(reply(phase, line, provider))).toMatchObject({
      class: cls,
      scope,
      action,
      suppress,
    });
  });

  test("local failures carry enhanced codes and are classified like replies", () => {
    const local = (enhanced: string, phase: Phase = "starttls") =>
      classify({ phase, code: null, enhanced, text: "local" });
    expect(local("4.7.5")).toMatchObject({ class: "tls", action: "retry" });
    expect(local("4.7.10")).toMatchObject({ class: "tls-required", action: "retry" });
    expect(local("5.7.30", "mail")).toMatchObject({
      class: "requiretls-unsupported",
      action: "fail-message",
      suppress: false,
    });
    expect(local("4.4.1", "connect")).toMatchObject({ class: "no-answer", action: "retry" });
    expect(local("5.3.4", "mail")).toMatchObject({ class: "too-big", action: "fail-message" });
    expect(local("5.1.10", "dns")).toMatchObject({ class: "null-mx", suppress: true });
    expect(local("4.4.3", "dns")).toMatchObject({ class: "dns", action: "retry" });
    expect(local("5.4.4", "dns")).toMatchObject({
      class: "unroutable",
      action: "fail-recipient",
      suppress: false,
    });
  });

  test("golden rule: only permanent recipient errors suppress", () => {
    const all = cases.map(([p, l, prov]) => classify(reply(p, l, prov)));
    for (const c of all.filter((c) => c.suppress)) {
      expect(c).toMatchObject({ scope: "recipient", permanent: true, action: "fail-recipient" });
    }
    const blocked = classify(reply("rcpt", "550 5.1.1 blocked using zen.spamhaus.org"));
    expect(blocked).toMatchObject({ scope: "reputation", suppress: false });
    const greeting = classify(reply("greeting", "550 5.1.1 user unknown"));
    expect(greeting.suppress).toBe(false);
  });

  test("a user-unknown reply after DATA for several recipients never suppresses", () => {
    const line = "550 5.1.1 User unknown";
    expect(classify({ ...reply("dot", line), shared: true }).suppress).toBe(false);
    expect(classify(reply("dot", line)).suppress).toBe(true);
  });

  test("reputation and sender problems alert the operator", () => {
    expect(classify(reply("rcpt", "554 5.7.1 blocked using zen.spamhaus.org")).alert).toBe(true);
    expect(classify(reply("dot", "550 5.7.26 DMARC policy")).alert).toBe(true);
    expect(classify(reply("rcpt", "550 5.1.1 User unknown")).alert).toBe(false);
  });
});

describe("retry hints", () => {
  test("reads the server's suggested wait", () => {
    expect(retryHint("451 4.7.1 Please try again in 5 minutes")).toBe(300_000);
    expect(retryHint("421 Retry after 90 seconds")).toBe(90_000);
    expect(retryHint("450 wait 2 hours")).toBe(7_200_000);
    expect(retryHint("421 4.7.0 Try again later")).toBeNull();
  });

  test("greylisting defaults to one minute", () => {
    const c = classify(reply("rcpt", "450 4.2.0 Greylisted, try again later"));
    expect(c.hintMs).toBe(60_000);
  });
});
