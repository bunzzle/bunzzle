import { describe, expect, test } from "bun:test";
import {
  allows,
  createKey,
  hashToken,
  keyForHash,
  revokeKey,
  TOKEN,
} from "../../src/accounts/api-keys.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { evaluate, expectedRecords, getDomain, saveDomain } from "../../src/domains/domains.ts";
import {
  findIdempotent,
  IDEMPOTENCY_TTL_MS,
  pruneIdempotency,
  rememberIdempotent,
} from "../../src/emails/idempotency.ts";
import { ApiError } from "../../src/http/errors.ts";
import { prepareEmail, sendSchema } from "../../src/http/send.ts";

const T0 = 1_700_000_000_000;
const keys = [
  {
    selector: "s1r",
    algorithm: "rsa-sha256" as const,
    publicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
  },
  {
    selector: "s1e",
    algorithm: "ed25519-sha256" as const,
    publicKey: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
  },
];

describe("domain records", () => {
  const records = expectedRecords("acme.test", keys, "203.0.113.7");

  test("DKIM for both keys is required, SPF and DMARC are recommended", () => {
    expect(records.map((r) => [r.record, r.name, r.required])).toEqual([
      ["DKIM", "s1r._domainkey.acme.test", true],
      ["DKIM", "s1e._domainkey.acme.test", true],
      ["SPF", "acme.test", false],
      ["DMARC", "_dmarc.acme.test", false],
    ]);
    expect(records[2]?.value).toBe("v=spf1 ip4:203.0.113.7 ~all");
  });

  test("verified when both DKIM keys match, even split or reformatted by the DNS host", () => {
    const rsa = `v=DKIM1; k=rsa; p=${keys[0]?.publicKey}`;
    const r = evaluate(
      records,
      {
        "s1r._domainkey.acme.test": [rsa.replace("p=", "p= ").replace(/(.{20})/, "$1 ")],
        "s1e._domainkey.acme.test": [`v=DKIM1;k=ed25519;p=${keys[1]?.publicKey}`],
      },
      "203.0.113.7",
    );
    expect(r.status).toBe("verified");
    expect(r.records.map((x) => x.status)).toEqual(["verified", "verified", "missing", "missing"]);
  });

  test("a wrong key is a mismatch and the domain stays pending", () => {
    const r = evaluate(
      records,
      {
        "s1r._domainkey.acme.test": ["v=DKIM1; k=rsa; p=OTHER"],
        "s1e._domainkey.acme.test": [`v=DKIM1; k=ed25519; p=${keys[1]?.publicKey}`],
      },
      null,
    );
    expect(r.status).toBe("pending");
    expect(r.records[0]).toMatchObject({ status: "mismatch", found: "v=DKIM1; k=rsa; p=OTHER" });
  });

  test("SPF: must include our IP; two SPF records are an error; DMARC just needs to exist", () => {
    const base = {
      "s1r._domainkey.acme.test": [`p=${keys[0]?.publicKey}`],
      "s1e._domainkey.acme.test": [`p=${keys[1]?.publicKey}`],
    };
    const spf = (txt: string[]) =>
      evaluate(records, { ...base, "acme.test": txt }, "203.0.113.7").records[2]?.status;
    expect(spf(["v=spf1 include:_spf.google.com ip4:203.0.113.7 -all"])).toBe("verified");
    expect(spf(["v=spf1 include:_spf.google.com -all"])).toBe("mismatch");
    expect(spf(["v=spf1 ip4:203.0.113.7 -all", "v=spf1 a -all"])).toBe("mismatch");
    expect(spf(["google-site-verification=x"])).toBe("missing");
    const dmarc = evaluate(records, { ...base, "_dmarc.acme.test": ["v=DMARC1; p=reject"] }, null);
    expect(dmarc.records[3]?.status).toBe("verified");
  });
});

describe("API keys", () => {
  test("tokens look like bz_..., only the hash is stored, revoked keys stop matching", () => {
    const db = openDatabase({ path: ":memory:" });
    const { key, token } = createKey(
      db,
      { name: "app", scope: "send", domains: ["acme.test"] },
      T0,
    );
    expect(token).toMatch(TOKEN);
    const row = db.query<{ token_hash: string }, []>("SELECT token_hash FROM api_keys").get();
    expect(row?.token_hash).toBe(hashToken(token));
    expect(JSON.stringify(db.query("SELECT * FROM api_keys").all())).not.toContain(token);
    expect(keyForHash(db, hashToken(token))).toMatchObject({ id: key.id, domains: ["acme.test"] });
    expect(revokeKey(db, key.id, T0)).toBe(true);
    expect(keyForHash(db, hashToken(token))).toBeNull();
    expect(revokeKey(db, key.id, T0)).toBe(false);
  });

  test("scopes", () => {
    expect(allows("full", "send")).toBe(true);
    expect(allows("send", "send")).toBe(true);
    expect(allows("send", "read")).toBe(false);
    expect(allows("read", "full")).toBe(false);
  });
});

describe("idempotency records", () => {
  test("found within 24 hours, then forgotten", () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("INSERT INTO messages (id, type, payload, created_at) VALUES ('m', 'email', '{}', 0)");
    rememberIdempotent(db, "k", "order-1", "h1", "m", T0);
    expect(findIdempotent(db, "k", "order-1", T0 + 1)).toMatchObject({
      bodyHash: "h1",
      messageId: "m",
    });
    expect(findIdempotent(db, "other", "order-1", T0 + 1)).toBeNull();
    expect(findIdempotent(db, "k", "order-1", T0 + IDEMPOTENCY_TTL_MS)).toBeNull();
    expect(pruneIdempotency(db, T0 + IDEMPOTENCY_TTL_MS)).toBe(1);
  });
});

describe("send requests", () => {
  const prepare = (body: unknown) => prepareEmail(sendSchema.parse(body), new Date(T0));

  test("strings or arrays, recipients deduplicated, bcc never in the headers", () => {
    const e = prepare({
      from: "Acme <hello@acme.test>",
      to: "a@example.test",
      cc: ["b@example.test", "a@example.test"],
      bcc: "secret@example.test",
      subject: "Hi",
      text: "x",
    });
    expect(e.recipients).toEqual(["a@example.test", "b@example.test", "secret@example.test"]);
    expect(e.fromDomain).toBe("acme.test");
    expect(e.data).toContain("To: a@example.test");
    expect(e.data).not.toContain("secret@example.test");
    expect(e.meta.bcc).toEqual(["secret@example.test"]);
  });

  test("attachments as base64 or byte arrays; URLs are refused", () => {
    const e = prepare({
      from: "hello@acme.test",
      to: "a@example.test",
      subject: "Hi",
      text: "x",
      attachments: [
        { filename: "a.txt", content: btoa("hello") },
        { filename: "b.bin", content: [1, 2, 3], content_type: "application/octet-stream" },
      ],
    });
    expect(e.data).toContain('filename="a.txt"');
    expect(e.data).toContain(btoa("hello"));
    expect(() =>
      prepare({
        from: "hello@acme.test",
        to: "a@example.test",
        subject: "Hi",
        text: "x",
        attachments: [{ filename: "x", path: "http://169.254.169.254/" }],
      }),
    ).toThrow(ApiError);
  });

  test("more than 50 recipients, no body or header injection are 422", () => {
    const many = Array.from({ length: 51 }, (_, i) => `u${i}@example.test`);
    const err = (body: unknown) => {
      try {
        prepare(body);
        return null;
      } catch (e) {
        return e as ApiError;
      }
    };
    expect(
      sendSchema.safeParse({ from: "h@acme.test", to: many, subject: "x", text: "x" }).success,
    ).toBe(false);
    expect(
      err({
        from: "h@acme.test",
        to: many.slice(0, 30),
        cc: many.slice(30),
        subject: "x",
        text: "x",
      })?.status,
    ).toBe(422);
    expect(err({ from: "h@acme.test", to: "a@example.test", subject: "x" })?.message).toContain(
      "html",
    );
    expect(
      err({
        from: "h@acme.test",
        to: "a@example.test",
        subject: "x\r\nBcc: evil@x.test",
        text: "x",
      })?.status,
    ).toBe(422);
  });

  test("scheduled_at and expires_at must be dates", () => {
    const e = prepare({
      from: "h@acme.test",
      to: "a@example.test",
      subject: "x",
      text: "x",
      scheduled_at: "2026-10-16T09:00:00Z",
      expires_at: "2026-10-16T10:00:00Z",
    });
    expect(e.scheduledAt).toBe(Date.parse("2026-10-16T09:00:00Z"));
    expect(() =>
      prepare({
        from: "h@acme.test",
        to: "a@example.test",
        subject: "x",
        text: "x",
        scheduled_at: "tomorrow",
      }),
    ).toThrow("ISO 8601");
  });
});

describe("cached lookups", () => {
  test("a cached API key is dropped the moment it is revoked", () => {
    const db = openDatabase({ path: ":memory:" });
    const { key, token } = createKey(
      db,
      { name: "app", scope: "send", domains: null, rateLimit: 10 },
      T0,
    );
    const hash = hashToken(token);
    expect(keyForHash(db, hash)?.id).toBe(key.id);
    expect(keyForHash(db, hash)).toBe(keyForHash(db, hash));
    revokeKey(db, key.id, T0 + 1);
    expect(keyForHash(db, hash)).toBeNull();
  });

  test("a domain read inside a transaction that rolls back is never cached", () => {
    const db = openDatabase({ path: ":memory:" });
    const d = {
      name: "acme.test",
      status: "pending" as const,
      records: [],
      createdAt: T0,
      checkedAt: null,
    };
    saveDomain(db, d, T0);
    expect(getDomain(db, "acme.test")?.status).toBe("pending");
    try {
      db.transaction(() => {
        saveDomain(db, { ...d, status: "verified" }, T0 + 1);
        expect(getDomain(db, "acme.test")?.status).toBe("verified");
        throw new Error("rollback");
      })();
    } catch {}
    expect(getDomain(db, "acme.test")?.status).toBe("pending");
    saveDomain(db, { ...d, status: "verified" }, T0 + 2);
    expect(getDomain(db, "acme.test")?.status).toBe("verified");
  });
});
