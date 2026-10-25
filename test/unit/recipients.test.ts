import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT as A, type ProjectId } from "../../src/accounts/projects.ts";
import {
  checkRecipients,
  finishSeed,
  pruneRecipients,
  RECIPIENT_MEMORY_MS,
  recipientHasher,
  recipientsSeeded,
  rememberRecipients,
  seedPage,
} from "../../src/accounts/recipients.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { generateMasterKey, MasterKeyError, masterKeyFrom } from "../../src/crypto/master.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import { loadRecipientKey } from "../../src/signer/recipient-key.ts";

const B = "p-other" as ProjectId;
const T0 = Date.UTC(2026, 9, 22, 12);
const sealed = { epoch: 1, wrapped: new Uint8Array([1]), body: new Uint8Array([2]) };

describe("known recipients", () => {
  test("hashes ignore case and depend on the key", () => {
    const one = recipientHasher(new Uint8Array(32));
    const two = recipientHasher(new Uint8Array(32).fill(1));
    expect(one("A@x.test")).toEqual(one("a@x.test"));
    expect(one("a@x.test")).not.toEqual(two("a@x.test"));
    expect(one("a@x.test").length).toBe(16);
  });

  test("hashes are HMAC-SHA-256 of the lowercase address, first 16 bytes", async () => {
    const key = new Uint8Array(32).map((_, i) => i * 7);
    const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    const hash = recipientHasher(key);
    for (const a of ["a@x.test", "Bob@Example.COM", "ü@ex.test"]) {
      const mac = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(a.toLowerCase()));
      expect(hash(a)).toEqual(new Uint8Array(mac).slice(0, 16));
    }
  });

  test("remembered for 90 days, then pruned", () => {
    const db = openDatabase({ path: ":memory:" });
    const h = recipientHasher(new Uint8Array(32))("a@x.test");
    rememberRecipients(db, A, [h], T0);
    expect(checkRecipients(db, A, [h, h], T0 + 1).fresh).toBe(0);
    expect(checkRecipients(db, A, [h, h], T0 + RECIPIENT_MEMORY_MS).fresh).toBe(1);
    pruneRecipients(db, T0 + RECIPIENT_MEMORY_MS - 1);
    expect(db.query("SELECT count(*) AS n FROM project_recipients").get()).toEqual({ n: 1 });
    pruneRecipients(db, T0 + RECIPIENT_MEMORY_MS);
    expect(db.query("SELECT count(*) AS n FROM project_recipients").get()).toEqual({ n: 0 });
  });

  test("a recipient refreshed today is not written again", () => {
    const db = openDatabase({ path: ":memory:" });
    const h = recipientHasher(new Uint8Array(32))("a@x.test");
    expect(checkRecipients(db, A, [h], T0)).toEqual({ fresh: 1, stale: [h] });
    rememberRecipients(db, A, [h], T0);
    expect(checkRecipients(db, A, [h], T0 + 23 * 3_600_000)).toEqual({ fresh: 0, stale: [] });
    expect(checkRecipients(db, A, [h], T0 + 24 * 3_600_000)).toEqual({ fresh: 0, stale: [h] });
  });

  test("the first fill reads recent email, skips test and suppressed recipients", () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [B, T0]);
    const add = (
      project: ProjectId,
      to: string[],
      at: number,
      extra: { test?: boolean; suppressed?: string } = {},
    ) =>
      enqueueEmail(
        db,
        project,
        {
          id: Bun.randomUUIDv7(),
          body: sealed,
          from: "x@a.test",
          recipients: to,
          smtpUtf8: false,
          requireTls: false,
          ...(extra.suppressed
            ? { suppressed: new Map([[extra.suppressed, { reason: "manual", scope: "all" }]]) }
            : {}),
          ...(extra.test ? { metadata: { test: true } } : {}),
        },
        at,
      );
    add(A, ["old@dest.test"], T0 - RECIPIENT_MEMORY_MS - 1);
    add(A, ["a@dest.test", "gone@dest.test"], T0, { suppressed: "gone@dest.test" });
    add(A, ["t@dest.test"], T0, { test: true });
    add(B, ["b@dest.test", "c@other.test"], T0);
    expect(recipientsSeeded(db)).toBe(false);
    const first = seedPage(db, 0, T0, 2);
    expect(first.rows.map((r) => [r.project, r.address])).toEqual([
      [A, "a@dest.test"],
      [B, "b@dest.test"],
    ]);
    expect(first.next).not.toBeNull();
    const second = seedPage(db, first.next ?? 0, T0, 2);
    expect(second.rows.map((r) => r.address)).toEqual(["c@other.test"]);
    expect(second.next).toBeNull();
    finishSeed(db, T0);
    expect(recipientsSeeded(db)).toBe(true);
  });

  test("the recipient key is made once, sealed, and opens only with its master key", async () => {
    const dir = (await Bun.$`mktemp -d`.text()).trim();
    const path = `${dir}/recipients.json`;
    const master = await masterKeyFrom(generateMasterKey());
    const key = await loadRecipientKey(path, master);
    expect(key.length).toBe(32);
    expect(await loadRecipientKey(path, master)).toEqual(key);
    expect(await Bun.file(path).text()).not.toContain(key.toBase64());
    expect((await Bun.file(path).stat()).mode & 0o777).toBe(0o600);
    const other = await masterKeyFrom(generateMasterKey());
    await expect(loadRecipientKey(path, other)).rejects.toBeInstanceOf(MasterKeyError);
    await Bun.$`rm -r ${dir}`.quiet();
  });
});
