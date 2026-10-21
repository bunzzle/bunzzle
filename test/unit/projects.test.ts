import { describe, expect, test } from "bun:test";
import { createKey, hashToken, listKeys, revokeKey } from "../../src/accounts/api-keys.ts";
import { DEFAULT_PROJECT, type ProjectId } from "../../src/accounts/projects.ts";
import { appendEvent } from "../../src/core/events.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { cancelEmail, enqueueEmail, scheduledEmail } from "../../src/delivery/queue.ts";
import {
  findDomain,
  getDomain,
  listDomains,
  saveDomain,
  setDomainPool,
} from "../../src/domains/domains.ts";
import { countEmail, searchEmails, statsFor } from "../../src/emails/search.ts";
import { emailSummary, emailView } from "../../src/emails/view.ts";
import { createHold, listHolds, releaseHold } from "../../src/guards/guards.ts";
import { createRoute, deleteRoute, listRoutes } from "../../src/inbound/routes.ts";
import { collect, render } from "../../src/metrics/metrics.ts";
import { queueSummary, removeQueued } from "../../src/queue/control.ts";
import { requireServerWide, resolveActor, scopeOf } from "../../src/roles/actor.ts";
import {
  listSuppressions,
  removeSuppression,
  suppress,
  suppressionFor,
} from "../../src/suppressions/store.ts";
import { createTemplate, findTemplate, listTemplates } from "../../src/templates/store.ts";
import { projectEvents } from "../../src/webhooks/project.ts";
import { createWebhook, deleteWebhook, listWebhooks } from "../../src/webhooks/store.ts";

const T0 = Date.UTC(2026, 9, 21, 12);
const A = DEFAULT_PROJECT;
const B = "p-other" as ProjectId;
const sealed = { epoch: 1, wrapped: new Uint8Array([1]), body: new Uint8Array([2]) };

function setup() {
  const db = openDatabase({ path: ":memory:" });
  db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [B, T0]);
  saveDomain(
    db,
    { project: A, name: "a.test", status: "verified", records: [], createdAt: T0, checkedAt: null },
    T0,
  );
  const id = Bun.randomUUIDv7();
  enqueueEmail(
    db,
    A,
    {
      id,
      body: sealed,
      from: "x@a.test",
      recipients: ["r@dest.test"],
      smtpUtf8: false,
      requireTls: false,
      runAfter: T0 + 60_000,
      metadata: { scheduledAt: T0 + 60_000 },
    },
    T0,
  );
  return { db, id };
}

describe("projects", () => {
  test("a key resolves to its own project; no key is the operator on the default project", () => {
    const { db } = setup();
    const { token } = createKey(db, B, { name: "b", scope: "full" }, T0);
    expect(resolveActor(db, hashToken(token), "read")).toMatchObject({
      kind: "project",
      project: B,
    });
    expect(resolveActor(db, undefined)).toEqual({ kind: "operator", project: A, key: null });
    expect(listKeys(db, A)).toEqual([]);
    const [key] = listKeys(db, B);
    expect(revokeKey(db, A, key?.id as string, T0)).toBe(false);
    expect(revokeKey(db, B, key?.id as string, T0)).toBe(true);
  });

  test("domains of another project are not found", () => {
    const { db } = setup();
    expect(getDomain(db, B, "a.test")).toBeNull();
    expect(getDomain(db, A, "a.test")?.name).toBe("a.test");
    expect(listDomains(db, B)).toEqual([]);
    expect(setDomainPool(db, B, "a.test", "bulk", T0)).toBe(false);
    saveDomain(
      db,
      {
        project: B,
        name: "a.test",
        status: "pending",
        records: [],
        createdAt: T0,
        checkedAt: null,
      },
      T0 + 1,
    );
    expect(findDomain(db, "a.test")).toMatchObject({ project: A, status: "verified" });
  });

  test("emails, search and stats of another project are not visible", () => {
    const { db, id } = setup();
    countEmail(db, id, "delivered", 1, T0);
    expect(searchEmails(db, A, { limit: 10 })).toEqual([id]);
    expect(searchEmails(db, B, { limit: 10 })).toEqual([]);
    expect(searchEmails(db, B, { limit: 10, to: "r@dest.test" })).toEqual([]);
    expect(emailView(db, B, id, T0)).toBeNull();
    expect(emailSummary(db, B, id, T0)).toBeNull();
    expect(emailView(db, A, id, T0)).not.toBeNull();
    expect(scheduledEmail(db, B, id)).toBeNull();
    expect(cancelEmail(db, B, id, T0)).toBe("started");
    expect(scheduledEmail(db, A, id)).not.toBeNull();
    const day = new Date(T0).toISOString().slice(0, 10);
    expect(statsFor(db, B, { since: day, until: day })[0]?.delivered).toBe(0);
    expect(statsFor(db, A, { since: day, until: day })[0]?.sent).toBe(1);
  });

  test("suppressions are kept per project", () => {
    const { db } = setup();
    suppress(db, A, { address: "r@dest.test", scope: "all", reason: "manual" }, T0);
    expect(suppressionFor(db, B, "r@dest.test", "transactional", T0)).toBeNull();
    suppress(db, B, { address: "r@dest.test", scope: "all", reason: "complaint" }, T0);
    expect(suppressionFor(db, A, "r@dest.test", "transactional", T0)?.reason).toBe("manual");
    expect(removeSuppression(db, B, "r@dest.test", null)).toBe(1);
    expect(listSuppressions(db, A, T0).map((s) => s.address)).toEqual(["r@dest.test"]);
    expect(listSuppressions(db, B, T0)).toEqual([]);
  });

  test("webhooks get only their own project's events", () => {
    const { db, id } = setup();
    const a = createWebhook(db, A, "https://a.test/hook", [], T0);
    const b = createWebhook(db, B, "https://b.test/hook", [], T0);
    expect(listWebhooks(db, B).map((h) => h.id)).toEqual([b.id]);
    expect(deleteWebhook(db, B, a.id, T0)).toBe(false);
    appendEvent(db, { messageId: id, kind: "canceled", source: "api", at: T0 });
    projectEvents(db, T0);
    const to = db
      .query<{ webhook_id: string }, []>("SELECT webhook_id FROM webhook_deliveries")
      .all()
      .map((r) => r.webhook_id);
    expect(to).toEqual([a.id]);
  });

  test("templates and routes belong to one project", () => {
    const { db } = setup();
    const content = { subject: "Hi", html: null, text: "Hi" };
    const a = createTemplate(db, A, "welcome", content, T0);
    expect(createTemplate(db, B, "welcome", content, T0)).not.toBeNull();
    expect(findTemplate(db, B, a?.id as string)).toBeNull();
    expect(listTemplates(db, B).map((t) => t.id)).not.toContain(a?.id);
    const r = createRoute(db, A, "in@a.test", "https://a.test/in", "raw", T0);
    expect(listRoutes(db, B)).toEqual([]);
    expect(deleteRoute(db, B, r?.id as string, T0)).toBe(false);
    expect(listRoutes(db, A).map((x) => x.id)).toEqual([r?.id as string]);
  });

  test("server endpoints show and change only the caller's project", () => {
    const { db } = setup();
    const held = createHold(db, "domain:a.test", "bulk", "test", T0).hold;
    expect(listHolds(db, B).map((h) => h.id)).toEqual([]);
    expect(listHolds(db, A).map((h) => h.id)).toEqual([held.id]);
    expect(listHolds(db, null).map((h) => h.id)).toEqual([held.id]);
    expect(releaseHold(db, B, held.id, T0)).toBe(false);
    expect(queueSummary(db, B, T0).domains).toEqual([]);
    expect(queueSummary(db, A, T0).domains.length).toBe(1);
    const filter = { domain: "dest.test" };
    expect(removeQueued(db, B, filter, "cancel", "x", T0, true).emails).toBe(0);
    expect(removeQueued(db, A, filter, "cancel", "x", T0, true).emails).toBe(1);
    expect(render(collect(db, B, [], T0, T0))).toContain('bunzzle_jobs{state="ready"} 0');
    expect(render(collect(db, A, [], T0, T0))).toContain('bunzzle_jobs{state="ready"} 1');
    expect(scopeOf(resolveActor(db, undefined))).toBeNull();
  });

  test("delivery-wide changes need the operator once a second project exists", () => {
    const db = openDatabase({ path: ":memory:" });
    const { token } = createKey(db, A, { name: "a", scope: "full" }, T0);
    const key = resolveActor(db, hashToken(token), "full");
    expect(() => requireServerWide(db, key)).not.toThrow();
    db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [B, T0]);
    expect(() => requireServerWide(db, key)).toThrow("the operator must do it");
    expect(() => requireServerWide(db, resolveActor(db, undefined))).not.toThrow();
  });
});
