import { describe, expect, test } from "bun:test";
import {
  createAdminKey,
  createKey,
  hashToken,
  keyForHash,
  listKeys,
  revokeKey,
} from "../../src/accounts/api-keys.ts";
import {
  createProject,
  DEFAULT_PROJECT,
  deleteProject,
  findProject,
  listProjects,
  type ProjectId,
  projectOfMessage,
  recordAdminEvent,
  SYSTEM_PROJECT,
  updateProject,
} from "../../src/accounts/projects.ts";
import { purgeDeletedProject } from "../../src/accounts/purge.ts";
import { appendEvent } from "../../src/core/events.ts";
import {
  claim,
  expireHeldJobs,
  HELD_OFFSET,
  holdProjectJobs,
  nextWakeAt,
  releaseProjectJobs,
} from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { epochKeyPair, newEpochSeed } from "../../src/crypto/envelope.ts";
import { cancelEmail, enqueueEmail, scheduledEmail } from "../../src/delivery/queue.ts";
import {
  findDomain,
  getDomain,
  listDomains,
  moveDomain,
  releaseProjectDomains,
  saveDomain,
  setDomainPool,
} from "../../src/domains/domains.ts";
import { countEmail, searchEmails, statsFor } from "../../src/emails/search.ts";
import { emailSummary, emailView } from "../../src/emails/view.ts";
import { nextAdminBatch } from "../../src/eventlog/export.ts";
import { createHold, listHolds, releaseHold } from "../../src/guards/guards.ts";
import {
  createRoute,
  deleteRoute,
  findRoute,
  listRoutes,
  moveDomainRoutes,
} from "../../src/inbound/routes.ts";
import type { RpcClient } from "../../src/ipc/rpc.ts";
import { collect, render } from "../../src/metrics/metrics.ts";
import { cancelProjectQueue, queueSummary, removeQueued } from "../../src/queue/control.ts";
import {
  requireServerWide,
  resolveActor,
  resolveAdmin,
  resolveServer,
  scopeOf,
} from "../../src/roles/actor.ts";
import { coreMethods } from "../../src/roles/core-api.ts";
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
    expect(resolveActor(db, { tokenHash: hashToken(token) }, "read")).toMatchObject({
      kind: "project",
      project: B,
    });
    expect(resolveActor(db, {})).toEqual({ kind: "operator", project: A, key: null });
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
    expect(scopeOf(resolveActor(db, {}))).toBeNull();
  });

  test("delivery-wide changes need the operator once a second project exists", () => {
    const db = openDatabase({ path: ":memory:" });
    const { token } = createKey(db, A, { name: "a", scope: "full" }, T0);
    const key = resolveActor(db, { tokenHash: hashToken(token) }, "full");
    expect(() => requireServerWide(db, key)).not.toThrow();
    db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [B, T0]);
    expect(() => requireServerWide(db, key)).toThrow("the operator must do it");
    expect(() => requireServerWide(db, resolveActor(db, {}))).not.toThrow();
  });

  test("admin keys manage projects and cannot touch project data", () => {
    const db = openDatabase({ path: ":memory:" });
    const admin = createAdminKey(db, { name: "ops" }, T0);
    const user = createKey(db, A, { name: "app", scope: "full" }, T0);
    const asAdmin = { tokenHash: hashToken(admin.token) };
    const asUser = { tokenHash: hashToken(user.token) };
    expect(admin.key).toMatchObject({ scope: "admin", projectId: null });
    expect(() => resolveActor(db, asAdmin, "read")).toThrow("use a project key");
    expect(resolveAdmin(db, asAdmin).kind).toBe("admin");
    expect(scopeOf(resolveServer(db, asAdmin, "read"))).toBeNull();
    expect(() => resolveAdmin(db, asUser)).toThrow("needs an admin key");
    expect(resolveAdmin(db, {}).kind).toBe("operator");
    expect(listKeys(db, null).map((k) => k.id)).toEqual([admin.key.id]);
    expect(listKeys(db, A).map((k) => k.id)).toEqual([user.key.id]);
    expect(() => resolveActor(db, { ...asUser, project: "default" })).toThrow("own project");
  });

  test("the operator picks a project by name; unknown names are not found", () => {
    const db = openDatabase({ path: ":memory:" });
    const p = createProject(db, "acme", T0);
    expect(resolveActor(db, { project: "acme" }).project).toBe(p?.id as ProjectId);
    expect(resolveActor(db, {}).project).toBe(A);
    expect(() => resolveActor(db, { project: "nope" })).toThrow("no project nope");
  });

  test("projects: names are unique, limits change, removal revokes keys at once", () => {
    const db = openDatabase({ path: ":memory:" });
    const p = createProject(db, "acme", T0) as NonNullable<ReturnType<typeof createProject>>;
    expect(createProject(db, "acme", T0)).toBeNull();
    expect(listProjects(db).map((x) => x.name)).toEqual(["acme", "default"]);
    expect(updateProject(db, p.id, { perHour: 100, suspended: true }, T0 + 1)).toMatchObject({
      perHour: 100,
      perDay: null,
      suspendedAt: T0 + 1,
    });
    expect(updateProject(db, p.id, { suspended: false }, T0 + 2)?.suspendedAt).toBeNull();
    const { token } = createKey(db, p.id, { name: "k", scope: "send" }, T0);
    expect(keyForHash(db, hashToken(token))?.projectId).toBe(p.id);
    expect(deleteProject(db, p.id, T0 + 3)).toBe(true);
    expect(deleteProject(db, p.id, T0 + 3)).toBe(false);
    expect(keyForHash(db, hashToken(token))).toBeNull();
    expect(findProject(db, "acme")).toBeNull();
    expect(() => resolveActor(db, { project: "acme" })).toThrow("no project acme");
  });

  test("admin actions go to the event log with the project and who did it", () => {
    const db = openDatabase({ path: ":memory:" });
    recordAdminEvent(
      db,
      { kind: "project.created", project: B, actor: "operator", data: { name: "other" } },
      T0,
    );
    const batch = nextAdminBatch(db);
    expect(batch?.lines.map((l) => JSON.parse(l))).toEqual([
      {
        admin_event_id: 1,
        at: new Date(T0).toISOString(),
        project_id: B,
        event: "project.created",
        source: "admin",
        actor: "operator",
        data: { name: "other" },
      },
    ]);
  });

  function withMail(project: ProjectId) {
    const db = openDatabase({ path: ":memory:" });
    if (project !== A) {
      db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [project, T0]);
    }
    const id = Bun.randomUUIDv7();
    enqueueEmail(
      db,
      project,
      {
        id,
        body: sealed,
        from: "x@a.test",
        recipients: ["r@dest.test"],
        smtpUtf8: false,
        requireTls: false,
      },
      T0,
    );
    return { db, id };
  }

  test("a suspended project's queued mail waits and goes out after resume", () => {
    const { db } = withMail(B);
    db.run("UPDATE projects SET suspended_at = ? WHERE id = ?", [T0, B]);
    expect(holdProjectJobs(db, B, T0)).toBe(1);
    expect(holdProjectJobs(db, B, T0)).toBe(0);
    expect(claim(db, T0 + 1_000, 10, 60_000)).toEqual([]);
    db.run("UPDATE jobs SET run_after = ? WHERE project_id = ?", [T0, B]);
    expect(claim(db, T0 + 1_000, 10, 60_000)).toEqual([]);
    db.run("UPDATE jobs SET run_after = run_after + ? WHERE project_id = ?", [HELD_OFFSET, B]);
    db.run("UPDATE projects SET suspended_at = NULL WHERE id = ?", [B]);
    expect(releaseProjectJobs(db, B, T0 + 2)).toBe(1);
    expect(releaseProjectJobs(db, B, T0 + 2)).toBe(0);
    expect(claim(db, T0 + 1_000, 10, 60_000).length).toBe(1);
  });

  test("a removed project's queue is canceled, its domains freed, its data purged", () => {
    const { db, id } = withMail(B);
    saveDomain(
      db,
      {
        project: B,
        name: "b.test",
        status: "verified",
        records: [],
        createdAt: T0,
        checkedAt: null,
      },
      T0,
    );
    createKey(db, B, { name: "k", scope: "full" }, T0);
    createTemplate(db, B, "welcome", { subject: "Hi", html: null, text: "Hi" }, T0);
    suppress(db, B, { address: "r@dest.test", scope: "all", reason: "manual" }, T0);
    deleteProject(db, B, T0 + 1);
    expect(cancelProjectQueue(db, B, T0 + 1).emails).toBe(1);
    expect(releaseProjectDomains(db, B)).toEqual(["b.test"]);
    expect(findDomain(db, "b.test")).toBeNull();
    expect(purgeDeletedProject(db)).toEqual({ project: B, messages: 1, finished: false });
    expect(db.query("SELECT 1 FROM messages WHERE id = ?").get(id)).toBeNull();
    expect(purgeDeletedProject(db)).toEqual({ project: B, messages: 0, finished: true });
    for (const t of ["api_keys", "templates", "suppressions", "projects WHERE id = 'p-other'"]) {
      expect(db.query(`SELECT 1 FROM ${t}`).all()).toEqual([]);
    }
    expect(purgeDeletedProject(db)).toEqual({ project: null, messages: 0, finished: false });
    expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
  });

  test("purge waits for mail that is being sent", () => {
    const { db } = withMail(B);
    db.run("UPDATE jobs SET state = 'leased' WHERE project_id = ?", [B]);
    deleteProject(db, B, T0);
    expect(purgeDeletedProject(db)).toEqual({ project: null, messages: 0, finished: false });
    expect(db.query("SELECT 1 FROM projects WHERE id = ?").get(B)).not.toBeNull();
  });

  test("held email fails as expired when its expiry passes, without waiting for resume", () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("INSERT INTO projects (id, name, created_at) VALUES (?, 'other', ?)", [B, T0]);
    const id = Bun.randomUUIDv7();
    enqueueEmail(
      db,
      B,
      {
        id,
        body: sealed,
        from: "x@a.test",
        recipients: ["r@dest.test"],
        smtpUtf8: false,
        requireTls: false,
        expiresAt: T0 + 60_000,
      },
      T0,
    );
    db.run("UPDATE projects SET suspended_at = ? WHERE id = ?", [T0, B]);
    holdProjectJobs(db, B, T0);
    expect(expireHeldJobs(db, T0 + 59_999)).toBe(0);
    expect(claim(db, T0 + 59_999, 10, 60_000)).toEqual([]);
    expect(expireHeldJobs(db, T0 + 60_000)).toBe(1);
    const [job] = claim(db, T0 + 60_000, 10, 60_000);
    expect(job).toMatchObject({ messageId: id, expiresAt: T0 + 60_000 });
  });

  test("the scheduler does not wake for email it cannot send", () => {
    const { db } = withMail(B);
    db.run("UPDATE projects SET suspended_at = ? WHERE id = ?", [T0, B]);
    expect(nextWakeAt(db, T0 + 1_000)).toBeUndefined();
    db.run("UPDATE projects SET suspended_at = NULL WHERE id = ?", [B]);
    expect(nextWakeAt(db, T0 + 1_000)).toBe(T0);
  });

  test("server email is sent for a suspended project's domain; the project's own email is refused", async () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("INSERT INTO projects (id, name, created_at, suspended_at) VALUES (?, 'other', ?, ?)", [
      B,
      T0,
      T0,
    ]);
    saveDomain(
      db,
      {
        project: B,
        name: "b.test",
        status: "verified",
        records: [],
        createdAt: T0,
        checkedAt: null,
      },
      T0,
    );
    const epoch = await epochKeyPair(1, newEpochSeed());
    const stub = {
      call: async (m: string) => (m === "domains" ? ["b.test"] : null),
    } as unknown as RpcClient;
    const { methods, enqueueInternal } = coreMethods({
      db,
      writer: new Writer(db),
      log: createLogger("error", {}, () => {}),
      signer: stub,
      delivery: stub,
      currentKey: async () => epoch,
      sourceIp: null,
    });
    const data = "From: tlsrpt@b.test\r\nTo: r@dest.test\r\nSubject: report\r\n\r\nhi\r\n";
    const id = await enqueueInternal("tlsrpt@b.test", "r@dest.test", data);
    expect(projectOfMessage(db, id)).toBe(SYSTEM_PROJECT);
    expect(claim(db, Date.now() + 1_000, 10, 60_000).map((j) => j.messageId)).toEqual([id]);
    const send = methods["enqueue"]?.handle({
      project: "other",
      from: "tlsrpt@b.test",
      recipients: ["r@dest.test"],
      data,
      smtpUtf8: false,
      requireTls: false,
    });
    await expect(send).rejects.toThrow("suspended");
  });

  test("send limits at intake: whole batches, real recipients only, retry time, 90 % event", async () => {
    const db = openDatabase({ path: ":memory:" });
    saveDomain(
      db,
      {
        project: A,
        name: "a.test",
        status: "verified",
        records: [],
        createdAt: T0,
        checkedAt: null,
      },
      T0,
    );
    db.run("UPDATE projects SET per_hour = 10 WHERE id = ?", [A]);
    suppress(db, A, { address: "gone@dest.test", scope: "all", reason: "manual" }, T0);
    const epoch = await epochKeyPair(1, newEpochSeed());
    const stub = {
      call: async (m: string) => (m === "domains" ? ["a.test"] : null),
    } as unknown as RpcClient;
    const { methods } = coreMethods({
      db,
      writer: new Writer(db),
      log: createLogger("error", {}, () => {}),
      signer: stub,
      delivery: stub,
      currentKey: async () => epoch,
      sourceIp: null,
    });
    const email = (to: string[]) => ({
      from: "x@a.test",
      recipients: to,
      data: "From: x@a.test\r\nSubject: s\r\n\r\nhi\r\n",
      smtpUtf8: false,
      requireTls: false,
    });
    const rcpts = (n: number, tag: string) =>
      Array.from({ length: n }, (_, i) => `${tag}${i}@dest.test`);
    const enqueue = (p: unknown) => methods["enqueue"]?.handle(p) as Promise<unknown>;
    const batch = (p: unknown) => methods["enqueueBatch"]?.handle(p) as Promise<unknown>;

    await enqueue(email([...rcpts(8, "a"), "gone@dest.test"]));
    const events = () =>
      db
        .query<{ data: string }, []>("SELECT data FROM events WHERE kind = 'limit_approaching'")
        .all()
        .map((e) => JSON.parse(e.data));
    expect(events()).toEqual([]);
    const before = db.query("SELECT count(*) AS n FROM messages").get();
    const refused = batch({ emails: [email(rcpts(1, "b")), email(rcpts(2, "c"))] });
    await expect(refused).rejects.toMatchObject({ code: "project-limit" });
    await refused.catch((e: { retryAfter?: number }) => expect(e.retryAfter).toBeGreaterThan(0));
    expect(db.query("SELECT count(*) AS n FROM messages").get()).toEqual(before);
    await batch({ emails: [email(rcpts(1, "d")), email(rcpts(1, "e"))] });
    expect(events()).toEqual([{ window: "hour", limit: 10, used: 9 }]);
    await expect(enqueue(email(rcpts(11, "f")))).rejects.toMatchObject({ code: "invalid" });
  });

  test("moving a domain takes its inbound routes; queued email and stats stay", () => {
    const { db, id } = setup();
    countEmail(db, id, "delivered", 1, T0);
    const r = createRoute(db, A, "in@a.test", "https://a.test/in", "raw", T0);
    createRoute(db, A, "in@other.test", "https://a.test/o", "raw", T0);
    expect(moveDomain(db, "a.test", B, T0 + 1)).toBe(true);
    expect(moveDomain(db, "a.test", B, T0 + 1)).toBe(false);
    expect(moveDomainRoutes(db, "a.test", B)).toBe(1);
    expect(getDomain(db, B, "a.test")?.name).toBe("a.test");
    expect(getDomain(db, A, "a.test")).toBeNull();
    expect(listRoutes(db, B).map((x) => x.id)).toEqual([r?.id as string]);
    expect(findRoute(db, "in@a.test")?.id).toBe(r?.id as string);
    expect(projectOfMessage(db, id)).toBe(A);
    const day = new Date(T0).toISOString().slice(0, 10);
    expect(statsFor(db, A, { since: day, until: day })[0]?.delivered).toBe(1);
    expect(statsFor(db, B, { since: day, until: day })[0]?.delivered).toBe(0);
  });
});
