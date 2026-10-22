import type { Database } from "bun:sqlite";
import {
  type ApiKey,
  createAdminKey,
  createKey,
  listKeys,
  revokeKey,
} from "../accounts/api-keys.ts";
import { listPoolOwners, ownPool, poolOwner, SHARED_POOLS, sharePool } from "../accounts/pools.ts";
import {
  createProject,
  DEFAULT_PROJECT,
  deleteProject,
  findProject,
  findRemovedProject,
  listProjects,
  nameTaken,
  PROJECT_NAME,
  type Project,
  type ProjectId,
  purgedProjectId,
  recordAdminEvent,
  updateProject,
} from "../accounts/projects.ts";
import type { SourceIp } from "../config.ts";
import { holdProjectJobs, releaseProjectJobs } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { findDomain, moveDomain, releaseProjectDomains } from "../domains/domains.ts";
import { disableProjectRoutes, moveDomainRoutes } from "../inbound/routes.ts";
import { type Methods, method, RpcError } from "../ipc/rpc.ts";
import { cancelProjectQueue } from "../queue/control.ts";
import { b } from "../validate/schema.ts";
import { disableProjectWebhooks } from "../webhooks/store.ts";
import { actorName, type Caller, resolveActor, resolveAdmin } from "./actor.ts";
import { domainName, knownPool, usablePool } from "./checks.ts";
import { project, tokenHash } from "./wire.ts";

export interface ProjectDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  ips?: SourceIp[];
  now?: () => number;
}

const iso = (t: number | null) => (t === null ? null : new Date(t).toISOString());

export const projectView = (p: Project) => ({
  object: "project",
  id: p.id,
  name: p.name,
  per_hour: p.perHour,
  per_day: p.perDay,
  ip_pool: p.pool,
  suspended: p.suspendedAt !== null,
  created_at: iso(p.createdAt),
  suspended_at: iso(p.suspendedAt),
});

const keyView = (k: ApiKey, token: string) => ({
  object: "api_key",
  id: k.id,
  name: k.name,
  scope: k.scope,
  domains: k.domains,
  rate_limit: k.rateLimit,
  test: k.test,
  ip_pool: k.pool ?? null,
  created_at: iso(k.createdAt),
  token,
});

const projectKey = {
  name: b.string().min(1).max(100),
  scope: b.enum(["send", "read", "full"]),
  domains: b.array(b.string().max(253)).max(100).optional(),
  rateLimit: b.number().int().min(1).max(10_000).optional(),
  test: b.boolean().optional(),
  pool: b.string().max(32).optional(),
};

const projectKeySchema = b.object(projectKey);

const limit = b.number().int().min(1).max(100_000_000).nullable().optional();

export function projectMethods(deps: ProjectDeps): Methods {
  const { db, writer, log } = deps;
  const now = deps.now ?? Date.now;

  const validName = (name: string) => {
    if (!PROJECT_NAME.test(name)) {
      throw new RpcError(
        "invalid",
        "name must be 1 to 63 lowercase letters, digits, _ and -, starting with a letter or digit",
      );
    }
  };

  const target = (id: string): Project => {
    const p = findProject(db, id);
    if (!p) throw new RpcError("not-found", "project not found");
    return p;
  };

  const newKey = (caller: Caller, projectId: ProjectId, p: b.infer<typeof projectKeySchema>) => {
    if (p.pool !== undefined) usablePool(db, deps.ips, projectId, p.pool);
    const domains = p.domains?.map(domainName);
    return writer.run((d) => {
      const made = createKey(
        d,
        projectId,
        {
          name: p.name,
          scope: p.scope,
          ...(domains ? { domains } : {}),
          ...(p.rateLimit ? { rateLimit: p.rateLimit } : {}),
          ...(p.test ? { test: true } : {}),
          ...(p.pool !== undefined ? { pool: p.pool } : {}),
        },
        now(),
      );
      recordAdminEvent(
        d,
        {
          kind: "project.key_created",
          project: projectId,
          actor: actorName(caller),
          data: { key_id: made.key.id, name: made.key.name, scope: made.key.scope },
        },
        now(),
      );
      return made;
    });
  };

  return {
    createKey: method(
      b.object({
        project,
        ...projectKey,
        scope: b.enum(["send", "read", "full", "admin"]),
      }),
      async (p) => {
        if (p.scope === "admin") {
          if (p.project !== undefined || p.domains || p.test || p.pool !== undefined) {
            throw new RpcError(
              "invalid",
              "an admin key has no project, domains, test mode or pool",
            );
          }
          const { key, token } = await writer.run((d) =>
            createAdminKey(
              d,
              { name: p.name, ...(p.rateLimit ? { rateLimit: p.rateLimit } : {}) },
              now(),
            ),
          );
          log.warn("admin API key created", { id: key.id, name: key.name });
          return { ...key, token };
        }
        const actor = resolveActor(db, p);
        const { key, token } = await newKey(actor, actor.project, { ...p, scope: p.scope });
        return { ...key, token };
      },
    ),

    listKeys: method(b.object({ project, admin: b.boolean().default(false) }), (p) =>
      listKeys(db, p.admin ? null : resolveActor(db, p).project),
    ),

    revokeKey: method(b.object({ project, id: b.string().min(1).max(64) }), async (p) => {
      const scope = resolveActor(db, p).project;
      const done = await writer.run(
        (d) => revokeKey(d, scope, p.id, now()) || revokeKey(d, null, p.id, now()),
      );
      if (!done) throw new RpcError("not-found", "no active key with that id");
      return { id: p.id, revoked: true };
    }),

    listProjects: method(b.object({ tokenHash }), (p) => {
      resolveAdmin(db, p);
      return listProjects(db).map(projectView);
    }),

    createProject: method(b.object({ tokenHash, name: b.string().max(63) }), async (p) => {
      const caller = resolveAdmin(db, p);
      validName(p.name);
      const made = await writer.run((d) => {
        const created = createProject(d, p.name, now());
        if (created) {
          recordAdminEvent(
            d,
            {
              kind: "project.created",
              project: created.id,
              actor: actorName(caller),
              data: { name: created.name },
            },
            now(),
          );
        }
        return created;
      });
      if (!made) throw new RpcError("invalid", `a project named ${p.name} already exists`);
      log.info("project created", { id: made.id, name: made.name });
      return projectView(made);
    }),

    getProject: method(b.object({ tokenHash, id: b.string().max(64) }), (p) => {
      resolveAdmin(db, p);
      return projectView(target(p.id));
    }),

    updateProject: method(
      b.object({
        tokenHash,
        id: b.string().max(64),
        name: b.string().max(63).optional(),
        perHour: limit,
        perDay: limit,
        pool: b.string().max(32).nullable().optional(),
        suspended: b.boolean().optional(),
      }),
      async (p) => {
        const caller = resolveAdmin(db, p);
        const before = target(p.id);
        if (p.name !== undefined) {
          validName(p.name);
          if (before.id === DEFAULT_PROJECT && p.name !== before.name) {
            throw new RpcError("invalid", "the default project cannot be renamed");
          }
          if (nameTaken(db, p.name, before.id)) {
            throw new RpcError("invalid", `a project named ${p.name} already exists`);
          }
        }
        if (p.pool !== undefined && p.pool !== null) usablePool(db, deps.ips, before.id, p.pool);
        const after = await writer.run((d) => {
          const next = updateProject(
            d,
            before.id,
            {
              ...(p.name !== undefined ? { name: p.name } : {}),
              ...(p.perHour !== undefined ? { perHour: p.perHour } : {}),
              ...(p.perDay !== undefined ? { perDay: p.perDay } : {}),
              ...(p.pool !== undefined ? { pool: p.pool } : {}),
              ...(p.suspended !== undefined ? { suspended: p.suspended } : {}),
            },
            now(),
          );
          if (!next) return null;
          const record = (kind: string, data?: Record<string, unknown>) =>
            recordAdminEvent(
              d,
              { kind, project: next.id, actor: actorName(caller), ...(data ? { data } : {}) },
              now(),
            );
          const changed = {
            ...(next.name !== before.name ? { name: next.name } : {}),
            ...(next.perHour !== before.perHour ? { per_hour: next.perHour } : {}),
            ...(next.perDay !== before.perDay ? { per_day: next.perDay } : {}),
            ...(next.pool !== before.pool ? { ip_pool: next.pool } : {}),
          };
          if (Object.keys(changed).length > 0) record("project.updated", changed);
          if (before.suspendedAt === null && next.suspendedAt !== null) {
            record("project.suspended", { held_jobs: holdProjectJobs(d, next.id, now()) });
          }
          if (before.suspendedAt !== null && next.suspendedAt === null) {
            record("project.resumed", { released_jobs: releaseProjectJobs(d, next.id, now()) });
          }
          return next;
        });
        if (!after) throw new RpcError("not-found", "project not found");
        return projectView(after);
      },
    ),

    deleteProject: method(b.object({ tokenHash, id: b.string().max(64) }), async (p) => {
      const caller = resolveAdmin(db, p);
      const removed = findRemovedProject(db, p.id);
      if (removed) return { object: "project", id: removed.id, deleted: true };
      const purged = findProject(db, p.id) ? null : purgedProjectId(db, p.id);
      if (purged) return { object: "project", id: purged, deleted: true };
      const t = target(p.id);
      if (t.id === DEFAULT_PROJECT) {
        throw new RpcError("invalid", "the default project cannot be removed");
      }
      const done = await writer.run((d) => {
        if (!deleteProject(d, t.id, now())) return null;
        const queue = cancelProjectQueue(d, t.id, now());
        const domains = releaseProjectDomains(d, t.id);
        disableProjectWebhooks(d, t.id, now());
        disableProjectRoutes(d, t.id, now());
        recordAdminEvent(
          d,
          {
            kind: "project.deleted",
            project: t.id,
            actor: actorName(caller),
            data: { name: t.name, canceled_emails: queue.emails, released_domains: domains },
          },
          now(),
        );
        return { emails: queue.emails, domains };
      });
      if (done) log.warn("project removed", { id: t.id, name: t.name, ...done });
      return { object: "project", id: t.id, deleted: true };
    }),

    listPools: method(b.object({}), () => {
      const owners = listPoolOwners(db);
      const names = new Map(listProjects(db).map((x) => [x.id, x.name]));
      const pools = new Map<string, string[]>();
      for (const ip of deps.ips ?? []) pools.set(ip.pool, [...(pools.get(ip.pool) ?? []), ip.ip]);
      return [...pools.entries()].map(([pool, ips]) => {
        const owner = owners.get(pool) ?? null;
        return { pool, ips, owner: owner === null ? null : (names.get(owner) ?? owner) };
      });
    }),

    ownPool: method(b.object({ pool: b.string().max(32), to: b.string().max(64) }), async (p) => {
      knownPool(deps.ips, p.pool);
      if (SHARED_POOLS.includes(p.pool)) {
        throw new RpcError("invalid", `${p.pool} is shared by every project`);
      }
      const to = target(p.to);
      const before = poolOwner(db, p.pool);
      const { cleared } = await writer.run((d) => {
        const r = ownPool(d, p.pool, to.id, now());
        for (const project of new Set([to.id, ...(before && before !== to.id ? [before] : [])])) {
          recordAdminEvent(
            d,
            {
              kind: "project.pool_owned",
              project,
              actor: "operator",
              data: { pool: p.pool, owner: to.id, cleared: r.cleared },
            },
            now(),
          );
        }
        return r;
      });
      log.info("pool owned", { pool: p.pool, project: to.id, cleared });
      return { pool: p.pool, owner: to.name, cleared };
    }),

    sharePool: method(b.object({ pool: b.string().max(32) }), async (p) => {
      const before = poolOwner(db, p.pool);
      if (!before) return { pool: p.pool, owner: null, changed: false };
      await writer.run((d) => {
        sharePool(d, p.pool);
        recordAdminEvent(
          d,
          {
            kind: "project.pool_shared",
            project: before,
            actor: "operator",
            data: { pool: p.pool },
          },
          now(),
        );
      });
      return { pool: p.pool, owner: null, changed: true };
    }),

    moveDomain: method(
      b.object({ name: b.string().max(253), to: b.string().max(64) }),
      async (p) => {
        const name = domainName(p.name);
        const to = target(p.to);
        const d = findDomain(db, name);
        if (!d) throw new RpcError("not-found", `domain ${name} is not registered`);
        if (d.project === to.id) return { name, project: to.name, moved: false };
        const routes = await writer.run((w) => {
          if (!moveDomain(w, name, to.id, now())) return null;
          const moved = moveDomainRoutes(w, name, to.id);
          for (const project of [d.project, to.id]) {
            recordAdminEvent(
              w,
              {
                kind: "project.domain_moved",
                project,
                actor: "operator",
                data: { domain: name, from: d.project, to: to.id, routes: moved },
              },
              now(),
            );
          }
          return moved;
        });
        if (routes === null) return { name, project: to.name, moved: false };
        log.info("domain moved", { domain: name, from: d.project, to: to.id, routes });
        return { name, project: to.name, moved: true, routes };
      },
    ),

    createProjectKey: method(
      b.object({ tokenHash, id: b.string().max(64), ...projectKey }),
      async (p) => {
        const caller = resolveAdmin(db, p);
        const t = target(p.id);
        const { key, token } = await newKey(caller, t.id, p);
        return keyView(key, token);
      },
    ),
  };
}
