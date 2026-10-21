import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import type { SealedBody } from "../crypto/envelope.ts";
import { RETRY_MS } from "../webhooks/store.ts";

export const ROUTE_FORMATS = ["parsed", "raw"] as const;
export type RouteFormat = (typeof ROUTE_FORMATS)[number];

export interface Route {
  id: string;
  address: string;
  url: string;
  format: RouteFormat;
  createdAt: number;
}

interface Row {
  id: string;
  address: string;
  url: string;
  format: RouteFormat;
  created_at: number;
}

const fromRow = (r: Row): Route => ({
  id: r.id,
  address: r.address,
  url: r.url,
  format: r.format,
  createdAt: r.created_at,
});

const LOCAL = /^(\*|[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*)$/;

export function splitRouteAddress(input: string): { local: string; domain: string } | null {
  const address = input.trim().toLowerCase();
  const at = address.lastIndexOf("@");
  if (at <= 0) return null;
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (local.length > 64 || !LOCAL.test(local)) return null;
  return { local, domain };
}

export function createRoute(
  db: Database,
  project: ProjectId,
  address: string,
  url: string,
  format: RouteFormat,
  now: number,
): Route | null {
  const id = Bun.randomUUIDv7();
  const added = db
    .query<unknown, [string, string, string, string, string, number]>(
      `INSERT INTO routes (id, project_id, address, url, format, created_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT DO NOTHING`,
    )
    .run(id, project, address, url, format, now).changes;
  return added ? { id, address, url, format, createdAt: now } : null;
}

export function listRoutes(db: Database, project: ProjectId): Route[] {
  return db
    .query<Row, [string]>(
      `SELECT id, address, url, format, created_at FROM routes
       WHERE project_id = ? AND disabled_at IS NULL ORDER BY address`,
    )
    .all(project)
    .map(fromRow);
}

export function deleteRoute(db: Database, project: ProjectId, id: string, now: number): boolean {
  return (
    db
      .query<unknown, [number, string, string]>(
        "UPDATE routes SET disabled_at = ? WHERE id = ? AND project_id = ? AND disabled_at IS NULL",
      )
      .run(now, id, project).changes > 0
  );
}

export function findRoute(db: Database, address: string): Route | null {
  const parts = splitRouteAddress(address);
  if (!parts || parts.local === "*") return null;
  const { local, domain } = parts;
  const plus = local.indexOf("+");
  const candidates = [`${local}@${domain}`];
  if (plus > 0) candidates.push(`${local.slice(0, plus)}@${domain}`);
  candidates.push(`*@${domain}`);
  const get = db.query<Row, [string]>(
    `SELECT id, address, url, format, created_at FROM routes
     WHERE address = ? AND disabled_at IS NULL`,
  );
  for (const c of candidates) {
    const row = get.get(c);
    if (row) return fromRow(row);
  }
  return null;
}

export function queueRouted(
  db: Database,
  routeId: string,
  id: string,
  sealed: SealedBody,
  size: number,
  now: number,
): void {
  db.query<
    unknown,
    [string, string, number, Uint8Array, Uint8Array, number, number, number, number]
  >(
    `INSERT INTO route_deliveries
       (id, route_id, epoch, wrapped, body, size, state, next_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
  ).run(id, routeId, sealed.epoch, sealed.wrapped, sealed.body, size, now, now, now);
}

export interface RoutedPending {
  id: string;
  routeId: string;
  url: string;
  attempt: number;
  sealed: SealedBody;
}

export function claimRouted(db: Database, now: number, limit: number): RoutedPending[] {
  return db
    .query<
      {
        id: string;
        route_id: string;
        url: string;
        attempt: number;
        epoch: number;
        wrapped: Uint8Array;
        body: Uint8Array;
      },
      [number, number, number]
    >(
      `UPDATE route_deliveries SET state = 'sending', attempt = attempt + 1, updated_at = ?1
       WHERE id IN (
         SELECT d.id FROM route_deliveries d JOIN routes r ON r.id = d.route_id
         WHERE d.state = 'pending' AND d.next_at <= ?1 AND r.disabled_at IS NULL
           AND d.body IS NOT NULL
         ORDER BY d.next_at LIMIT ?3
       )
       RETURNING id, route_id, (SELECT url FROM routes WHERE id = route_id) AS url, attempt,
         epoch, wrapped, body`,
    )
    .all(now, now, limit)
    .map((r) => ({
      id: r.id,
      routeId: r.route_id,
      url: r.url,
      attempt: r.attempt,
      sealed: { epoch: r.epoch, wrapped: r.wrapped, body: r.body },
    }));
}

export type RouteOutcome =
  | { ok: true }
  | { ok: false; error: string; retry: boolean; retryAfterMs: number | null };

export const RETRY_AFTER_MAX_MS = 6 * 3_600_000;

export function retryAfterMs(value: string | undefined, now: number): number | null {
  if (!value) return null;
  const v = value.trim();
  const ms = /^\d+$/.test(v) ? Number(v) * 1_000 : Date.parse(v) - now;
  if (!Number.isFinite(ms)) return null;
  return Math.min(RETRY_AFTER_MAX_MS, Math.max(1_000, ms));
}

export function outcomeOf(
  r: { ok: true; status: number; retryAfter?: string | undefined } | { ok: false; error: string },
  now: number,
): RouteOutcome {
  if (!r.ok) return { ok: false, error: r.error, retry: true, retryAfterMs: null };
  if (r.status >= 200 && r.status < 300) return { ok: true };
  const retry = r.status === 408 || r.status === 429 || r.status >= 500;
  return {
    ok: false,
    error: `endpoint answered ${r.status}`,
    retry,
    retryAfterMs: retry ? retryAfterMs(r.retryAfter, now) : null,
  };
}

export function settleRouted(
  db: Database,
  d: Pick<RoutedPending, "id" | "attempt">,
  outcome: RouteOutcome,
  now: number,
  scale = 1,
): "done" | "retry" | "failed" {
  if (outcome.ok) {
    db.query<unknown, [number, string]>(
      `UPDATE route_deliveries SET state = 'done', last_error = NULL, epoch = NULL,
         wrapped = NULL, body = NULL, updated_at = ? WHERE id = ?`,
    ).run(now, d.id);
    return "done";
  }
  const wait = outcome.retry ? RETRY_MS[d.attempt - 1] : undefined;
  if (wait === undefined) {
    db.query<unknown, [string, number, string]>(
      "UPDATE route_deliveries SET state = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
    ).run(outcome.error, now, d.id);
    return "failed";
  }
  const delay = outcome.retryAfterMs ?? wait;
  db.query<unknown, [number, string, number, string]>(
    `UPDATE route_deliveries SET state = 'pending', next_at = ?, last_error = ?, updated_at = ?
     WHERE id = ?`,
  ).run(now + Math.max(1, Math.round(delay * scale)), outcome.error, now, d.id);
  return "retry";
}

export function retryFailed(
  db: Database,
  project: ProjectId,
  routeId: string,
  now: number,
): number {
  return db
    .query<unknown, [number, number, string, string]>(
      `UPDATE route_deliveries SET state = 'pending', attempt = 0, next_at = ?, updated_at = ?
       WHERE route_id = (SELECT id FROM routes WHERE id = ? AND project_id = ?)
         AND state = 'failed' AND body IS NOT NULL`,
    )
    .run(now, now, routeId, project).changes;
}

export function resetRouted(db: Database, now: number): number {
  return db
    .query<unknown, [number]>(
      "UPDATE route_deliveries SET state = 'pending', updated_at = ? WHERE state = 'sending'",
    )
    .run(now).changes;
}

export function pruneRouted(db: Database, before: number): void {
  db.query<unknown, [number]>(
    "DELETE FROM route_deliveries WHERE state IN ('done', 'failed') AND updated_at < ?",
  ).run(before);
}

export function disableProjectRoutes(db: Database, project: ProjectId, now: number): number {
  return db
    .query<unknown, [number, string]>(
      "UPDATE routes SET disabled_at = ? WHERE project_id = ? AND disabled_at IS NULL",
    )
    .run(now, project).changes;
}

export function moveDomainRoutes(db: Database, domain: string, to: ProjectId): number {
  return db
    .query<unknown, [string, string]>(
      `UPDATE routes SET project_id = ? WHERE disabled_at IS NULL
         AND substr(address, instr(address, '@') + 1) = ?`,
    )
    .run(to, domain).changes;
}
