import type { Database } from "bun:sqlite";

export type HookKind = "check" | "scan" | "inbound";
export type OnError = "accept" | "refuse";

export interface Hook {
  id: string;
  kind: HookKind;
  url: string;
  timeoutMs: number;
  onError: OnError;
  maxScore: number | null;
  createdAt: number;
}

interface Row {
  id: string;
  kind: HookKind;
  url: string;
  timeout_ms: number;
  on_error: OnError;
  max_score: number | null;
  created_at: number;
}

const fromRow = (r: Row): Hook => ({
  id: r.id,
  kind: r.kind,
  url: r.url,
  timeoutMs: r.timeout_ms,
  onError: r.on_error,
  maxScore: r.max_score,
  createdAt: r.created_at,
});

export function addHook(db: Database, h: Omit<Hook, "id" | "createdAt">, now: number): Hook {
  const hook: Hook = { ...h, id: Bun.randomUUIDv7(), createdAt: now };
  db.query<unknown, [string, string, string, number, string, number | null, number]>(
    "INSERT INTO hooks (id, kind, url, timeout_ms, on_error, max_score, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).run(hook.id, hook.kind, hook.url, hook.timeoutMs, hook.onError, hook.maxScore, now);
  return hook;
}

export function listHooks(db: Database, kind?: HookKind): Hook[] {
  const rows =
    kind === undefined
      ? db.query<Row, []>("SELECT * FROM hooks ORDER BY id").all()
      : db.query<Row, [string]>("SELECT * FROM hooks WHERE kind = ? ORDER BY id").all(kind);
  return rows.map(fromRow);
}

export function removeHook(db: Database, id: string): boolean {
  return db.query<unknown, [string]>("DELETE FROM hooks WHERE id = ?").run(id).changes > 0;
}
