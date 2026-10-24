import type { Database } from "bun:sqlite";

export type Settled = "done" | "dead" | "retry" | "unknown" | "requeued" | "stale";

export type Apply = (db: Database, settled: Exclude<Settled, "stale">, now: number) => void;

export type Committed = (settled: Exclude<Settled, "stale">) => void;

export type Outcome = (
  | { kind: "continue" }
  | { kind: "done" }
  | { kind: "fail"; code: string; reason: string }
  | { kind: "defer"; reason: string; delayMs?: number }
  | { kind: "unknown"; reason: string }
  | { kind: "requeue"; reason: string; delayMs: number; aged?: boolean }
) & { apply?: Apply; committed?: Committed; path?: string };

export const ok = { continue: { kind: "continue" }, done: { kind: "done" } } as const;

export const fail = (code: string, reason: string): Outcome => ({ kind: "fail", code, reason });

export const defer = (reason: string, delayMs?: number): Outcome =>
  delayMs === undefined ? { kind: "defer", reason } : { kind: "defer", reason, delayMs };

export const unknown = (reason: string): Outcome => ({ kind: "unknown", reason });

export const requeue = (reason: string, delayMs: number): Outcome => ({
  kind: "requeue",
  reason,
  delayMs,
});
