import type { Database } from "bun:sqlite";

export type Settled = "done" | "dead" | "retry" | "unknown" | "stale";

export type Apply = (db: Database, settled: Exclude<Settled, "stale">, now: number) => void;

export type Outcome = (
  | { kind: "continue" }
  | { kind: "done" }
  | { kind: "fail"; code: string; reason: string }
  | { kind: "defer"; reason: string; delayMs?: number }
  | { kind: "unknown"; reason: string }
) & { apply?: Apply };

export const ok = { continue: { kind: "continue" }, done: { kind: "done" } } as const;

export const fail = (code: string, reason: string): Outcome => ({ kind: "fail", code, reason });

export const defer = (reason: string, delayMs?: number): Outcome =>
  delayMs === undefined ? { kind: "defer", reason } : { kind: "defer", reason, delayMs };

export const unknown = (reason: string): Outcome => ({ kind: "unknown", reason });
