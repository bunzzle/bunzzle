export type Outcome =
  | { kind: "continue" }
  | { kind: "done" }
  | { kind: "fail"; code: string; reason: string }
  | { kind: "defer"; reason: string; delayMs?: number }
  | { kind: "unknown"; reason: string };

export const ok = { continue: { kind: "continue" }, done: { kind: "done" } } as const;

export const fail = (code: string, reason: string): Outcome => ({ kind: "fail", code, reason });

export const defer = (reason: string, delayMs?: number): Outcome =>
  delayMs === undefined ? { kind: "defer", reason } : { kind: "defer", reason, delayMs };

export const unknown = (reason: string): Outcome => ({ kind: "unknown", reason });
