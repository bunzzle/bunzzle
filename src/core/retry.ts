export interface RetryPolicy {
  stepsMs: number[];
  everyMs: number;
  jitter: number;
  maxAttempts: number;
  maxAgeMs: number;
  noticesMs: number[];
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export const defaultRetryPolicy: RetryPolicy = {
  stepsMs: [MINUTE, 5 * MINUTE, 15 * MINUTE, 30 * MINUTE],
  everyMs: HOUR,
  jitter: 0.1,
  maxAttempts: 200,
  maxAgeMs: 5 * 24 * HOUR,
  noticesMs: [HOUR, 24 * HOUR],
};

export function retryDelay(policy: RetryPolicy, attempt: number, random = Math.random): number {
  const base = policy.stepsMs[attempt - 1] ?? policy.everyMs;
  return Math.max(0, Math.round(base * (1 + policy.jitter * (2 * random() - 1))));
}

export function clampHint(ms: number, minMs = MINUTE, maxMs = HOUR): number {
  return Math.min(maxMs, Math.max(minMs, ms));
}
