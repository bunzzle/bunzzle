export interface RetryPolicy {
  maxAttempts: number;
  maxAgeMs: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

export const defaultRetryPolicy: RetryPolicy = {
  maxAttempts: 12,
  maxAgeMs: 24 * 60 * 60 * 1000,
  baseDelayMs: 5_000,
  maxDelayMs: 15 * 60 * 1000,
};

export function backoff(policy: RetryPolicy, attempt: number, random = Math.random): number {
  const cap = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** attempt);
  return Math.floor(random() * cap);
}
