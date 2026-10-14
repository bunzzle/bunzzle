import type { Database } from "bun:sqlite";
import { type Clock, systemClock } from "../core/clock.ts";
import {
  type ClaimedJob,
  claim,
  expireLeases,
  nextWakeAt,
  recoverAfterCrash,
  resendUnresolved,
  type Settled,
  settle,
} from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import type { Outcome } from "../core/outcome.ts";
import { defaultRetryPolicy, type RetryPolicy } from "../core/retry.ts";
import type { Writer } from "../core/store/writer.ts";

export type JobHandler = (job: ClaimedJob, signal: AbortSignal) => Promise<Outcome>;

export interface SchedulerOptions {
  db: Database;
  writer: Writer;
  handle: JobHandler;
  log: Logger;
  clock?: Clock;
  concurrency?: number;
  leaseMs?: number;
  reconcileMs?: number;
  retry?: RetryPolicy;
  sweepMs?: number;
  random?: () => number;
}

export type SchedulerStats = Record<Settled | "claimed", number>;

export class Scheduler {
  readonly #o: Required<Omit<SchedulerOptions, "random">> & { random?: () => number };
  #running = false;
  #pumping = false;
  #again = false;
  #inFlight = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #unsubscribe: (() => void) | undefined;
  #idle: PromiseWithResolvers<void> | undefined;
  readonly stats: SchedulerStats = { claimed: 0, done: 0, dead: 0, retry: 0, unknown: 0, stale: 0 };

  constructor(opts: SchedulerOptions) {
    this.#o = {
      clock: systemClock,
      concurrency: 64,
      leaseMs: 60_000,
      reconcileMs: 15 * 60_000,
      retry: defaultRetryPolicy,
      sweepMs: 1_000,
      ...opts,
    };
  }

  get inFlight(): number {
    return this.#inFlight;
  }

  async start(): Promise<void> {
    if (this.#running) return;
    const { writer, clock, reconcileMs, log } = this.#o;
    const recovered = await writer.run((db) => recoverAfterCrash(db, clock.now(), reconcileMs));
    if (recovered > 0) log.warn("leases from a previous run marked unknown", { jobs: recovered });
    this.#running = true;
    this.#unsubscribe = writer.onCommit(() => this.wake());
    this.wake();
  }

  async stop(): Promise<void> {
    this.#running = false;
    clearTimeout(this.#timer);
    this.#unsubscribe?.();
    if (this.#inFlight === 0) return;
    this.#idle = Promise.withResolvers<void>();
    await this.#idle.promise;
  }

  wake(): void {
    if (!this.#running) return;
    if (this.#pumping) {
      this.#again = true;
      return;
    }
    void this.#pump();
  }

  async #pump(): Promise<void> {
    this.#pumping = true;
    const { writer, clock, concurrency, leaseMs, log } = this.#o;
    try {
      do {
        this.#again = false;
        const free = concurrency - this.#inFlight;
        if (free <= 0) break;
        const jobs = await writer.run((db) => claim(db, clock.now(), free, leaseMs), {
          quiet: true,
        });
        this.stats.claimed += jobs.length;
        for (const job of jobs) this.#runJob(job);
        if (jobs.length === free) this.#again = true;
      } while (this.#again && this.#running);
    } catch (err) {
      log.error("claim failed", { error: (err as Error).message });
    } finally {
      this.#pumping = false;
      this.#arm();
    }
  }

  #arm(): void {
    clearTimeout(this.#timer);
    if (!this.#running) return;
    const { clock, sweepMs, db } = this.#o;
    const now = clock.now();
    const next = nextWakeAt(db) ?? Number.POSITIVE_INFINITY;
    const delay = Math.max(0, Math.min(next - now, sweepMs));
    this.#timer = setTimeout(() => void this.#sweep(), delay);
  }

  async #sweep(): Promise<void> {
    if (!this.#running) return;
    const { writer, clock, reconcileMs, log } = this.#o;
    try {
      const [expired, resent] = await writer.run((db) => {
        const now = clock.now();
        return [expireLeases(db, now, reconcileMs), resendUnresolved(db, now)] as const;
      });
      if (expired > 0) log.warn("leases expired", { jobs: expired });
      if (resent > 0) log.warn("resending unresolved jobs (duplicate risk)", { jobs: resent });
    } catch (err) {
      log.error("sweep failed", { error: (err as Error).message });
    }
    this.wake();
  }

  #runJob(job: ClaimedJob): void {
    this.#inFlight++;
    const { handle, writer, clock, leaseMs, reconcileMs, retry, random, log } = this.#o;
    const signal = AbortSignal.timeout(Math.max(1, Math.floor(leaseMs * 0.9)));

    void (async () => {
      let outcome: Outcome;
      try {
        outcome = await handle(job, signal);
      } catch (err) {
        outcome = { kind: "unknown", reason: `handler threw: ${(err as Error)?.message ?? err}` };
      }
      try {
        const result = await writer.run((db) =>
          settle(db, job, outcome, clock.now(), {
            retry,
            reconcileMs,
            ...(random ? { random } : {}),
          }),
        );
        this.stats[result]++;
      } catch (err) {
        log.error("could not record outcome", { job: job.id, error: (err as Error).message });
      }
    })().finally(() => {
      this.#inFlight--;
      if (this.#inFlight === 0) this.#idle?.resolve();
      this.wake();
    });
  }
}
