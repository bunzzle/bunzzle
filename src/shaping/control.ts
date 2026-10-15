import type { Limits } from "./limits.ts";

export type Mode = "normal" | "held" | "paused" | "probing";
export type Signal = "success" | "rate" | "reputation" | "neutral";

export interface Change {
  at: number;
  what: "halved" | "climbed" | "paused" | "probing" | "probe-ok" | "probe-failed" | "resumed";
  reason: string;
  rate: number;
  connections: number;
}

export interface Tuning {
  holdMs: number;
  firstPauseMs: number;
  maxPauseMs: number;
  climbEvery: number;
  ignoreRepeatMs: number;
}

export const DEFAULT_TUNING: Tuning = {
  holdMs: 15 * 60_000,
  firstPauseMs: 15 * 60_000,
  maxPauseMs: 4 * 3_600_000,
  climbEvery: 20,
  ignoreRepeatMs: 10_000,
};

export interface ControlState {
  rate: number;
  connections: number;
  mode: Mode;
  until: number | null;
  pauseMs: number;
  changes: Change[];
}

const MAX_CHANGES = 20;

export class PathControl {
  readonly ceiling: Limits;
  readonly tuning: Tuning;
  rate: number;
  connections: number;
  mode: Mode = "normal";
  until: number | null = null;
  pauseMs: number;
  inflight = 0;
  probeOut = false;
  changes: Change[] = [];
  #streak = 0;
  #tokens: number;
  #refilledAt: number;
  #lastDecrease = Number.NEGATIVE_INFINITY;
  #connLimited = false;
  #rateLimited = false;

  constructor(ceiling: Limits, now: number, tuning: Tuning = DEFAULT_TUNING, state?: ControlState) {
    this.ceiling = ceiling;
    this.tuning = tuning;
    this.rate = state?.rate ?? ceiling.ratePerSec;
    this.connections = state?.connections ?? ceiling.connections;
    this.mode = state?.mode ?? "normal";
    this.until = state?.until ?? null;
    this.pauseMs = state?.pauseMs ?? tuning.firstPauseMs;
    this.changes = state?.changes ?? [];
    if (this.mode === "probing") this.mode = "paused";
    this.#tokens = Math.max(1, Math.min(this.rate, this.connections));
    this.#refilledAt = now;
  }

  get floorRate(): number {
    return Math.max(0.2, this.ceiling.ratePerSec / 20);
  }

  state(): ControlState {
    return {
      rate: this.rate,
      connections: this.connections,
      mode: this.mode,
      until: this.until,
      pauseMs: this.pauseMs,
      changes: this.changes,
    };
  }

  #change(now: number, what: Change["what"], reason: string) {
    this.changes = [
      ...this.changes,
      { at: now, what, reason, rate: round(this.rate), connections: this.connections },
    ].slice(-MAX_CHANGES);
  }

  tick(now: number) {
    if (this.mode === "held" && this.until !== null && now >= this.until) {
      this.mode = "normal";
      this.until = null;
    }
    if (this.mode === "paused" && this.until !== null && now >= this.until) {
      this.mode = "probing";
      this.until = null;
      this.probeOut = false;
      this.#change(now, "probing", "pause over: sending one probe email");
    }
    const burst = Math.max(1, Math.min(this.rate, this.connections));
    this.#tokens = Math.min(burst, this.#tokens + ((now - this.#refilledAt) / 1000) * this.rate);
    this.#refilledAt = now;
  }

  tryAcquire(now: number): boolean {
    this.tick(now);
    if (this.mode === "paused") return false;
    if (this.mode === "probing") {
      if (this.probeOut || this.inflight > 0) return false;
      this.probeOut = true;
      this.inflight++;
      return true;
    }
    if (this.inflight >= this.connections) {
      this.#connLimited = true;
      return false;
    }
    if (this.#tokens < 1) {
      this.#rateLimited = true;
      return false;
    }
    this.#tokens -= 1;
    this.inflight++;
    return true;
  }

  nextChanceAt(now: number): number | null {
    this.tick(now);
    if (this.mode === "paused") return this.until;
    if (this.mode === "probing") return this.probeOut ? null : now;
    if (this.inflight >= this.connections) return null;
    if (this.#tokens >= 1) return now;
    return now + Math.ceil(((1 - this.#tokens) / this.rate) * 1000);
  }

  release(now: number, signal: Signal, reason: string) {
    this.inflight = Math.max(0, this.inflight - 1);
    this.tick(now);
    if (this.mode === "probing") {
      this.probeOut = false;
      if (signal === "success") {
        this.mode = "normal";
        this.until = null;
        this.rate = this.floorRate;
        this.connections = 1;
        this.pauseMs = this.tuning.firstPauseMs;
        this.#streak = 0;
        this.#change(now, "probe-ok", "probe delivered: restarting slowly");
      } else if (signal === "reputation" || signal === "rate") {
        this.#pause(now, reason, "probe-failed");
      }
      return;
    }
    switch (signal) {
      case "success":
        this.#streak++;
        if (this.#streak >= this.tuning.climbEvery && this.mode === "normal") {
          this.#streak = 0;
          const rate = this.#rateLimited
            ? Math.min(this.ceiling.ratePerSec, Math.max(this.rate * 1.25, this.rate + 0.5))
            : this.rate;
          const connections = this.#connLimited
            ? Math.min(this.ceiling.connections, this.connections + 1)
            : this.connections;
          this.#rateLimited = false;
          this.#connLimited = false;
          if (rate !== this.rate || connections !== this.connections) {
            this.rate = rate;
            this.connections = connections;
            this.#change(now, "climbed", `${this.tuning.climbEvery} deliveries without throttling`);
          }
        }
        return;
      case "rate":
        this.#streak = 0;
        if (now - this.#lastDecrease < this.tuning.ignoreRepeatMs) return;
        this.#lastDecrease = now;
        this.rate = Math.max(this.floorRate, this.rate / 2);
        this.connections = Math.max(1, Math.floor(this.connections / 2));
        this.#tokens = Math.min(this.#tokens, 1);
        if (this.mode !== "paused") {
          this.mode = "held";
          this.until = now + this.tuning.holdMs;
        }
        this.#change(now, "halved", reason);
        return;
      case "reputation":
        this.#streak = 0;
        if (this.mode === "paused") return;
        this.#pause(now, reason, "paused");
        return;
      case "neutral":
        return;
    }
  }

  #pause(now: number, reason: string, what: "paused" | "probe-failed") {
    this.mode = "paused";
    this.until = now + this.pauseMs;
    this.#change(now, what, reason);
    this.pauseMs = Math.min(this.tuning.maxPauseMs, this.pauseMs * 2);
  }
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
