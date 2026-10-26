import { type Clock, systemClock } from "../core/clock.ts";
import type { Logger } from "../core/log.ts";
import {
  type Change,
  type ControlState,
  DEFAULT_TUNING,
  PathControl,
  type Signal,
  type Tuning,
} from "./control.ts";
import { type Limits, limitsFor } from "./limits.ts";

export type Lane = "transactional" | "bulk";

export type Admission =
  | { kind: "go"; connections: number; release(signal: Signal, reason: string): void }
  | { kind: "requeue"; delayMs: number; reason: string; blocked?: boolean };

interface Waiter {
  lane: Lane;
  settle(a: Admission): void;
  timer: ReturnType<typeof setTimeout> | null;
}

interface Path {
  key: string;
  source: string;
  target: string;
  provider: string | null;
  control: PathControl;
  waiting: { transactional: Waiter[]; bulk: Waiter[] };
  served: number;
  timer: ReturnType<typeof setTimeout> | null;
  sent: number;
  logged: Change | null;
  holdMs: number | null;
  slotAt: number;
}

export interface PathView {
  key: string;
  source: string;
  target: string;
  provider: string | null;
  mode: string;
  until: number | null;
  rate: number;
  connections: number;
  ceiling: Limits;
  inflight: number;
  waiting: { transactional: number; bulk: number };
  sent: number;
  changes: ControlState["changes"];
}

export interface ShaperOptions {
  log: Logger;
  clock?: Clock;
  tuning?: Tuning;
  limits?: (provider: string | null) => Limits;
  bulkEvery?: number;
  onChange?: (key: string, state: ControlState) => void;
  restore?: Map<string, ControlState>;
  slots?: number;
}

const MIN_REQUEUE_MS = 1_000;
const MAX_REQUEUE_MS = 5 * 60_000;
const MAX_SLOT_MS = 60 * 60_000;
const BULK_AHEAD_MS = 1_000;
const HOLD_WEIGHT = 0.2;
const PARALLEL_MARGIN = 1.5;
const SLOW_HOLD_MS = 1_000;
const SLOW_MIN_SHARE = 0.25;
const FAST_RESERVE = 0.25;
const LANES = ["transactional", "bulk"] as const;

export class Shaper {
  readonly #paths = new Map<string, Path>();
  readonly #o: ShaperOptions;
  readonly #clock: Clock;
  readonly #tuning: Tuning;
  readonly #bulkEvery: number;
  #slowHeld = 0;
  #fastHeld = 0;

  constructor(o: ShaperOptions) {
    this.#o = o;
    this.#clock = o.clock ?? systemClock;
    this.#tuning = o.tuning ?? DEFAULT_TUNING;
    this.#bulkEvery = o.bulkEvery ?? 10;
  }

  static key(source: string, target: string): string {
    return `${source}|${target}`;
  }

  #path(source: string, target: string, provider: string | null): Path {
    const key = Shaper.key(source, target);
    let p = this.#paths.get(key);
    if (!p) {
      const now = this.#clock.now();
      const limits = (this.#o.limits ?? limitsFor)(provider);
      const control = new PathControl(limits, now, this.#tuning, this.#o.restore?.get(key));
      p = {
        key,
        source,
        target,
        provider,
        control,
        waiting: { transactional: [], bulk: [] },
        served: 0,
        timer: null,
        sent: 0,
        logged: control.changes.at(-1) ?? null,
        holdMs: null,
        slotAt: 0,
      };
      this.#paths.set(key, p);
    }
    return p;
  }

  #waitingCount(p: Path): number {
    return p.waiting.transactional.length + p.waiting.bulk.length;
  }

  #maxWaiting(p: Path): number {
    return Math.max(20, p.control.connections * 4 + Math.ceil(p.control.rate * 2));
  }

  #hardCap(p: Path): number {
    return this.#maxWaiting(p) * 2;
  }

  #estimate(p: Path, ahead: number): number {
    const ms = Math.round((ahead / p.control.rate) * 1000);
    return Math.min(MAX_REQUEUE_MS, Math.max(MIN_REQUEUE_MS, ms));
  }

  #perSec(p: Path): number {
    const c = p.control;
    if (p.holdMs === null) return c.rate;
    return Math.min(c.rate, (c.connections * 1000) / Math.max(1, p.holdMs));
  }

  #parallel(p: Path): number {
    const c = p.control;
    if (p.holdMs === null) return 1;
    const needed = Math.ceil((c.rate * p.holdMs * PARALLEL_MARGIN) / 1000);
    return Math.max(1, Math.min(c.connections, needed));
  }

  #capped(p: Path): boolean {
    return p.control.mode === "normal" && p.control.inflight >= this.#parallel(p);
  }

  #bulkBudget(p: Path): number {
    const ahead = Math.ceil((this.#perSec(p) * BULK_AHEAD_MS) / 1000);
    return Math.max(2, this.#parallel(p) + ahead);
  }

  #overBudget(p: Path): boolean {
    return p.control.inflight + p.waiting.bulk.length >= this.#bulkBudget(p);
  }

  #slow(p: Path): boolean {
    return p.holdMs !== null && p.holdMs > SLOW_HOLD_MS;
  }

  #slowFull(): boolean {
    const slots = this.#o.slots;
    if (slots === undefined) return false;
    const free = slots - this.#fastHeld - slots * FAST_RESERVE;
    return this.#slowHeld >= Math.max(slots * SLOW_MIN_SHARE, free);
  }

  #nextSlot(p: Path, now: number): number {
    p.slotAt = Math.min(now + MAX_SLOT_MS, Math.max(now, p.slotAt) + 1000 / this.#perSec(p));
    return Math.max(MIN_REQUEUE_MS, Math.round(p.slotAt - now));
  }

  blocked(): { paused: string[]; full: string[] } {
    const now = this.#clock.now();
    const paused: string[] = [];
    const full: string[] = [];
    const slow: string[] = [];
    this.#slowHeld = 0;
    this.#fastHeld = 0;
    for (const p of this.#paths.values()) {
      p.control.tick(now);
      this.#flush(p);
      if (this.#slow(p)) this.#slowHeld += p.control.inflight + p.waiting.bulk.length;
      else this.#fastHeld += p.control.inflight + this.#waitingCount(p);
      if (
        p.control.mode === "paused" ||
        (p.control.mode === "probing" && p.control.probeOut) ||
        this.#waitingCount(p) >= this.#hardCap(p)
      ) {
        paused.push(p.key);
      } else if (this.#waitingCount(p) >= this.#maxWaiting(p) || this.#overBudget(p)) {
        full.push(p.key);
      } else if (this.#slow(p)) {
        slow.push(p.key);
      }
    }
    if (this.#slowFull()) full.push(...slow);
    return { paused, full };
  }

  admit(
    source: string,
    target: string,
    provider: string | null,
    lane: Lane,
    maxWaitMs = 10 * 60_000,
  ): Promise<Admission> {
    const p = this.#path(source, target, provider);
    const now = this.#clock.now();
    p.control.tick(now);
    this.#flush(p);
    const c = p.control;
    if (c.mode === "paused") {
      return Promise.resolve({
        kind: "requeue",
        delayMs: Math.max(MIN_REQUEUE_MS, (c.until ?? now) - now),
        reason: `${p.target} paused`,
        blocked: true,
      });
    }
    if (c.mode === "probing" && (c.probeOut || this.#waitingCount(p) > 0)) {
      return Promise.resolve({
        kind: "requeue",
        delayMs: 30_000,
        reason: `${p.target} probing`,
        blocked: true,
      });
    }
    if (lane === "bulk" && (this.#overBudget(p) || (this.#slow(p) && this.#slowFull()))) {
      return Promise.resolve({
        kind: "requeue",
        delayMs: this.#nextSlot(p, now),
        reason: `${p.target} queue full`,
      });
    }
    const waiting = this.#waitingCount(p);
    if (waiting >= this.#maxWaiting(p)) {
      if (lane === "bulk") {
        return Promise.resolve({
          kind: "requeue",
          delayMs: this.#estimate(p, waiting),
          reason: `${p.target} queue full`,
        });
      }
      if (waiting >= this.#hardCap(p) || p.waiting.bulk.length === 0) {
        if (waiting >= this.#hardCap(p)) {
          return Promise.resolve({
            kind: "requeue",
            delayMs: this.#estimate(p, waiting),
            reason: `${p.target} queue full`,
          });
        }
      } else {
        const evicted = p.waiting.bulk.pop() as Waiter;
        this.#settle(evicted, {
          kind: "requeue",
          delayMs: this.#estimate(p, waiting),
          reason: `${p.target} queue full: transactional email first`,
        });
      }
    }
    if (lane === "bulk" && this.#slow(p)) this.#slowHeld++;
    return new Promise<Admission>((resolve) => {
      const w: Waiter = { lane, settle: resolve, timer: null };
      w.timer = setTimeout(() => {
        const list = p.waiting[lane];
        const i = list.indexOf(w);
        if (i < 0) return;
        list.splice(i, 1);
        this.#settle(w, {
          kind: "requeue",
          delayMs: this.#estimate(p, this.#waitingCount(p)),
          reason: `${p.target} busy`,
        });
      }, maxWaitMs);
      p.waiting[lane].push(w);
      this.#pump(p);
    });
  }

  #settle(w: Waiter, a: Admission) {
    if (w.timer) clearTimeout(w.timer);
    w.timer = null;
    w.settle(a);
  }

  #next(p: Path): Waiter | undefined {
    const t = p.waiting.transactional;
    const b = p.waiting.bulk;
    if (t.length > 0 && b.length > 0) {
      p.served++;
      return p.served % this.#bulkEvery === 0 ? b.shift() : t.shift();
    }
    return t.shift() ?? b.shift();
  }

  #pump(p: Path) {
    const now = this.#clock.now();
    while (this.#waitingCount(p) > 0) {
      const capped = this.#capped(p);
      if (capped && p.waiting.transactional.length === 0) break;
      if (!p.control.tryAcquire(now)) break;
      const w = capped ? p.waiting.transactional.shift() : this.#next(p);
      if (!w) break;
      let released = false;
      this.#settle(w, {
        kind: "go",
        connections: p.control.connections,
        release: (signal, reason) => {
          if (released) return;
          released = true;
          this.#release(p, signal, reason, this.#clock.now() - now);
        },
      });
    }
    this.#flush(p);
    this.#arm(p);
  }

  #arm(p: Path) {
    if (p.timer) clearTimeout(p.timer);
    p.timer = null;
    if (this.#waitingCount(p) === 0) return;
    if (this.#capped(p) && p.waiting.transactional.length === 0) return;
    const now = this.#clock.now();
    const at = p.control.nextChanceAt(now);
    if (at === null) return;
    p.timer = setTimeout(
      () => {
        p.timer = null;
        this.#pump(p);
      },
      Math.max(1, at - now),
    );
  }

  #flush(p: Path) {
    const all = p.control.changes;
    const from = p.logged ? all.indexOf(p.logged) + 1 : 0;
    const fresh = all.slice(from);
    if (fresh.length === 0) return;
    p.logged = all.at(-1) ?? null;
    for (const c of fresh) {
      const level =
        c.what === "paused" || c.what === "probe-failed"
          ? "error"
          : c.what === "halved"
            ? "warn"
            : "info";
      this.#o.log[level](`path ${c.what}`, {
        path: p.key,
        rate: c.rate,
        connections: c.connections,
        reason: c.reason,
      });
    }
    this.#o.onChange?.(p.key, p.control.state());
  }

  #release(p: Path, signal: Signal, reason: string, heldMs: number) {
    if (signal === "success") p.sent++;
    p.holdMs = p.holdMs === null ? heldMs : p.holdMs + (heldMs - p.holdMs) * HOLD_WEIGHT;
    p.control.release(this.#clock.now(), signal, reason);
    this.#flush(p);
    if (p.control.mode === "paused") {
      const delayMs = Math.max(MIN_REQUEUE_MS, (p.control.until ?? 0) - this.#clock.now());
      for (const lane of LANES) {
        for (const w of p.waiting[lane].splice(0)) {
          this.#settle(w, {
            kind: "requeue",
            delayMs,
            reason: `${p.target} paused`,
            blocked: true,
          });
        }
      }
    }
    this.#pump(p);
  }

  pausedUntil(key: string): number | null {
    const p = this.#paths.get(key);
    return p && p.control.mode === "paused" ? p.control.until : null;
  }

  views(): PathView[] {
    const now = this.#clock.now();
    return [...this.#paths.values()].map((p) => {
      p.control.tick(now);
      this.#flush(p);
      return {
        key: p.key,
        source: p.source,
        target: p.target,
        provider: p.provider,
        mode: p.control.mode,
        until: p.control.until,
        rate: Math.round(p.control.rate * 100) / 100,
        connections: p.control.connections,
        ceiling: p.control.ceiling,
        inflight: p.control.inflight,
        waiting: { transactional: p.waiting.transactional.length, bulk: p.waiting.bulk.length },
        sent: p.sent,
        changes: p.control.changes,
      };
    });
  }

  poke() {
    for (const p of this.#paths.values()) this.#pump(p);
  }

  stop() {
    for (const p of this.#paths.values()) {
      if (p.timer) clearTimeout(p.timer);
      p.timer = null;
      for (const lane of LANES) {
        for (const w of p.waiting[lane].splice(0)) {
          this.#settle(w, { kind: "requeue", delayMs: 0, reason: "shutting down" });
        }
      }
    }
  }
}
