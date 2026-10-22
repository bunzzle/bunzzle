import type { Logger } from "../core/log.ts";
import { encodeSpans, type Span } from "./otlp.ts";

export type Post = (
  path: "/v1/traces" | "/v1/metrics",
  body: string,
) => Promise<{ ok: true; status: number } | { ok: false; error: string }>;

export const MAX_QUEUE = 4_096;
export const BATCH = 512;

export class SpanExporter {
  #queue: Span[] = [];
  #dropped = 0;
  #sending = false;
  #warnedAt = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly instance: string,
    private readonly post: Post,
    private readonly log: Logger,
    private readonly now: () => number = Date.now,
  ) {}

  add(spans: Span[]): void {
    this.#queue.push(...spans);
    const over = this.#queue.length - MAX_QUEUE;
    if (over > 0) {
      this.#queue.splice(0, over);
      this.#dropped += over;
    }
    if (this.#queue.length >= BATCH) void this.flush();
  }

  get queued(): number {
    return this.#queue.length;
  }

  async flush(): Promise<void> {
    if (this.#sending) return;
    this.#sending = true;
    try {
      while (this.#queue.length > 0) {
        const batch = this.#queue.splice(0, BATCH);
        const r = await this.post("/v1/traces", encodeSpans(this.instance, batch));
        const problem = !r.ok ? r.error : r.status >= 300 ? `answered ${r.status}` : null;
        if (problem) {
          this.#dropped += batch.length;
          this.warn("could not export traces", problem);
          break;
        }
      }
    } finally {
      this.#sending = false;
    }
  }

  warn(message: string, error: string): void {
    const t = this.now();
    if (t - this.#warnedAt < 60_000) return;
    this.#warnedAt = t;
    this.log.warn(message, { error, dropped: this.#dropped });
    this.#dropped = 0;
  }
}
