import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import type { Family } from "../metrics/metrics.ts";
import { MAX_QUEUE } from "../otel/exporter.ts";
import {
  type Attrs,
  encodeMetrics,
  newSpanId,
  parseTraceparent,
  SPAN_SERVER,
  type Span,
  traceIdOf,
} from "../otel/otlp.ts";
import { every } from "./runtime.ts";

export interface TelemetryDeps {
  delivery: RpcClient;
  log: Logger;
  instance: string;
  metricsIntervalMs: number;
  families: () => Family[];
  startedAt: number;
  now?: () => number;
}

export function intakeSpan(
  id: string | null,
  start: number,
  end: number,
  attributes: Attrs,
  error: string | null,
  traceparent: string | undefined,
): Span {
  const caller = parseTraceparent(traceparent);
  return {
    traceId: id ? traceIdOf(id) : crypto.getRandomValues(new Uint8Array(16)).toHex(),
    spanId: newSpanId(),
    name: "email.intake",
    kind: SPAN_SERVER,
    start,
    end,
    attributes: { "bunzzle.email.id": id, ...attributes },
    error,
    ...(caller ? { links: [caller] } : {}),
  };
}

export function telemetry(deps: TelemetryDeps) {
  const now = deps.now ?? Date.now;
  let pending: Span[] = [];
  let warnedAt = Number.NEGATIVE_INFINITY;
  const warn = (message: string, err: unknown) => {
    if (now() - warnedAt < 60_000) return;
    warnedAt = now();
    deps.log.warn(message, { error: (err as Error).message });
  };

  const flush = async () => {
    if (pending.length === 0) return;
    const spans = pending;
    pending = [];
    try {
      await deps.delivery.call("exportSpans", { spans }, { timeoutMs: 10_000 });
    } catch (err) {
      warn("could not hand traces to delivery", err);
    }
  };

  const pushMetrics = async () => {
    try {
      const body = encodeMetrics(deps.instance, deps.families(), now(), deps.startedAt);
      await deps.delivery.call("exportMetrics", { body }, { timeoutMs: 30_000 });
    } catch (err) {
      warn("could not hand metrics to delivery", err);
    }
  };

  const stopFlush = every(5_000, flush);
  const stopMetrics = every(deps.metricsIntervalMs, pushMetrics);

  return {
    record(span: Span) {
      if (pending.length < MAX_QUEUE) pending.push(span);
    },
    async stop() {
      stopFlush();
      stopMetrics();
      await flush();
    },
  };
}
