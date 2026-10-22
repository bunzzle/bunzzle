import type { Family } from "../metrics/metrics.ts";
import { b } from "../validate/schema.ts";
import { VERSION } from "../version.ts";

export type AttrValue = string | number | boolean;
export type Attrs = Record<string, AttrValue | null | undefined>;

export const SPAN_INTERNAL = 1;
export const SPAN_SERVER = 2;
export const SPAN_CLIENT = 3;

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string | undefined;
  name: string;
  kind: number;
  start: number;
  end: number;
  attributes: Attrs;
  error?: string | null | undefined;
  links?: { traceId: string; spanId: string }[] | undefined;
}

const UUID = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i;

export function traceIdOf(messageId: string): string {
  const m = UUID.exec(messageId);
  if (m) return m.slice(1).join("").toLowerCase();
  return new Bun.CryptoHasher("sha256").update(messageId).digest("hex").slice(0, 32);
}

export const newSpanId = () => crypto.getRandomValues(new Uint8Array(8)).toHex();

export function parseTraceparent(value: string | null | undefined) {
  const m = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/.exec(value?.trim() ?? "");
  if (!m || /^0+$/.test(m[1] as string) || /^0+$/.test(m[2] as string)) return null;
  return { traceId: m[1] as string, spanId: m[2] as string };
}

const nanos = (ms: number) => `${BigInt(Math.round(ms * 1_000)) * 1_000n}`;

function attributes(a: Attrs) {
  const out: { key: string; value: Record<string, unknown> }[] = [];
  for (const [key, v] of Object.entries(a)) {
    if (v === null || v === undefined) continue;
    const value =
      typeof v === "string"
        ? { stringValue: v }
        : typeof v === "boolean"
          ? { boolValue: v }
          : Number.isInteger(v)
            ? { intValue: String(v) }
            : { doubleValue: v };
    out.push({ key, value });
  }
  return out;
}

export function resource(instance: string) {
  return {
    attributes: attributes({
      "service.name": "bunzzle",
      "service.version": VERSION,
      "service.instance.id": instance,
    }),
  };
}

const SCOPE = { name: "bunzzle", version: VERSION };

export function encodeSpans(instance: string, spans: Span[]): string {
  return JSON.stringify({
    resourceSpans: [
      {
        resource: resource(instance),
        scopeSpans: [
          {
            scope: SCOPE,
            spans: spans.map((s) => ({
              traceId: s.traceId,
              spanId: s.spanId,
              ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
              name: s.name,
              kind: s.kind,
              startTimeUnixNano: nanos(s.start),
              endTimeUnixNano: nanos(Math.max(s.start, s.end)),
              attributes: attributes(s.attributes),
              ...(s.links?.length ? { links: s.links } : {}),
              status: s.error ? { code: 2, message: s.error } : { code: 1 },
            })),
          },
        ],
      },
    ],
  });
}

export function encodeMetrics(
  instance: string,
  families: Family[],
  now: number,
  startedAt: number,
): string {
  const time = nanos(now);
  const start = nanos(startedAt);
  const metrics = families.map((f) => {
    const points = (counter: boolean) =>
      f.samples.map((s) => ({
        attributes: attributes(s.labels),
        ...(counter ? { startTimeUnixNano: start } : {}),
        timeUnixNano: time,
        asDouble: f.type === "info" ? 1 : Number.isFinite(s.value) ? s.value : 0,
      }));
    return f.type === "counter"
      ? {
          name: f.name,
          description: f.help,
          sum: { aggregationTemporality: 2, isMonotonic: true, dataPoints: points(true) },
        }
      : { name: f.name, description: f.help, gauge: { dataPoints: points(false) } };
  });
  return JSON.stringify({
    resourceMetrics: [{ resource: resource(instance), scopeMetrics: [{ scope: SCOPE, metrics }] }],
  });
}

const hex = (n: number) => b.string().regex(new RegExp(`^[0-9a-f]{${n}}$`));

export const spanWire = b.object({
  traceId: hex(32),
  spanId: hex(16),
  parentSpanId: hex(16).optional(),
  name: b.string().max(200),
  kind: b.number().int().min(0).max(5),
  start: b.number(),
  end: b.number(),
  attributes: b.record(
    b.string().max(200),
    b
      .union([b.string().max(2000), b.number(), b.boolean()])
      .nullable()
      .optional(),
  ),
  error: b.string().max(2000).nullable().optional(),
  links: b
    .array(b.object({ traceId: hex(32), spanId: hex(16) }))
    .max(10)
    .optional(),
});

export function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of text.split(/[,\n]/)) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (!/^[A-Za-z0-9-]+$/.test(name)) continue;
    const value = part.slice(eq + 1).trim();
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}
