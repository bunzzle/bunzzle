import { describe, expect, test } from "bun:test";
import type { Logger } from "../../src/core/log.ts";
import type { DeliverRequest } from "../../src/delivery/transport.ts";
import { deliverySpans } from "../../src/otel/delivery-spans.ts";
import { BATCH, MAX_QUEUE, SpanExporter } from "../../src/otel/exporter.ts";
import {
  encodeMetrics,
  encodeSpans,
  parseHeaders,
  parseTraceparent,
  type Span,
  traceIdOf,
} from "../../src/otel/otlp.ts";
import { intakeSpan } from "../../src/roles/core-telemetry.ts";
import type { DeliveryReport } from "../../src/smtp/deliver.ts";

const span = (n = 0): Span => ({
  traceId: "0".repeat(31) + (n % 10),
  spanId: "1".repeat(16),
  name: "email.intake",
  kind: 2,
  start: 1_700_000_000_123.5,
  end: 1_700_000_000_200,
  attributes: { "bunzzle.recipients": 2, rate: 0.5, ok: true, skip: null, s: "x" },
});

const warnings: unknown[] = [];
const log = { warn: (...a: unknown[]) => warnings.push(a) } as unknown as Logger;

describe("OTLP encoding", () => {
  test("a UUID email id is its trace id; other ids are hashed", () => {
    expect(traceIdOf("0193a3b2-7c1d-7e00-8000-0123456789ab")).toBe(
      "0193a3b27c1d7e0080000123456789ab",
    );
    const custom = traceIdOf("order-42");
    expect(custom).toMatch(/^[0-9a-f]{32}$/);
    expect(traceIdOf("order-42")).toBe(custom);
  });

  test("traceparent is read only when valid", () => {
    const t = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    expect(parseTraceparent(t)).toEqual({
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
    });
    expect(parseTraceparent(`00-${"0".repeat(32)}-00f067aa0ba902b7-01`)).toBeNull();
    expect(parseTraceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")).toBeNull();
    expect(parseTraceparent("garbage")).toBeNull();
    expect(parseTraceparent(undefined)).toBeNull();
  });

  test("spans use nanosecond strings, typed attributes and a status", () => {
    const body = JSON.parse(encodeSpans("out.test", [{ ...span(), error: "invalid: bad" }]));
    const rs = body.resourceSpans[0];
    expect(rs.resource.attributes).toContainEqual({
      key: "service.name",
      value: { stringValue: "bunzzle" },
    });
    const s = rs.scopeSpans[0].spans[0];
    expect(s.startTimeUnixNano).toBe("1700000000123500000");
    expect(s.endTimeUnixNano).toBe("1700000000200000000");
    expect(s.attributes).toEqual([
      { key: "bunzzle.recipients", value: { intValue: "2" } },
      { key: "rate", value: { doubleValue: 0.5 } },
      { key: "ok", value: { boolValue: true } },
      { key: "s", value: { stringValue: "x" } },
    ]);
    expect(s.status).toEqual({ code: 2, message: "invalid: bad" });
    expect(
      JSON.parse(encodeSpans("x", [span()])).resourceSpans[0].scopeSpans[0].spans[0].status,
    ).toEqual({ code: 1 });
  });

  test("counters are cumulative monotonic sums, gauges and info are gauges", () => {
    const body = JSON.parse(
      encodeMetrics(
        "x",
        [
          { name: "a", type: "counter", help: "A", samples: [{ labels: { k: "v" }, value: 3 }] },
          { name: "b", type: "gauge", help: "B", samples: [{ labels: {}, value: Number.NaN }] },
          { name: "c", type: "info", help: "C", samples: [{ labels: { version: "1" }, value: 0 }] },
        ],
        2_000,
        1_000,
      ),
    );
    const [a, g, c] = body.resourceMetrics[0].scopeMetrics[0].metrics;
    expect(a.sum).toEqual({
      aggregationTemporality: 2,
      isMonotonic: true,
      dataPoints: [
        {
          attributes: [{ key: "k", value: { stringValue: "v" } }],
          startTimeUnixNano: "1000000000",
          timeUnixNano: "2000000000",
          asDouble: 3,
        },
      ],
    });
    expect(g.gauge.dataPoints[0].asDouble).toBe(0);
    expect(c.gauge.dataPoints[0].asDouble).toBe(1);
  });

  test("headers file uses name=value pairs", () => {
    expect(parseHeaders("Authorization=Bearer%20abc,x-team = mail\nbad header=1\n=x")).toEqual({
      Authorization: "Bearer abc",
      "x-team": "mail",
    });
  });

  test("intake spans link to the caller's span", () => {
    const s = intakeSpan(
      "0193a3b2-7c1d-7e00-8000-0123456789ab",
      1,
      2,
      { "bunzzle.recipients": 1 },
      null,
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    );
    expect(s.traceId).toBe("0193a3b27c1d7e0080000123456789ab");
    expect(s.links).toEqual([
      { traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "00f067aa0ba902b7" },
    ]);
    expect(intakeSpan(null, 1, 2, {}, "invalid: x", undefined).traceId).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("delivery spans", () => {
  test("one span per attempt with a child per SMTP session", () => {
    const req = {
      messageId: "0193a3b2-7c1d-7e00-8000-0123456789ab",
      domain: "example.test",
      lane: "bulk",
    } as DeliverRequest;
    const report = {
      domain: "example.test",
      provider: { id: "gmail" },
      policy: { rule: "mta-sts", required: true },
      sessions: [
        {
          host: "mx1.example.test",
          address: "192.0.2.1",
          startedAt: 10,
          finishedAt: 20,
          tls: { version: "TLSv1.3" },
          phase: "connect",
          error: "connection refused",
          tryNext: true,
          recipients: [],
        },
        {
          host: "mx2.example.test",
          address: "192.0.2.2",
          startedAt: 20,
          finishedAt: 40,
          tls: { version: "TLSv1.3" },
          phase: "done",
          error: null,
          tryNext: false,
          recipients: [],
          reused: true,
        },
      ],
      recipients: [
        { address: "a@example.test", status: "delivered", reply: "250 ok" },
        { address: "b@example.test", status: "bounced", reply: "550 no such user" },
      ],
    } as unknown as DeliveryReport;
    const [top, s1, s2] = deliverySpans(req, report, 5, 45);
    expect(top?.traceId).toBe("0193a3b27c1d7e0080000123456789ab");
    expect(top?.attributes).toMatchObject({
      "bunzzle.domain": "example.test",
      "bunzzle.lane": "bulk",
      "bunzzle.provider": "gmail",
      "bunzzle.tls.policy": "mta-sts",
      "bunzzle.delivered": 1,
      "bunzzle.bounced": 1,
    });
    expect(top?.error).toBeNull();
    expect(s1?.parentSpanId).toBe(top?.spanId);
    expect(s1?.error).toBe("connection refused");
    expect(s2?.attributes).toMatchObject({
      "server.address": "mx2.example.test",
      "network.peer.address": "192.0.2.2",
      "tls.protocol.version": "TLSv1.3",
      "bunzzle.smtp.reused": true,
    });
    const failed = deliverySpans(
      req,
      { ...report, recipients: [report.recipients[1]] } as DeliveryReport,
      5,
      45,
    );
    expect(failed[0]?.error).toBe("bounced: 550 no such user");
  });
});

describe("span exporter", () => {
  test("sends in batches, drops the oldest when full, warns once a minute", async () => {
    const sent: number[] = [];
    let fail = false;
    let t = 0;
    const exporter = new SpanExporter(
      "x",
      async (_path, body) => {
        sent.push(JSON.parse(body).resourceSpans[0].scopeSpans[0].spans.length);
        return fail ? { ok: false, error: "refused" } : { ok: true, status: 200 };
      },
      log,
      () => t,
    );
    exporter.add(Array.from({ length: BATCH + 10 }, (_, i) => span(i)));
    await exporter.flush();
    expect(sent).toEqual([BATCH, 10]);
    fail = true;
    exporter.add(Array.from({ length: MAX_QUEUE + 5 }, (_, i) => span(i)));
    expect(exporter.queued).toBe(MAX_QUEUE);
    await exporter.flush();
    await exporter.flush();
    expect(warnings).toHaveLength(1);
    t = 61_000;
    await exporter.flush();
    expect(warnings).toHaveLength(2);
  });
});
