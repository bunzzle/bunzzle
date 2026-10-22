import type { DeliverRequest } from "../delivery/transport.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";
import { newSpanId, SPAN_CLIENT, type Span, traceIdOf } from "./otlp.ts";

export function deliverySpans(
  req: DeliverRequest,
  report: DeliveryReport,
  start: number,
  end: number,
): Span[] {
  const traceId = traceIdOf(req.messageId);
  const spanId = newSpanId();
  const count = (status: string) => report.recipients.filter((r) => r.status === status).length;
  const failed = report.recipients.find((r) => r.status !== "delivered");
  const sessions: Span[] = report.sessions.map((s) => ({
    traceId,
    spanId: newSpanId(),
    parentSpanId: spanId,
    name: "smtp.session",
    kind: SPAN_CLIENT,
    start: s.startedAt,
    end: s.finishedAt,
    attributes: {
      "server.address": s.host,
      "network.peer.address": s.address,
      "tls.protocol.version": s.tls.version ?? null,
      "bunzzle.smtp.phase": s.phase,
      "bunzzle.smtp.reused": s.reused ?? false,
      "bunzzle.smtp.try_next": s.tryNext,
    },
    error: s.error,
  }));
  return [
    {
      traceId,
      spanId,
      name: "email.deliver",
      kind: SPAN_CLIENT,
      start,
      end,
      attributes: {
        "bunzzle.email.id": req.messageId,
        "bunzzle.domain": req.domain,
        "bunzzle.lane": req.lane ?? "transactional",
        "bunzzle.provider": report.provider?.id ?? null,
        "bunzzle.source": req.source ?? null,
        "bunzzle.via": req.via ?? null,
        "bunzzle.tls.policy": report.policy?.rule ?? null,
        "bunzzle.recipients": report.recipients.length,
        "bunzzle.delivered": count("delivered"),
        "bunzzle.deferred": count("deferred"),
        "bunzzle.bounced": count("bounced"),
      },
      error:
        failed && count("delivered") === 0
          ? `${failed.status}: ${failed.reply}`.slice(0, 500)
          : null,
    },
    ...sessions,
  ];
}
