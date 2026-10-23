import type { DeliveryReport } from "../smtp/deliver.ts";
import type { DeliverRequest } from "./transport.ts";

export function unprepared(req: DeliverRequest, err: unknown): DeliveryReport {
  const code = (err as { code?: unknown })?.code;
  const message = (err as Error)?.message ?? String(err);
  const gone = code === "epoch-gone" || code === "unreadable";
  return {
    domain: req.domain,
    destination: req.destination,
    provider: null,
    policy: null,
    sessions: [],
    recipients: req.recipients.map((address) => ({
      address,
      status: gone ? "bounced" : "deferred",
      phase: "connect",
      code: null,
      enhanced: gone ? "5.6.6" : "4.3.5",
      reply: `could not prepare the message: ${message}`,
    })),
  };
}
