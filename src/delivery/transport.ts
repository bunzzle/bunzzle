import type { SealedBody } from "../crypto/envelope.ts";
import type { Destination } from "../dns/mx.ts";
import {
  allRecipients,
  type DeliveryOptions,
  type DeliveryReport,
  deliverTo,
  findDestination,
} from "../smtp/deliver.ts";

export interface DeliverRequest {
  key: string;
  recall: string | null;
  messageId: string;
  domain: string;
  destination: Destination;
  from: string;
  recipients: string[];
  smtpUtf8: boolean;
  requireTls: boolean;
  body: SealedBody;
  connections?: number | undefined;
}

export interface DeliveryTransport {
  lookup(domain: string): Promise<Destination>;
  deliver(req: DeliverRequest): Promise<DeliveryReport>;
}

export type OpenBody = (messageId: string, body: SealedBody) => Promise<string>;

function unprepared(req: DeliverRequest, err: unknown): DeliveryReport {
  const code = (err as { code?: unknown })?.code;
  const message = (err as Error)?.message ?? String(err);
  const gone = code === "epoch-gone" || code === "unreadable";
  return {
    domain: req.domain,
    destination: req.destination,
    provider: null,
    policy: null,
    sessions: [],
    recipients: allRecipients(
      req,
      gone ? "bounced" : "deferred",
      gone ? "5.6.6" : "4.3.5",
      `could not prepare the message: ${message}`,
      "connect",
    ),
  };
}

export interface RememberOptions {
  maxEntries?: number;
  ttlMs?: number;
  now?: () => number;
}

export function rememberingTransport(
  inner: DeliveryTransport,
  o: RememberOptions = {},
): DeliveryTransport {
  const maxEntries = o.maxEntries ?? 50_000;
  const ttlMs = o.ttlMs ?? 2 * 3_600_000;
  const now = o.now ?? Date.now;
  const memory = new Map<string, { at: number; report: Promise<DeliveryReport> }>();
  const remember = (key: string, report: Promise<DeliveryReport>) => {
    memory.delete(key);
    memory.set(key, { at: now(), report });
    report.catch(() => memory.delete(key));
    while (memory.size > maxEntries) {
      const oldest = memory.keys().next().value;
      if (oldest === undefined) break;
      memory.delete(oldest);
    }
  };
  return {
    lookup: (domain) => inner.lookup(domain),
    async deliver(req) {
      if (req.recall) {
        const prev = memory.get(req.recall);
        if (prev && now() - prev.at <= ttlMs) {
          const report = await prev.report.catch(() => null);
          if (report && !report.recipients.some((r) => r.status === "unknown")) {
            remember(req.key, prev.report);
            return { ...report, recalled: true };
          }
        }
      }
      const report = inner.deliver(req);
      remember(req.key, report);
      return report;
    },
  };
}

export function localTransport(opts: DeliveryOptions, open: OpenBody): DeliveryTransport {
  return {
    lookup: (domain) => findDestination(domain, opts),
    async deliver(req) {
      let data: string;
      try {
        data = await open(req.messageId, req.body);
      } catch (err) {
        return unprepared(req, err);
      }
      return deliverTo(
        req.destination,
        {
          domain: req.domain,
          from: req.from,
          recipients: req.recipients,
          data,
          smtpUtf8: req.smtpUtf8,
          requireTls: req.requireTls,
          ...(req.connections !== undefined ? { connections: req.connections } : {}),
        },
        opts,
      );
    },
  };
}
