import type { SealedBody } from "../crypto/envelope.ts";
import type { Destination } from "../dns/mx.ts";
import {
  allRecipients,
  type DeliveryOptions,
  type DeliveryReport,
  deliverTo,
  findDestination,
} from "../smtp/deliver.ts";
import type { StsPolicy } from "../smtp/mta-sts.ts";

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
  lane?: "transactional" | "bulk" | undefined;
  bounceDomain?: string | null | undefined;
  source?: string | undefined;
  settled?: string[] | undefined;
}

export interface DeliveryTransport {
  lookup(domain: string): Promise<Destination>;
  deliver(req: DeliverRequest): Promise<DeliveryReport>;
  forget?(keys: string[]): void;
}

export interface OpenedBody {
  data: string;
  bounceToken: string;
}

export type OpenBody = (
  messageId: string,
  body: SealedBody,
  o: { lane: "transactional" | "bulk"; bounceDomain: string | null },
) => Promise<OpenedBody>;

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
): DeliveryTransport & { forget(keys: string[]): void; readonly remembered: number } {
  const maxEntries = o.maxEntries ?? 50_000;
  const ttlMs = o.ttlMs ?? 2 * 3_600_000;
  const now = o.now ?? Date.now;
  const memory = new Map<string, { at: number; report: Promise<DeliveryReport> }>();
  const expire = () => {
    const cutoff = now() - ttlMs;
    for (const [key, entry] of memory) {
      if (entry.at > cutoff && memory.size <= maxEntries) break;
      memory.delete(key);
    }
  };
  const remember = (key: string, report: Promise<DeliveryReport>) => {
    memory.delete(key);
    memory.set(key, { at: now(), report });
    report.catch(() => memory.delete(key));
    expire();
  };
  const forget = (keys: string[]) => {
    for (const key of keys) memory.delete(key);
    expire();
  };
  return {
    lookup: (domain) => inner.lookup(domain),
    forget,
    get remembered() {
      return memory.size;
    },
    async deliver(req) {
      if (req.settled?.length) forget(req.settled);
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

export interface LocalOptions extends DeliveryOptions {
  sts?: (domain: string) => Promise<StsPolicy | null>;
  sources?: string[];
  ehloFor?: (source: string) => string;
}

function forSource(opts: LocalOptions, source: string | undefined): DeliveryOptions | string {
  if (!source || source === "default") return opts;
  if (!opts.sources?.includes(source)) return `source IP ${source} is not configured here`;
  return { ...opts, localAddress: source, ehloName: opts.ehloFor?.(source) ?? opts.ehloName };
}

export function localTransport(opts: LocalOptions, open: OpenBody): DeliveryTransport {
  return {
    lookup: (domain) => findDestination(domain, opts),
    async deliver(req) {
      const o = forSource(opts, req.source);
      if (typeof o === "string") return unprepared(req, new Error(o));
      let opened: OpenedBody;
      try {
        opened = await open(req.messageId, req.body, {
          lane: req.lane ?? "transactional",
          bounceDomain: req.bounceDomain ?? null,
        });
      } catch (err) {
        return unprepared(req, err);
      }
      const from = req.bounceDomain ? `b-${opened.bounceToken}@${req.bounceDomain}` : req.from;
      const data = opened.data;
      return deliverTo(
        req.destination,
        {
          domain: req.domain,
          from,
          recipients: req.recipients,
          data,
          smtpUtf8: req.smtpUtf8,
          requireTls: req.requireTls,
          ...(req.connections !== undefined ? { connections: req.connections } : {}),
          sts: req.destination.kind === "targets" ? ((await opts.sts?.(req.domain)) ?? null) : null,
        },
        o,
      );
    },
  };
}
