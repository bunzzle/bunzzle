import type { Family } from "../dns/ip.ts";
import { type Destination, lookupDestination } from "../dns/mx.ts";
import type { Resolver } from "../dns/resolver.ts";
import { type Provider, providerOf } from "../routing/providers.ts";
import {
  type RecipientResult,
  type RecipientStatus,
  runSession,
  type SessionResult,
  type Timeouts,
  type TlsPolicy,
} from "./session.ts";

export interface DeliveryInput {
  domain: string;
  from: string;
  recipients: string[];
  data: string;
  smtpUtf8: boolean;
  requireTls?: boolean;
}

export interface DeliveryOptions {
  resolver: Resolver;
  ehloName: string;
  localAddress?: string;
  port?: number;
  families?: Family[];
  allowPrivate?: boolean;
  ownAddresses?: string[];
  maxSessions?: number;
  timeouts?: Partial<Timeouts>;
  tlsCa?: string;
}

export interface DeliveryReport {
  domain: string;
  destination: Destination;
  provider: Provider | null;
  policy: TlsPolicy | null;
  sessions: SessionResult[];
  recipients: RecipientResult[];
}

export function tlsPolicy(requireTls: boolean, provider: Provider | null): TlsPolicy {
  if (requireTls) return { rule: "requiretls", required: true };
  if (provider?.tlsRequired) return { rule: "provider", required: true };
  return { rule: "opportunistic", required: false };
}

function allRecipients(
  input: DeliveryInput,
  status: RecipientStatus,
  enhanced: string,
  reply: string,
): RecipientResult[] {
  return input.recipients.map((address) => ({
    address,
    status,
    phase: "dns",
    code: null,
    enhanced,
    reply,
  }));
}

export function findDestination(domain: string, opts: DeliveryOptions): Promise<Destination> {
  return lookupDestination(domain, {
    resolver: opts.resolver,
    ...(opts.families ? { families: opts.families } : {}),
    ...(opts.allowPrivate ? { allowPrivate: true } : {}),
    ...(opts.ownAddresses ? { ownAddresses: opts.ownAddresses } : {}),
  });
}

export async function deliver(
  input: DeliveryInput,
  opts: DeliveryOptions,
): Promise<DeliveryReport> {
  return deliverTo(await findDestination(input.domain, opts), input, opts);
}

export async function deliverTo(
  destination: Destination,
  input: DeliveryInput,
  opts: DeliveryOptions,
): Promise<DeliveryReport> {
  const report: DeliveryReport = {
    domain: destination.domain,
    destination,
    provider: null,
    policy: null,
    sessions: [],
    recipients: [],
  };

  if (destination.kind === "fail") {
    report.recipients = allRecipients(input, "bounced", destination.code, destination.reason);
    return report;
  }
  if (destination.kind === "defer") {
    report.recipients = allRecipients(input, "deferred", "4.4.3", destination.reason);
    return report;
  }

  report.provider = providerOf(destination.mxHosts[0] ?? "");
  const policy = tlsPolicy(input.requireTls ?? false, report.provider);
  report.policy = policy;
  const maxSessions = opts.maxSessions ?? 2;
  let sessions = 0;

  for (const target of destination.targets) {
    const session = await runSession({
      host: target.host,
      address: target.address,
      port: opts.port ?? 25,
      ehloName: opts.ehloName,
      policy,
      from: input.from,
      recipients: input.recipients,
      data: input.data,
      smtpUtf8: input.smtpUtf8,
      ...(opts.localAddress ? { localAddress: opts.localAddress } : {}),
      ...(opts.timeouts ? { timeouts: opts.timeouts } : {}),
      ...(opts.tlsCa ? { tlsCa: opts.tlsCa } : {}),
    });
    report.sessions.push(session);
    report.recipients = session.recipients;
    if (!session.tryNext) break;
    if (session.phase !== "connect" && ++sessions >= maxSessions) break;
  }
  return report;
}
