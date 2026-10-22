import { type Family, familyOf } from "../dns/ip.ts";
import { type Destination, lookupDestination } from "../dns/mx.ts";
import type { Resolver } from "../dns/resolver.ts";
import type { TlsaData } from "../dns/wire.ts";
import { type Provider, providerOfTargets } from "../routing/providers.ts";
import { mxAllowed, type StsPolicy } from "./mta-sts.ts";
import type { SessionPool } from "./pool.ts";
import {
  type Phase,
  type RecipientResult,
  type RecipientStatus,
  type RequireTlsMode,
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
  connections?: number;
  sts?: StsPolicy | null;
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
  pool?: SessionPool;
  perConnection?: (provider: string | null) => number;
  dane?: boolean;
  relay?: Relay | null;
  requiretls?: RequireTlsMode;
}

export interface Relay {
  host: string;
  port: number;
  implicitTls: boolean;
  username: string | null;
  password: string | null;
}

export interface DeliveryReport {
  domain: string;
  destination: Destination;
  provider: Provider | null;
  policy: TlsPolicy | null;
  sessions: SessionResult[];
  recipients: RecipientResult[];
  mtaSts?: { mode: string; id: string; mx: string[]; maxAge: number } | null | undefined;
  recalled?: boolean | undefined;
}

export function tlsOptional(data: string): boolean {
  const end = data.indexOf("\r\n\r\n");
  const head = end === -1 ? data : data.slice(0, end);
  return /(?:^|\r\n)TLS-Required:[ \t]*No[ \t]*(?:\r\n|$)/i.test(head);
}

export function tlsPolicy(
  requireTls: boolean,
  provider: Provider | null,
  sts: StsPolicy | null = null,
): TlsPolicy {
  if (requireTls) return { rule: "requiretls", required: true };
  if (sts?.mode === "enforce") return { rule: "mta-sts", required: true };
  if (provider?.tlsRequired) return { rule: "provider", required: true };
  return { rule: "opportunistic", required: false };
}

export function allRecipients(
  input: Pick<DeliveryInput, "recipients">,
  status: RecipientStatus,
  enhanced: string,
  reply: string,
  phase: Phase = "dns",
): RecipientResult[] {
  return input.recipients.map((address) => ({
    address,
    status,
    phase,
    code: null,
    enhanced,
    reply,
  }));
}

export async function relayDestination(
  domain: string,
  relay: Relay,
  opts: DeliveryOptions,
): Promise<Destination> {
  const families = opts.families ?? [4];
  const literal = familyOf(relay.host);
  const addresses: { address: string; family: Family }[] = [];
  if (literal) {
    addresses.push({ address: relay.host, family: literal });
  } else {
    for (const family of families) {
      try {
        const a = await opts.resolver.query(relay.host, family === 6 ? "AAAA" : "A");
        for (const r of a.records) {
          if (r.type === "A" || r.type === "AAAA") addresses.push({ address: r.address, family });
        }
      } catch {}
    }
  }
  if (addresses.length === 0) {
    return {
      kind: "defer",
      domain,
      code: "dns-temporary",
      reason: `the relay ${relay.host} has no address`,
    };
  }
  return {
    kind: "targets",
    domain,
    mxHosts: [relay.host],
    implicit: false,
    authenticated: false,
    targets: addresses.map((a) => ({ host: relay.host, preference: 0, ...a })),
    skipped: [],
  };
}

export function findDestination(domain: string, opts: DeliveryOptions): Promise<Destination> {
  if (opts.relay) return relayDestination(domain, opts.relay, opts);
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

  report.provider = providerOfTargets(destination.targets);
  const relay = opts.relay ?? null;
  const requireTls = input.requireTls ?? false;
  const optional = !requireTls && tlsOptional(input.data);
  const sts = relay || optional ? null : (input.sts ?? null);
  const base: TlsPolicy = relay
    ? { rule: "relay", required: true }
    : optional
      ? { rule: "tls-optional", required: false }
      : tlsPolicy(requireTls, report.provider, sts);
  const mode = opts.requiretls ?? "enforce";
  const policy: TlsPolicy = requireTls ? { ...base, requiretls: mode } : base;
  report.policy = policy;
  const secureLookup = (opts.dane === true && destination.authenticated) || sts?.mode === "enforce";
  if (requireTls && mode === "enforce" && !relay && !secureLookup) {
    report.recipients = allRecipients(
      input,
      "bounced",
      "5.7.30",
      `REQUIRETLS: the MX hosts of ${destination.domain} are protected by neither DNSSEC nor an enforced MTA-STS policy`,
      "mail",
    );
    return report;
  }
  report.mtaSts =
    sts && sts.mode !== "none"
      ? { mode: sts.mode, id: sts.id, mx: sts.mx, maxAge: sts.maxAge }
      : null;
  let targets = destination.targets;
  if (sts?.mode === "enforce") {
    targets = targets.filter((t) => mxAllowed(t.host, sts.mx));
    if (targets.length === 0) {
      report.recipients = allRecipients(
        input,
        "deferred",
        "4.7.5",
        `no MX host of ${input.domain} is allowed by its MTA-STS policy (${sts.mx.join(", ")})`,
        "connect",
      );
      return report;
    }
  }
  const maxSessions = opts.maxSessions ?? 2;
  let sessions = 0;

  for (const target of targets) {
    let targetPolicy = policy;
    if (!relay && !optional && opts.dane && destination.authenticated) {
      const dane = await daneFor(opts.resolver, target.host);
      if (dane.kind === "fail") {
        const now = Date.now();
        report.sessions.push({
          host: target.host,
          address: target.address,
          startedAt: now,
          finishedAt: now,
          tls: { status: "none", rule: "dane", version: null, cipher: null, error: null },
          extensions: [],
          phase: "connect",
          error: `DANE: ${dane.reason}`,
          tryNext: true,
          recipients: allRecipients(input, "deferred", "4.7.5", `DANE: ${dane.reason}`, "connect"),
        });
        report.recipients = report.sessions.at(-1)?.recipients ?? [];
        continue;
      }
      if (dane.kind === "tlsa") {
        targetPolicy = {
          rule: "dane",
          required: true,
          tlsa: dane.records,
          ...(policy.requiretls ? { requiretls: policy.requiretls } : {}),
        };
        report.policy = targetPolicy;
      }
    }
    const session = await runSession({
      host: target.host,
      address: target.address,
      port: relay ? relay.port : (opts.port ?? 25),
      ehloName: opts.ehloName,
      policy: targetPolicy,
      ...(relay?.implicitTls ? { implicitTls: true } : {}),
      ...(relay?.username && relay.password !== null
        ? { auth: { username: relay.username, password: relay.password } }
        : {}),
      from: input.from,
      recipients: input.recipients,
      data: input.data,
      smtpUtf8: input.smtpUtf8,
      ...(opts.localAddress ? { localAddress: opts.localAddress } : {}),
      ...(opts.timeouts ? { timeouts: opts.timeouts } : {}),
      ...(opts.tlsCa ? { tlsCa: opts.tlsCa } : {}),
      ...(targetPolicy.rule === "dane"
        ? {
            names: [...new Set([target.host, input.domain, destination.canonical ?? input.domain])],
          }
        : {}),
      ...(opts.pool
        ? {
            pool: opts.pool,
            perConnection: opts.perConnection?.(report.provider?.id ?? null) ?? 100,
            ...(input.connections !== undefined ? { maxOpen: input.connections } : {}),
          }
        : {}),
    });
    report.sessions.push(session);
    report.recipients = session.recipients;
    if (!session.tryNext) break;
    if (session.phase !== "connect" && ++sessions >= maxSessions) break;
  }
  return report;
}

type DaneLookup =
  | { kind: "none" }
  | { kind: "tlsa"; records: TlsaData[] }
  | { kind: "fail"; reason: string };

async function daneFor(resolver: Resolver, host: string): Promise<DaneLookup> {
  let answer: Awaited<ReturnType<Resolver["query"]>>;
  try {
    answer = await resolver.query(`_25._tcp.${host}`, "TLSA");
  } catch (err) {
    return { kind: "fail", reason: `TLSA lookup for ${host} failed: ${(err as Error).message}` };
  }
  if (answer.rcode === 2) {
    const why = answer.bogus ? `DNSSEC: ${answer.bogus}` : "SERVFAIL";
    return { kind: "fail", reason: `TLSA lookup for ${host} failed (${why})` };
  }
  if (!answer.authenticated) return { kind: "none" };
  const records = answer.records.flatMap((r) => (r.type === "TLSA" ? [r.tlsa] : []));
  return records.length ? { kind: "tlsa", records } : { kind: "none" };
}
