import type { EpochPublicKey, SealedBody } from "../crypto/envelope.ts";
import type { DeliverRequest } from "../delivery/transport.ts";
import type { Destination } from "../dns/mx.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";
import { b } from "../validate/schema.ts";

export const ROLES = ["signer", "dns", "core", "delivery", "api", "inbound"] as const;
export type Role = (typeof ROLES)[number];

export function sockets(runDir: string) {
  return {
    core: `${runDir}/core.sock`,
    signer: `${runDir}/signer.sock`,
    delivery: `${runDir}/delivery.sock`,
    dns: `${runDir}/dns.sock`,
  };
}

const b64 = b.string().regex(/^[A-Za-z0-9+/]*={0,2}$/);

export const sealedBodyWire = b.object({
  epoch: b.number().int().nonnegative(),
  wrapped: b64,
  body: b64,
});
export type SealedBodyWire = b.infer<typeof sealedBodyWire>;

export const toWire = (b: SealedBody): SealedBodyWire => ({
  epoch: b.epoch,
  wrapped: b.wrapped.toBase64(),
  body: b.body.toBase64(),
});

export const fromWire = (b: SealedBodyWire): SealedBody => ({
  epoch: b.epoch,
  wrapped: Uint8Array.fromBase64(b.wrapped),
  body: Uint8Array.fromBase64(b.body),
});

export const epochKeyWire = b.object({ epoch: b.number().int(), publicKey: b64 });

export const epochKeyFromWire = (k: b.infer<typeof epochKeyWire>): EpochPublicKey => ({
  epoch: k.epoch,
  publicKey: Uint8Array.fromBase64(k.publicKey),
});

const host = b.string().max(255);
const text = b.string().max(4096);

export const destinationWire: b.Schema<Destination> = b.discriminatedUnion("kind", [
  b.object({
    kind: b.literal("targets"),
    domain: host,
    mxHosts: b.array(host).max(64),
    implicit: b.boolean(),
    authenticated: b.boolean(),
    targets: b
      .array(
        b.object({
          host,
          preference: b.number().int(),
          address: b.string().max(64),
          family: b.union([b.literal(4), b.literal(6)]),
        }),
      )
      .max(64),
    skipped: b.array(b.object({ host, address: b.string().max(64), reason: text })).max(256),
  }),
  b.object({ kind: b.literal("fail"), domain: host, code: b.string().max(16), reason: text }),
  b.object({
    kind: b.literal("defer"),
    domain: host,
    code: b.enum(["nxdomain", "dns-temporary"]),
    reason: text,
  }),
]);

const phase = b.enum([
  "dns",
  "connect",
  "greeting",
  "ehlo",
  "starttls",
  "mail",
  "rcpt",
  "data",
  "dot",
]);
const tlsRule = b.enum(["requiretls", "mta-sts", "provider", "opportunistic"]);
const recipient = b.object({
  address: b.string().max(320),
  status: b.enum(["delivered", "deferred", "bounced", "unknown"]),
  phase,
  code: b.number().int().min(200).max(599).nullable(),
  enhanced: b
    .string()
    .regex(/^[245]\.\d{1,3}\.\d{1,3}$/)
    .nullable(),
  reply: text,
});

export const deliveryReportWire: b.Schema<DeliveryReport> = b.object({
  domain: host,
  destination: destinationWire,
  provider: b
    .object({ id: b.string().max(64), name: b.string().max(128), tlsRequired: b.boolean() })
    .nullable(),
  policy: b.object({ rule: tlsRule, required: b.boolean() }).nullable(),
  sessions: b
    .array(
      b.object({
        host,
        address: b.string().max(64),
        startedAt: b.number(),
        finishedAt: b.number(),
        tls: b.object({
          status: b.enum(["none", "unverified", "verified"]),
          rule: tlsRule,
          version: b.string().max(32).nullable(),
          cipher: b.string().max(128).nullable(),
          error: text.nullable(),
        }),
        extensions: b.array(b.string().max(64)).max(64),
        phase: b.union([phase, b.literal("done")]),
        error: text.nullable(),
        tryNext: b.boolean(),
        recipients: b.array(recipient).max(1000),
        reused: b.boolean().optional(),
      }),
    )
    .max(16),
  recipients: b.array(recipient).max(1000),
  recalled: b.boolean().optional(),
  mtaSts: b
    .object({ mode: b.string().max(10), id: b.string().max(32) })
    .nullable()
    .optional(),
});

export const deliverRequestWire = b.object({
  key: b.string().min(1).max(200),
  recall: b.string().min(1).max(200).nullable(),
  messageId: b.string().min(1).max(64),
  domain: host,
  destination: destinationWire,
  from: b.string().max(320),
  recipients: b.array(b.string().max(320)).min(1).max(1000),
  smtpUtf8: b.boolean(),
  requireTls: b.boolean(),
  body: sealedBodyWire,
  connections: b.number().int().min(1).max(1000).optional(),
  settled: b.array(b.string().min(1).max(200)).max(5000).optional(),
  lane: b.enum(["transactional", "bulk"]).optional(),
  bounceDomain: b.string().max(253).nullable().optional(),
  source: b.string().max(64).optional(),
});

export const requestToWire = (r: DeliverRequest) => ({ ...r, body: toWire(r.body) });
export const requestFromWire = (r: b.infer<typeof deliverRequestWire>): DeliverRequest => ({
  ...r,
  body: fromWire(r.body),
});

export const MESSAGE_ID = /^[A-Za-z0-9._-]{1,64}$/;

export const TOKEN_HASH = /^[0-9a-f]{64}$/;
export const tokenHash = b.string().regex(TOKEN_HASH).optional();
export const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

export const emailMeta = b.object({
  from: b.string().max(1000),
  to: b.array(b.string().max(320)).max(1000),
  cc: b.array(b.string().max(320)).max(1000),
  bcc: b.array(b.string().max(320)).max(1000),
  replyTo: b.array(b.string().max(320)).max(50),
  tags: b.array(b.object({ name: b.string().max(256), value: b.string().max(256) })).max(50),
  lane: b.enum(["transactional", "bulk"]).optional(),
});

export const enqueueParams = b.object({
  tokenHash,
  idempotencyKey: b.string().min(1).max(256).optional(),
  bodyHash: b.string().regex(TOKEN_HASH).optional(),
  scheduledAt: b.number().int().positive().optional(),
  meta: emailMeta.optional(),
  id: b.string().regex(MESSAGE_ID).optional(),
  from: b.string().min(3).max(320),
  recipients: b.array(b.string().min(3).max(320)).min(1).max(1000),
  data: b
    .string()
    .min(1)
    .max(40 * 1024 * 1024),
  smtpUtf8: b.boolean().default(false),
  requireTls: b.boolean().default(false),
  expiresAt: b.number().int().positive().optional(),
  priority: b.number().int().min(0).max(9).optional(),
});
export type EnqueueParams = b.input<typeof enqueueParams>;

export const enqueueResult = b.object({ id: b.string(), existed: b.boolean() });

const ref = b.string().max(100).nullable();
export const reportWire = b.discriminatedUnion("kind", [
  b.object({
    kind: b.literal("dsn"),
    ref,
    recipients: b
      .array(
        b.object({
          address: b.string().max(320),
          action: b.string().max(40),
          status: b.string().max(20).nullable(),
          diagnostic: b.string().max(2000).nullable(),
          remoteMta: b.string().max(255).nullable(),
        }),
      )
      .max(100),
  }),
  b.object({
    kind: b.literal("arf"),
    ref,
    feedbackType: b.string().max(40),
    originalRcpt: b.string().max(320).nullable(),
  }),
  b.object({ kind: b.literal("auto-reply"), ref }),
  b.object({
    kind: b.literal("bounce"),
    ref,
    status: b.string().max(20).nullable(),
    diagnostic: b.string().max(2000),
    addresses: b.array(b.string().max(320)).max(50),
  }),
  b.object({ kind: b.literal("unknown"), ref }),
]);

export const dmarcWire = b.object({
  org: b.string().max(200),
  email: b.string().max(320).nullable(),
  reportId: b.string().max(200),
  begin: b.number().int().nonnegative(),
  end: b.number().int().nonnegative(),
  domain: b.string().max(253),
  policy: b.string().max(20),
  rows: b
    .array(
      b.object({
        sourceIp: b.string().max(64),
        count: b.number().int().nonnegative(),
        disposition: b.string().max(20),
        dkim: b.string().max(20),
        spf: b.string().max(20),
        headerFrom: b.string().max(253),
        envelopeFrom: b.string().max(253).nullable(),
        dkimDomains: b.array(b.string().max(253)).max(10),
        spfDomain: b.string().max(253).nullable(),
      }),
    )
    .max(10_000),
});
