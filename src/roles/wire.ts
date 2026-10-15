import { z } from "zod";
import type { EpochPublicKey, SealedBody } from "../crypto/envelope.ts";
import type { DeliverRequest } from "../delivery/transport.ts";
import type { Destination } from "../dns/mx.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";

export const ROLES = ["signer", "core", "delivery", "api", "inbound"] as const;
export type Role = (typeof ROLES)[number];

export function sockets(runDir: string) {
  return {
    core: `${runDir}/core.sock`,
    signer: `${runDir}/signer.sock`,
    delivery: `${runDir}/delivery.sock`,
  };
}

const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/);

export const sealedBodyWire = z.object({
  epoch: z.number().int().nonnegative(),
  wrapped: b64,
  body: b64,
});
export type SealedBodyWire = z.infer<typeof sealedBodyWire>;

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

export const epochKeyWire = z.object({ epoch: z.number().int(), publicKey: b64 });

export const epochKeyFromWire = (k: z.infer<typeof epochKeyWire>): EpochPublicKey => ({
  epoch: k.epoch,
  publicKey: Uint8Array.fromBase64(k.publicKey),
});

const host = z.string().max(255);
const text = z.string().max(4096);

export const destinationWire: z.ZodType<Destination> = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("targets"),
    domain: host,
    mxHosts: z.array(host).max(64),
    implicit: z.boolean(),
    authenticated: z.boolean(),
    targets: z
      .array(
        z.object({
          host,
          preference: z.number().int(),
          address: z.string().max(64),
          family: z.union([z.literal(4), z.literal(6)]),
        }),
      )
      .max(64),
    skipped: z.array(z.object({ host, address: z.string().max(64), reason: text })).max(256),
  }),
  z.object({ kind: z.literal("fail"), domain: host, code: z.string().max(16), reason: text }),
  z.object({
    kind: z.literal("defer"),
    domain: host,
    code: z.enum(["nxdomain", "dns-temporary"]),
    reason: text,
  }),
]);

const phase = z.enum([
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
const tlsRule = z.enum(["requiretls", "provider", "opportunistic"]);
const recipient = z.object({
  address: z.string().max(320),
  status: z.enum(["delivered", "deferred", "bounced", "unknown"]),
  phase,
  code: z.number().int().min(200).max(599).nullable(),
  enhanced: z
    .string()
    .regex(/^[245]\.\d{1,3}\.\d{1,3}$/)
    .nullable(),
  reply: text,
});

export const deliveryReportWire: z.ZodType<DeliveryReport> = z.object({
  domain: host,
  destination: destinationWire,
  provider: z
    .object({ id: z.string().max(64), name: z.string().max(128), tlsRequired: z.boolean() })
    .nullable(),
  policy: z.object({ rule: tlsRule, required: z.boolean() }).nullable(),
  sessions: z
    .array(
      z.object({
        host,
        address: z.string().max(64),
        startedAt: z.number(),
        finishedAt: z.number(),
        tls: z.object({
          status: z.enum(["none", "unverified", "verified"]),
          rule: tlsRule,
          version: z.string().max(32).nullable(),
          cipher: z.string().max(128).nullable(),
          error: text.nullable(),
        }),
        extensions: z.array(z.string().max(64)).max(64),
        phase: z.union([phase, z.literal("done")]),
        error: text.nullable(),
        tryNext: z.boolean(),
        recipients: z.array(recipient).max(1000),
      }),
    )
    .max(16),
  recipients: z.array(recipient).max(1000),
  recalled: z.boolean().optional(),
});

export const deliverRequestWire = z.object({
  key: z.string().min(1).max(200),
  recall: z.string().min(1).max(200).nullable(),
  messageId: z.string().min(1).max(64),
  domain: host,
  destination: destinationWire,
  from: z.string().max(320),
  recipients: z.array(z.string().max(320)).min(1).max(1000),
  smtpUtf8: z.boolean(),
  requireTls: z.boolean(),
  body: sealedBodyWire,
});

export const requestToWire = (r: DeliverRequest) => ({ ...r, body: toWire(r.body) });
export const requestFromWire = (r: z.infer<typeof deliverRequestWire>): DeliverRequest => ({
  ...r,
  body: fromWire(r.body),
});

export const MESSAGE_ID = /^[A-Za-z0-9._-]{1,64}$/;

export const enqueueParams = z.object({
  id: z.string().regex(MESSAGE_ID).optional(),
  from: z.string().min(3).max(320),
  recipients: z.array(z.string().min(3).max(320)).min(1).max(1000),
  data: z
    .string()
    .min(1)
    .max(40 * 1024 * 1024),
  smtpUtf8: z.boolean().default(false),
  requireTls: z.boolean().default(false),
  expiresAt: z.number().int().positive().optional(),
  priority: z.number().int().min(0).max(9).optional(),
});
export type EnqueueParams = z.input<typeof enqueueParams>;

export const enqueueResult = z.object({ id: z.string(), existed: z.boolean() });
