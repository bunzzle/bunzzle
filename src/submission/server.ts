import { allows, hashToken, TOKEN } from "../accounts/api-keys.ts";
import type { Logger } from "../core/log.ts";
import { authResult, Buckets } from "../http/app.ts";
import { type RpcClient, RpcError } from "../ipc/rpc.ts";
import { type AddressError, normalizeAddress } from "../mime/address.ts";
import {
  DEFAULT_BLOCKING,
  type SmtpReply,
  type SmtpSession,
  startSmtpServer,
} from "../smtpd/server.ts";
import { b } from "../validate/schema.ts";
import { prepareSubmitted, SubmitError } from "./prepare.ts";

export interface SubmissionOptions {
  core: RpcClient;
  log: Logger;
  hostname: string;
  port: number;
  name: string;
  tls: { cert: string; key: string };
  implicitTls: boolean;
  maxSize?: number;
}

interface Sender {
  hash: string;
  id: string;
  domains: string[] | null;
  rateLimit: number;
}

const enqueued = b.object({ id: b.string(), existed: b.boolean() });

function fromRpc(err: unknown): SmtpReply {
  if (err instanceof RpcError) {
    switch (err.code) {
      case "invalid":
        return { code: 550, text: `5.6.0 ${err.message}` };
      case "unverified-domain":
      case "forbidden":
        return { code: 550, text: `5.7.1 ${err.message}` };
      case "unauthenticated":
        return { code: 530, text: "5.7.0 The API key is no longer valid" };
      case "held":
        return { code: 450, text: `4.7.1 ${err.message}` };
    }
  }
  return { code: 451, text: "4.3.0 Bunzzle is busy, try again later" };
}

export function startSubmission(o: SubmissionOptions): { port: number; stop(): void } {
  const buckets = new Buckets();
  const server = startSmtpServer({
    hostname: o.hostname,
    port: o.port,
    name: o.name,
    banner: "ESMTP Bunzzle submission",
    tls: o.tls,
    implicitTls: o.implicitTls,
    requireTls: true,
    requireAuth: true,
    utf8: true,
    maxSize: o.maxSize ?? 40 * 1024 * 1024,
    maxRecipients: 100,
    maxMessages: 100,
    maxConnectionsPerIp: 20,
    idleMs: 5 * 60_000,
    authFailures: { max: 10, windowMs: 15 * 60_000 },
    blocking: DEFAULT_BLOCKING,
    hooks: {
      auth: async (password, session) => {
        const token = password.trim();
        if (!TOKEN.test(token)) return null;
        const hash = hashToken(token);
        try {
          const key = await o.core.call(
            "authenticate",
            { tokenHash: hash },
            { result: authResult, timeoutMs: 5_000 },
          );
          if (!allows(key.scope, "send")) return null;
          o.log.info("submission login", { key: key.id, remote: session.remote });
          return {
            hash,
            id: key.id,
            domains: key.domains,
            rateLimit: key.rateLimit,
          } satisfies Sender;
        } catch (err) {
          if (err instanceof RpcError && err.code === "unauthenticated") return null;
          throw err;
        }
      },
      recipient: async (address) => {
        try {
          normalizeAddress(address);
          return null;
        } catch (err) {
          return { code: 550, text: `5.1.3 ${(err as AddressError).message}` };
        }
      },
      message: async (recipients, raw, session: SmtpSession) => {
        const sender = session.user as Sender;
        if (!buckets.take(sender.id, sender.rateLimit, Date.now()).ok) {
          return {
            code: 451,
            text: `4.7.1 Rate limit: this API key may send ${sender.rateLimit} emails per second`,
          };
        }
        let email: ReturnType<typeof prepareSubmitted>;
        try {
          email = prepareSubmitted(raw, recipients, new Date());
        } catch (err) {
          if (err instanceof SubmitError) return { code: err.code, text: err.text };
          throw err;
        }
        if (sender.domains && !sender.domains.includes(email.fromDomain)) {
          return { code: 550, text: `5.7.1 This API key cannot send from ${email.fromDomain}` };
        }
        try {
          const r = await o.core.call(
            "enqueue",
            {
              tokenHash: sender.hash,
              from: email.from,
              recipients: email.recipients,
              data: email.data,
              smtpUtf8: email.smtpUtf8 || session.utf8,
              requireTls: false,
              priority: 0,
              meta: email.meta,
            },
            { result: enqueued, timeoutMs: 30_000 },
          );
          return { code: 250, text: `2.0.0 Ok: queued as ${r.id}` };
        } catch (err) {
          return fromRpc(err);
        }
      },
    },
  });
  o.log.info("submission listening", { port: server.port, implicitTls: o.implicitTls });
  return server;
}
