import { startSmtpServer } from "../smtpd/server.ts";

export interface InboundHandlers {
  recipient(address: string): Promise<boolean>;
  message(recipients: string[], raw: string): Promise<"ok" | "retry" | "reject">;
}

export interface InboundOptions {
  hostname: string;
  port: number;
  name: string;
  handlers: InboundHandlers;
  maxSize?: number;
  maxRecipients?: number;
  idleMs?: number;
  tls?: { cert: string; key: string } | null;
}

export function startInboundServer(o: InboundOptions): { port: number; stop(): void } {
  return startSmtpServer({
    hostname: o.hostname,
    port: o.port,
    name: o.name,
    banner: "ESMTP Bunzzle (bounces and feedback only)",
    tls: o.tls ?? null,
    maxSize: o.maxSize ?? 1024 * 1024,
    maxRecipients: o.maxRecipients ?? 10,
    idleMs: o.idleMs ?? 60_000,
    maxConnectionsPerIp: 50,
    hooks: {
      recipient: async (address) =>
        (await o.handlers.recipient(address))
          ? null
          : { code: 550, text: "5.1.1 No such recipient here" },
      message: async (recipients, raw) => {
        const r = await o.handlers.message(recipients, raw);
        if (r === "ok") return { code: 250, text: "2.0.0 Ok: received" };
        if (r === "reject") return { code: 550, text: "5.6.0 Message not accepted" };
        return { code: 451, text: "4.3.0 Try again later" };
      },
    },
  });
}
