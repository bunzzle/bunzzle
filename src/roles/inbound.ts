import { z } from "zod";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { DmarcError, readDmarcReport } from "../dmarc/report.ts";
import { classifyReport, type Report } from "../inbound/parse.ts";
import { startInboundServer } from "../inbound/server.ts";
import { RpcClient, RpcError } from "../ipc/rpc.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

async function loadTls(config: Config): Promise<{ cert: string; key: string } | null> {
  const { inboundTlsCertFile: certFile, inboundTlsKeyFile: keyFile } = config;
  if (!certFile && !keyFile) return null;
  if (!certFile || !keyFile) {
    throw new Error(
      "set both BUNZZLE_INBOUND_TLS_CERT_FILE and BUNZZLE_INBOUND_TLS_KEY_FILE, or neither",
    );
  }
  const cert = await Bun.file(certFile).text();
  const key = await Bun.file(keyFile).text();
  if (!cert.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(`${certFile} is not a PEM certificate`);
  }
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) {
    throw new Error(`${keyFile} is not a PEM private key`);
  }
  return { cert, key };
}

export async function runInbound(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).core);
  const port = config.inboundPort;
  const tls = port === null ? null : await loadTls(config);
  const server =
    port === null
      ? null
      : startInboundServer({
          hostname: config.inboundHost,
          port,
          name: config.inboundHostname ?? "bunzzle",
          tls,
          handlers: {
            recipient: async (address) =>
              (
                await core.call(
                  "inboundRecipient",
                  { address },
                  { result: z.object({ accept: z.boolean() }), timeoutMs: 10_000 },
                )
              ).accept,
            message: async (recipients, raw) => {
              if (recipients.some((r) => /^dmarc@/i.test(r))) {
                try {
                  const dmarc = await readDmarcReport(raw);
                  await core.call(
                    "inboundDmarc",
                    { recipients, report: dmarc },
                    { timeoutMs: 30_000 },
                  );
                  return "ok";
                } catch (err) {
                  if (err instanceof DmarcError) {
                    log.warn("unreadable DMARC report", { error: err.message });
                    return "reject";
                  }
                  if (err instanceof RpcError && err.code === "invalid") return "reject";
                  log.warn("could not hand a DMARC report to core", {
                    error: (err as Error).message,
                  });
                  return "retry";
                }
              }
              let report: Report;
              try {
                report = classifyReport(raw);
              } catch {
                report = { kind: "unknown", ref: null };
              }
              try {
                await core.call(
                  "inboundReport",
                  { recipients, report, raw },
                  { timeoutMs: 30_000 },
                );
                return "ok";
              } catch (err) {
                if (err instanceof RpcError && err.code === "invalid") return "reject";
                log.warn("could not hand a report to core", { error: (err as Error).message });
                return "retry";
              }
            },
          },
        });
  const idle = server ? null : setInterval(() => {}, 1 << 30);
  onStop(log, () => {
    server?.stop();
    if (idle) clearInterval(idle);
    core.close();
  });
  if (server) log.info("inbound listening", { port: server.port, starttls: tls !== null });
  ready(server ? { port: server.port } : {});
}
