import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { DmarcError, readDmarcReport } from "../dmarc/report.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, dnsServers } from "../dns/resolver.ts";
import { type AuthResults, checkAuth, refusal } from "../inbound/auth.ts";
import { classifyReport, type Report } from "../inbound/parse.ts";
import { buildPayload } from "../inbound/payload.ts";
import { ROUTE_FORMATS } from "../inbound/routes.ts";
import { startInboundServer } from "../inbound/server.ts";
import { RpcClient, RpcError } from "../ipc/rpc.ts";
import { blocklists } from "../ips/blocklists.ts";
import { MimeParseError } from "../mime/parse.ts";
import { b } from "../validate/schema.ts";
import { onStop, ready, watchFile } from "./runtime.ts";
import { sockets } from "./wire.ts";

async function loadTls(config: Config): Promise<{ cert: string; key: string } | null> {
  const { inboundTlsCertFile: certFile, inboundTlsKeyFile: keyFile } = config;
  if (!certFile && !keyFile) return null;
  if (!certFile || !keyFile) {
    throw new Error(
      "set both BUNZZLE_INBOUND_TLS_CERT_FILE and BUNZZLE_INBOUND_TLS_KEY_FILE, or neither",
    );
  }
  if (config.acme && !(await Bun.file(certFile).exists())) return null;
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

const routesResult = b.object({
  routes: b.array(
    b.object({
      id: b.string(),
      format: b.enum(ROUTE_FORMATS),
      recipients: b.array(b.string()),
    }),
  ),
  rest: b.array(b.string()),
  scan: b.boolean(),
});

const scanResult = b.union([
  b.object({ result: b.literal("ok"), score: b.number().nullable() }),
  b.object({ result: b.literal("refused") }),
  b.object({ result: b.literal("failed") }),
]);

export async function runInbound(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).coreInbound);
  const port = config.inboundPort;
  const tls = port === null ? null : await loadTls(config);
  const servers = await dnsServers(config.dnsServers);
  const resolver = cachingResolver(createResolver({ servers }));
  const lists = blocklists(null).filter((l) => config.inboundBlocklists.includes(l.id));
  const server =
    port === null
      ? null
      : startInboundServer({
          hostname: config.inboundHost,
          port,
          name: config.inboundHostname ?? "bunzzle",
          tls,
          maxSize: config.inboundMaxSize,
          handlers: {
            recipient: async (address) =>
              (
                await core.call(
                  "inboundRecipient",
                  { address },
                  { result: b.object({ accept: b.boolean() }), timeoutMs: 10_000 },
                )
              ).accept,
            message: async (all, raw, meta) => {
              let recipients: string[];
              try {
                const split = await core.call(
                  "inboundRoutes",
                  { recipients: all },
                  { result: routesResult, timeoutMs: 10_000 },
                );
                let auth: AuthResults | null = null;
                if (split.routes.length > 0) {
                  auth = await checkAuth(
                    resolver,
                    raw,
                    { ip: meta.remote, mailFrom: meta.from, helo: meta.helo },
                    lists,
                  );
                  const refused = refusal(auth, config.inboundRefuse, meta.remote);
                  if (refused) {
                    log.info("refused a message for a route", {
                      reply: `${refused.code} ${refused.text}`,
                    });
                    return refused;
                  }
                }
                let spamScore: number | null = null;
                if (split.scan) {
                  const scanned = await core.call(
                    "inboundScan",
                    {
                      raw,
                      from: meta.from,
                      recipients: split.routes.flatMap((r) => r.recipients),
                      ip: meta.remote,
                      helo: meta.helo,
                    },
                    { result: scanResult, timeoutMs: 120_000 },
                  );
                  if (scanned.result === "refused") {
                    return { code: 550, text: "5.7.1 Message refused by the content check" };
                  }
                  if (scanned.result === "failed") {
                    return {
                      code: 451,
                      text: "4.7.1 Content check not available, try again later",
                    };
                  }
                  spamScore = scanned.score;
                }
                for (const r of split.routes) {
                  const id = Bun.randomUUIDv7();
                  const payload = buildPayload(
                    raw,
                    {
                      id,
                      receivedAt: Date.now(),
                      mailFrom: meta.from,
                      rcptTo: r.recipients,
                      remoteIp: meta.remote,
                      tls: meta.tls,
                      auth,
                      spamScore,
                    },
                    r.format,
                  );
                  await core.call(
                    "inboundRouted",
                    { routeId: r.id, id, payload },
                    { timeoutMs: 60_000 },
                  );
                }
                if (split.rest.length === 0) return "ok";
                recipients = split.rest;
              } catch (err) {
                if (err instanceof MimeParseError) {
                  log.warn("unreadable message for a route", { error: err.message });
                  return "reject";
                }
                if (err instanceof RpcError && err.code === "invalid") return "reject";
                log.warn("could not hand a message to core", { error: (err as Error).message });
                return "retry";
              }
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
  const restart = onStop(log, () => {
    server?.stop();
    if (idle) clearInterval(idle);
    core.close();
  });
  if (server && config.acme && config.inboundTlsCertFile) {
    await watchFile(config.inboundTlsCertFile, 10 * 60_000, () => {
      log.info("new TLS certificate: restarting to load it");
      void restart("new certificate");
    });
  }
  if (server) log.info("inbound listening", { port: server.port, starttls: tls !== null });
  ready(server ? { port: server.port } : {});
}
