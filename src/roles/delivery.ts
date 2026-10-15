import { z } from "zod";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { localTransport, rememberingTransport } from "../delivery/transport.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, systemServers } from "../dns/resolver.ts";
import { method, RpcClient, serveRpc } from "../ipc/rpc.ts";
import { limitsFor } from "../shaping/limits.ts";
import { allRecipients } from "../smtp/deliver.ts";
import { SessionPool } from "../smtp/pool.ts";
import { onStop, ready } from "./runtime.ts";
import { deliverRequestWire, requestFromWire, sockets, toWire } from "./wire.ts";

export async function runDelivery(config: Config, log: Logger) {
  const sock = sockets(config.runDir);
  const servers = config.dnsServers.length
    ? config.dnsServers.map(parseServer)
    : await systemServers();
  const uncached = createResolver({ servers });
  const resolver = cachingResolver(uncached);
  const signer = new RpcClient(sock.signer);
  const ehloName = config.ehloName;
  if (!ehloName) log.warn("BUNZZLE_EHLO_NAME is not set: email will wait until it is");

  const pool = new SessionPool();
  const transport = rememberingTransport(
    localTransport(
      {
        resolver,
        pool,
        perConnection: (provider) => limitsFor(provider).perConnection,
        ehloName: ehloName ?? "",
        port: config.smtpPort,
        families: config.ipv6 ? [4, 6] : [4],
        allowPrivate: config.allowPrivateDestinations,
        ...(config.sourceIp
          ? { localAddress: config.sourceIp, ownAddresses: [config.sourceIp] }
          : {}),
      },
      async (messageId, body) => {
        const r = await signer.call(
          "open",
          { messageId, body: toWire(body) },
          { result: z.object({ data: z.string() }), timeoutMs: 60_000 },
        );
        return r.data;
      },
    ),
  );

  const server = await serveRpc(sock.delivery, {
    lookup: method(z.object({ domain: z.string().min(1).max(255) }), ({ domain }) =>
      transport.lookup(domain),
    ),
    txt: method(
      z.object({ names: z.array(z.string().min(1).max(255)).max(20) }),
      async ({ names }) => {
        const out: Record<string, string[]> = {};
        for (const name of names) {
          try {
            const answer = await uncached.query(name, "TXT");
            out[name] = answer.records.flatMap((r) =>
              r.type === "TXT" ? [r.strings.join("")] : [],
            );
          } catch {
            out[name] = [];
          }
        }
        return out;
      },
    ),
    deliver: method(deliverRequestWire, async (wire) => {
      const req = requestFromWire(wire);
      if (!ehloName) {
        return {
          domain: req.domain,
          destination: req.destination,
          provider: null,
          policy: null,
          sessions: [],
          recipients: allRecipients(
            req,
            "deferred",
            "4.3.5",
            "BUNZZLE_EHLO_NAME is not set",
            "connect",
          ),
        };
      }
      return transport.deliver(req);
    }),
  });
  onStop(log, async () => {
    server.stop();
    await pool.closeAll();
  });
  log.info("delivery ready", { ehlo: ehloName, source: config.sourceIp ?? "default" });
  ready();
}
