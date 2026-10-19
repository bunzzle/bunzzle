import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, systemServers } from "../dns/resolver.ts";
import { method, serveRpc } from "../ipc/rpc.ts";
import { Cloudflare } from "../net/cloudflare.ts";
import { guardedRequest } from "../net/request.ts";
import { b } from "../validate/schema.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runDns(config: Config, log: Logger) {
  const servers = config.dnsServers.length
    ? config.dnsServers.map(parseServer)
    : await systemServers();
  const resolver = cachingResolver(createResolver({ servers }));
  const token =
    config.cloudflareToken ??
    (config.cloudflareTokenFile
      ? (await Bun.file(config.cloudflareTokenFile).text()).trim()
      : null);
  const cloudflare = token
    ? new Cloudflare(token, config.cloudflareUrl, (r) =>
        guardedRequest(r, {
          resolver,
          allowPrivate: config.allowPrivateDestinations,
          timeoutMs: 15_000,
        }),
      )
    : null;

  const server = await serveRpc(sockets(config.runDir).dns, {
    publish: method(
      b.object({
        op: b.enum(["status", "upsert", "remove"]),
        record: b
          .object({
            type: b.enum(["TXT", "MX"]),
            name: b.string().min(1).max(253),
            content: b.string().min(1).max(4096),
            priority: b.number().int().min(0).max(65535).optional(),
          })
          .optional(),
      }),
      async ({ op, record }) => {
        if (!cloudflare) return { enabled: false };
        if (op === "status" || !record) return { enabled: true };
        const r =
          op === "upsert" ? await cloudflare.upsert(record) : await cloudflare.remove(record);
        return { enabled: true, ...r };
      },
    ),
  });
  onStop(log, () => server.stop());
  ready({ provider: cloudflare ? "cloudflare" : null });
}
