import { ensureCertificate } from "../acme/manager.ts";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, systemServers } from "../dns/resolver.ts";
import { method, serveRpc } from "../ipc/rpc.ts";
import { openDnsProvider } from "../net/providers.ts";
import { guardedRequest } from "../net/request.ts";
import { b } from "../validate/schema.ts";
import { every, onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

const HOUR = 3_600_000;

export async function runDns(config: Config, log: Logger) {
  const servers = config.dnsServers.length
    ? config.dnsServers.map(parseServer)
    : await systemServers();
  const resolver = cachingResolver(createResolver({ servers }));
  const api = (r: Parameters<typeof guardedRequest>[0]) =>
    guardedRequest(r, {
      resolver,
      allowPrivate: config.allowPrivateDestinations,
      timeoutMs: 15_000,
    });
  const opened = await openDnsProvider(config, servers, api);
  const provider = opened?.provider ?? null;
  const providerName = opened?.name ?? null;

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
        if (!provider) return { enabled: false };
        if (op === "status" || !record) return { enabled: true, provider: providerName };
        const r = op === "upsert" ? await provider.upsert(record) : await provider.remove(record);
        return { enabled: true, provider: providerName, ...r };
      },
    ),
  });
  let stopAcme = () => {};
  const acme = config.acme;
  if (acme && provider) {
    const request = (r: Parameters<typeof guardedRequest>[0]) =>
      guardedRequest(r, {
        resolver,
        allowPrivate: config.allowPrivateDestinations,
        timeoutMs: 30_000,
      });
    let nextAt = Date.now() + 5_000;
    const tick = async () => {
      if (Date.now() < nextAt) return;
      try {
        await ensureCertificate({
          directory: acme.directory,
          email: acme.email,
          hosts: acme.hosts,
          dir: acme.dir,
          dns: provider,
          request,
          log,
        });
        nextAt = Date.now() + 12 * HOUR;
      } catch (err) {
        nextAt = Date.now() + HOUR;
        log.error("could not get a TLS certificate", {
          hosts: acme.hosts,
          error: (err as Error).message,
        });
      }
    };
    stopAcme = every(60_000, tick);
    setTimeout(() => void tick(), 5_000);
  }
  onStop(log, () => {
    stopAcme();
    server.stop();
  });
  ready({ provider: providerName });
}
