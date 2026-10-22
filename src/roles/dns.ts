import { ensureCertificate } from "../acme/manager.ts";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, dnsServers } from "../dns/resolver.ts";
import { method, serveRpc } from "../ipc/rpc.ts";
import { Postmaster } from "../net/postmaster.ts";
import { openDnsProvider } from "../net/providers.ts";
import { guardedRequest } from "../net/request.ts";
import { b } from "../validate/schema.ts";
import { every, onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

const HOUR = 3_600_000;

export async function runDns(config: Config, log: Logger) {
  const servers = await dnsServers(config.dnsServers);
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

  const pm = config.postmaster;
  const postmaster = pm
    ? new Postmaster(
        {
          clientId: pm.clientId,
          clientSecret: (await Bun.file(pm.clientSecretFile).text()).trim(),
          refreshToken: (await Bun.file(pm.refreshTokenFile).text()).trim(),
        },
        api,
        pm.apiUrl,
        pm.tokenUrl,
      )
    : null;

  let trackHosts: string[] = [];
  const server = await serveRpc(sockets(config.runDir).dns, {
    trackingHosts: method(
      b.object({ hosts: b.array(b.string().regex(/^[a-z0-9.-]{1,253}$/)).max(10_000) }),
      ({ hosts }) => {
        trackHosts = hosts.filter((h) => !h.includes(".."));
        return { certificates: config.track !== null && config.acme !== null && provider !== null };
      },
    ),
    postmaster: method(
      b.object({ domains: b.array(b.string().min(1).max(253)).max(1000) }),
      async ({ domains }) => {
        if (!postmaster) return { enabled: false, results: [] };
        const results = [];
        for (const domain of domains) {
          results.push({ domain, ...(await postmaster.trafficStats(domain)) });
        }
        return { enabled: true, results };
      },
    ),
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
    const certify = async (hosts: string[], dir: string) => {
      try {
        await ensureCertificate({
          directory: acme.directory,
          email: acme.email,
          hosts,
          dir,
          dns: provider,
          request,
          log,
        });
        return true;
      } catch (err) {
        log.error("could not get a TLS certificate", { hosts, error: (err as Error).message });
        return false;
      }
    };
    const nextAt = new Map<string, number>();
    const due = (key: string) => Date.now() >= (nextAt.get(key) ?? 0);
    const after = (key: string, ok: boolean) => nextAt.set(key, Date.now() + (ok ? 12 : 1) * HOUR);
    const tick = async () => {
      if (acme.hosts.length > 0 && due("")) after("", await certify(acme.hosts, acme.dir));
      const track = config.track;
      if (!track) return;
      for (const host of trackHosts) {
        if (due(host)) after(host, await certify([host], `${track.dir}/${host}`));
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
