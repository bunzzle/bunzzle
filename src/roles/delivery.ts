import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { localTransport, rememberingTransport } from "../delivery/transport.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, systemServers } from "../dns/resolver.ts";
import { checkReverse, type ReverseCheck } from "../dns/reverse.ts";
import { method, RpcClient, serveRpc } from "../ipc/rpc.ts";
import { Cloudflare } from "../net/cloudflare.ts";
import { guardedPost } from "../net/post.ts";
import { guardedRequest } from "../net/request.ts";
import { limitsFor } from "../shaping/limits.ts";
import { allRecipients } from "../smtp/deliver.ts";
import { StsCache } from "../smtp/mta-sts.ts";
import { SessionPool } from "../smtp/pool.ts";
import { b } from "../validate/schema.ts";
import { every, onStop, ready } from "./runtime.ts";
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
  const ips = config.sourceIps.map((s) => s.ip);
  const reverse = new Map<string, ReverseCheck>();
  const checkIps = async () => {
    for (const ip of ips) {
      const r = await checkReverse(uncached, ip);
      const before = reverse.get(ip);
      reverse.set(ip, r);
      if (r.problem && before?.problem !== r.problem) {
        log.warn("reverse DNS problem: receivers like Gmail will reject mail from this IP", {
          ip,
          problem: r.problem,
        });
      }
    }
  };
  const ehloFor = (ip: string) => {
    const r = reverse.get(ip);
    return r?.forwardConfirmed && r.ptr ? r.ptr : (ehloName ?? "");
  };
  if (!ehloName) log.warn("BUNZZLE_EHLO_NAME is not set: email will wait until it is");

  const cloudflareToken =
    config.cloudflareToken ??
    (config.cloudflareTokenFile
      ? (await Bun.file(config.cloudflareTokenFile).text()).trim()
      : null);
  const cloudflare = cloudflareToken
    ? new Cloudflare(cloudflareToken, config.cloudflareUrl, (r) =>
        guardedRequest(r, {
          resolver,
          allowPrivate: config.allowPrivateDestinations,
          timeoutMs: 15_000,
        }),
      )
    : null;
  const pool = new SessionPool();
  const stsCache = new StsCache(resolver, async (url) => {
    const r = await guardedRequest(
      { method: "GET", url, maxBody: 64 * 1024 },
      {
        resolver,
        allowPrivate: config.allowPrivateDestinations,
        ...(ips.length ? { ownAddresses: ips } : {}),
        timeoutMs: 10_000,
      },
    );
    return r.ok
      ? { status: r.status, type: r.headers.get("content-type") ?? "", body: r.body }
      : null;
  });
  const transport = rememberingTransport(
    localTransport(
      {
        resolver,
        pool,
        sources: ips,
        ehloFor,
        sts: (domain) => stsCache.policyFor(domain),
        perConnection: (provider) => limitsFor(provider).perConnection,
        ehloName: ehloName ?? "",
        port: config.smtpPort,
        families: config.ipv6 ? [4, 6] : [4],
        allowPrivate: config.allowPrivateDestinations,
        ...(ips.length ? { ownAddresses: ips } : {}),
      },
      async (messageId, body, o) =>
        signer.call(
          "open",
          { messageId, body: toWire(body), lane: o.lane, bounceDomain: o.bounceDomain },
          { result: b.object({ data: b.string(), bounceToken: b.string() }), timeoutMs: 60_000 },
        ),
    ),
  );

  const server = await serveRpc(sock.delivery, {
    lookup: method(b.object({ domain: b.string().min(1).max(255) }), ({ domain }) =>
      transport.lookup(domain),
    ),
    postWebhook: method(
      b.object({
        url: b.string().max(2048),
        headers: b.record(b.string().regex(/^[A-Za-z0-9-]+$/), b.string().max(1000)),
        body: b.string().max(1_000_000),
      }),
      ({ url, headers, body }) =>
        guardedPost(url, headers, body, {
          resolver,
          allowPrivate: config.allowPrivateDestinations,
          ...(ips.length ? { ownAddresses: ips } : {}),
          families: config.ipv6 ? [4, 6] : [4],
        }),
    ),
    ips: method(b.object({}), () =>
      ips.map((ip) => ({
        ip,
        ehlo: ehloFor(ip),
        ...(reverse.get(ip) ?? { ptr: null, forwardConfirmed: false, problem: "not checked yet" }),
      })),
    ),
    cloudflare: method(
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
    dns: method(
      b.object({
        queries: b
          .array(b.object({ name: b.string().min(1).max(255), type: b.enum(["TXT", "MX"]) }))
          .max(20),
      }),
      async ({ queries }) => {
        const out: Record<string, string[]> = {};
        for (const q of queries) {
          try {
            const answer = await uncached.query(q.name, q.type);
            out[`${q.type}:${q.name}`] = answer.records.flatMap((r) => {
              if (r.type === "TXT") return [r.strings.join("")];
              if (r.type === "MX") return [`${r.mx.preference} ${r.mx.exchange}`];
              return [];
            });
          } catch {
            out[`${q.type}:${q.name}`] = [];
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
    forget: method(
      b.object({ keys: b.array(b.string().min(1).max(200)).max(5000) }),
      ({ keys }) => {
        transport.forget(keys);
        return { remembered: transport.remembered };
      },
    ),
  });
  await checkIps();
  const stopChecks = every(3_600_000, checkIps);
  const stopExpire = every(60_000, () => transport.forget([]));
  onStop(log, async () => {
    stopChecks();
    stopExpire();
    server.stop();
    await pool.closeAll();
  });
  log.info("delivery ready", { ehlo: ehloName, sources: ips.length ? ips : ["default"] });
  ready();
}
