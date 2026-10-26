import { type Config, parseLinkAddress } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { holdProgress } from "../delivery/progress.ts";
import { type EgressTarget, localTransport, rememberingTransport } from "../delivery/transport.ts";
import { cachingResolver } from "../dns/cache.ts";
import { localValidatingResolver } from "../dns/dnssec.ts";
import { delegationAt, measureNs } from "../dns/probe.ts";
import { createResolver, dnsServers, type Resolver } from "../dns/resolver.ts";
import { checkReverse, type ReverseCheck } from "../dns/reverse.ts";
import { ownValidation } from "../dnssec/resolver.ts";
import { egressVia, type Via } from "../egress/tunnel.ts";
import { method, RpcClient, type RpcServer, serveRpc } from "../ipc/rpc.ts";
import { blocklists, checkBlocklists, type Listing } from "../ips/blocklists.ts";
import { onThisMachine } from "../ips/local.ts";
import { parseMilterAddress, runMilter } from "../milter/client.ts";
import { guardedPost } from "../net/post.ts";
import { guardedRequest } from "../net/request.ts";
import { DeliveryIdentity } from "../nodes/delivery-identity.ts";
import { nodeLinkMethods } from "../nodes/node.ts";
import { deliverySpans } from "../otel/delivery-spans.ts";
import { MAX_QUEUE, type Post, SpanExporter } from "../otel/exporter.ts";
import { parseHeaders, spanWire } from "../otel/otlp.ts";
import { limitsFor } from "../shaping/limits.ts";
import { allRecipients, type DeliveryReport } from "../smtp/deliver.ts";
import { StsCache } from "../smtp/mta-sts.ts";
import { SessionPool } from "../smtp/pool.ts";
import { b } from "../validate/schema.ts";
import { loadLinkTls } from "./node-link.ts";
import { every, onStop, ready } from "./runtime.ts";
import { deliverRequestWire, requestFromWire, sealedBodyWire, sockets } from "./wire.ts";

const PROGRESS_HOLD_MS = 20;

export async function runDelivery(config: Config, log: Logger) {
  const sock = sockets(config.runDir);
  const servers = await dnsServers(config.dnsServers);
  const uncached = createResolver({ servers });
  let dnssec: { mode: "resolver" | "own" | "off"; detail: string } = {
    mode: "off",
    detail: "BUNZZLE_DANE is off",
  };
  let validating: Resolver = uncached;
  if (config.dane !== "off") {
    if (await localValidatingResolver(servers, uncached)) {
      dnssec = { mode: "resolver", detail: "a local DNSSEC-validating resolver" };
    } else {
      let problem = "";
      for (let attempt = 0; attempt < 3 && dnssec.mode === "off"; attempt++) {
        if (attempt > 0) await Bun.sleep(2_000);
        const own = await ownValidation((name, type) =>
          (uncached.message as NonNullable<Resolver["message"]>)(name, type),
        );
        if ("resolver" in own) {
          validating = own.resolver;
          dnssec = { mode: "own", detail: "Bunzzle validates DNSSEC itself" };
        } else problem = own.problem;
      }
      if (dnssec.mode === "off") dnssec = { mode: "off", detail: problem };
    }
  }
  const resolver = cachingResolver(validating);
  const signer = new RpcClient(sock.signer);
  const relay = config.relay
    ? {
        host: config.relay.host,
        port: config.relay.port,
        implicitTls: config.relay.port === 465,
        username: config.relay.username,
        password: config.relay.passwordFile
          ? (await Bun.file(config.relay.passwordFile).text()).trim()
          : null,
      }
    : null;
  if (relay) log.info("sending through a relay", { relay: `${relay.host}:${relay.port}` });
  const dane = dnssec.mode !== "off";
  if (config.dane !== "off" && !dane) log.warn("DANE is off", { reason: dnssec.detail });
  const ehloName = config.ehloName;
  const ips = config.sourceIps.map((s) => s.ip);
  let owned = ips;
  let elsewhere = "";
  const checkOwned = async () => {
    const here = await Promise.all(ips.map(onThisMachine));
    owned = ips.filter((_, i) => here[i]);
    const missing = ips.filter((_, i) => !here[i]).join(", ");
    if (missing && missing !== elsewhere) {
      log.info("source IPs that are not on this machine are left to other delivery roles", {
        ips: missing,
      });
    }
    elsewhere = missing;
  };
  await checkOwned();
  const otlp = config.otlp;
  const otlpHeaders = otlp?.headersFile
    ? parseHeaders(await Bun.file(otlp.headersFile).text())
    : {};
  const postOtlp: Post = async (path, body) => {
    const r = await guardedRequest(
      {
        method: "POST",
        url: `${otlp?.endpoint}${path}`,
        headers: { ...otlpHeaders, "Content-Type": "application/json" },
        body,
        maxBody: 64 * 1024,
      },
      {
        resolver,
        allowPrivate: true,
        ...(ips.length ? { ownAddresses: ips } : {}),
        families: config.ipv6 ? [4, 6] : [4],
        timeoutMs: 10_000,
      },
    );
    return r.ok ? { ok: true, status: r.status } : { ok: false, error: r.error };
  };
  const spans = otlp ? new SpanExporter(ehloName ?? "bunzzle", postOtlp, log) : null;
  const reverse = new Map<string, ReverseCheck>();
  const checkIps = async () => {
    for (const ip of owned) {
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
  const lists = blocklists(
    config.spamhausKeyFile ? (await Bun.file(config.spamhausKeyFile).text()).trim() : null,
  );
  const listings = new Map<string, Listing[]>();
  const checkLists = async () => {
    for (const ip of owned) {
      const found = await checkBlocklists(uncached, ip, lists);
      const before = new Set(
        (listings.get(ip) ?? []).filter((l) => l.status === "listed").map((l) => l.list),
      );
      listings.set(ip, found);
      for (const l of found) {
        if (l.status === "listed" && !before.has(l.list)) {
          log.warn("sending IP is on a blocklist", {
            ip,
            list: l.name,
            detail: l.detail,
            removal: l.removal,
          });
        }
      }
    }
  };
  const ehloFor = (ip: string) => {
    const r = reverse.get(ip);
    return r?.forwardConfirmed && r.ptr ? r.ptr : (ehloName ?? "");
  };
  if (!ehloName) log.warn("BUNZZLE_EHLO_NAME is not set: email will wait until it is");

  const pool = new SessionPool();
  const linkIdentity = new DeliveryIdentity();
  const tunnels = Bun.env["TMPDIR"] ?? "/tmp";
  const viaFor = (egress: EgressTarget): Via | string => {
    const me = linkIdentity.current();
    if (!me) return "this delivery role has no link certificate yet";
    const at = parseLinkAddress(egress.address);
    if (!at) return `bad address for ${egress.name}`;
    const tls = { cert: me.cert, key: me.key, ca: me.ca, pins: [egress.pin], name: egress.name };
    return egressVia(egress.name, { ...at, tls }, tunnels);
  };
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
        egressVia: viaFor,
        sts: (domain) => stsCache.policyFor(domain),
        perConnection: (provider) => limitsFor(provider).perConnection,
        ehloName: ehloName ?? "",
        port: config.smtpPort,
        families: config.ipv6 ? [4, 6] : [4],
        allowPrivate: config.allowPrivateDestinations,
        dane,
        relay,
        relayAll: config.relay?.for.all ?? true,
        requiretls: config.requiretls,
        ...(ips.length ? { ownAddresses: ips } : {}),
      },
      async (messageId, body, o) =>
        signer.call(
          "open",
          { messageId, body: body, lane: o.lane, bounceDomain: o.bounceDomain },
          { result: b.object({ data: b.string(), bounceToken: b.string() }), timeoutMs: 60_000 },
        ),
    ),
  );

  const methods = {
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
    milter: method(
      b.object({
        address: b.string().max(2048),
        timeoutMs: b.number().int().min(100).max(60_000),
        id: b.string().max(64),
        from: b.string().max(1000),
        recipients: b.array(b.string().max(1000)).min(1).max(1000),
        user: b.string().max(200),
        data: b.string().max(60 * 1024 * 1024),
      }),
      async (p) => {
        const address = parseMilterAddress(p.address);
        if (!address) return { action: "failed" as const, error: "bad milter address" };
        try {
          return await runMilter(address, p.timeoutMs, {
            id: p.id,
            hostname: config.ehloName ?? "bunzzle",
            user: p.user,
            from: p.from,
            recipients: p.recipients,
            data: p.data,
          });
        } catch (err) {
          return { action: "failed" as const, error: (err as Error).message };
        }
      },
    ),
    postHook: method(
      b.object({
        url: b.string().max(2048),
        contentType: b.enum(["application/json", "message/rfc822"]),
        headers: b.record(b.string().regex(/^[A-Za-z0-9-]+$/), b.string().max(1000)),
        body: b.string().max(60 * 1024 * 1024),
        timeoutMs: b.number().int().min(100).max(60_000),
      }),
      async ({ url, contentType, headers, body, timeoutMs }) => {
        const r = await guardedRequest(
          {
            method: "POST",
            url,
            headers: { ...headers, "Content-Type": contentType },
            body,
            maxBody: 1024 * 1024,
          },
          {
            resolver,
            allowPrivate: true,
            ...(ips.length ? { ownAddresses: ips } : {}),
            families: config.ipv6 ? [4, 6] : [4],
            timeoutMs,
          },
        );
        return r.ok ? { ok: true, status: r.status, body: r.body } : { ok: false, error: r.error };
      },
    ),
    postInbound: method(
      b.object({
        routeId: b.string().min(1).max(64),
        id: b.string().min(1).max(64),
        url: b.string().max(2048),
        body: sealedBodyWire,
      }),
      async ({ routeId, id, url, body }) => {
        const timestamp = Math.floor(Date.now() / 1000);
        const msgId = `msg_${id}`;
        const opened = await signer.call(
          "openInbound",
          { id, routeId, msgId, timestamp, body },
          { result: b.object({ body: b.string(), signature: b.string() }), timeoutMs: 30_000 },
        );
        const r = await guardedRequest(
          {
            method: "POST",
            url,
            headers: {
              "Content-Type": "application/json",
              "webhook-id": msgId,
              "webhook-timestamp": String(timestamp),
              "webhook-signature": opened.signature,
            },
            body: opened.body,
          },
          {
            resolver,
            allowPrivate: config.allowPrivateDestinations,
            ...(ips.length ? { ownAddresses: ips } : {}),
            families: config.ipv6 ? [4, 6] : [4],
            timeoutMs: 30_000,
          },
        );
        if (!r.ok) return { ok: false, error: r.error };
        const retryAfter = r.headers.get("retry-after");
        return { ok: true, status: r.status, ...(retryAfter ? { retryAfter } : {}) };
      },
    ),
    dnssec: method(b.object({}), () => dnssec),
    ips: method(b.object({}), () =>
      owned.map((ip) => ({
        ip,
        ehlo: ehloFor(ip),
        ...(reverse.get(ip) ?? { ptr: null, forwardConfirmed: false, problem: "not checked yet" }),
        listings: listings.get(ip) ?? null,
      })),
    ),
    dns: method(
      b.object({
        queries: b
          .array(
            b.object({ name: b.string().min(1).max(255), type: b.enum(["TXT", "MX", "CNAME"]) }),
          )
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
              if (r.type === "CNAME" && q.type === "CNAME") return [r.target];
              return [];
            });
          } catch {
            out[`${q.type}:${q.name}`] = [];
          }
        }
        return out;
      },
    ),
    nsProbe: method(
      b.object({
        host: b.string().min(1).max(255),
        port: b.number().int().min(1).max(65535),
        zone: b.string().min(1).max(253),
      }),
      ({ host, port, zone }) => measureNs({ host, port }, zone),
    ),
    nsDelegation: method(b.object({ zone: b.string().min(1).max(253) }), ({ zone }) =>
      delegationAt(zone, uncached),
    ),
    deliver: method(deliverRequestWire, async (wire, ctx) => {
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
      const start = Date.now();
      const progress = holdProgress((recipients) => ctx.progress({ recipients }), PROGRESS_HOLD_MS);
      let report: DeliveryReport;
      try {
        report = await transport.deliver(req, progress.onOutcomes);
      } catch (err) {
        progress.flush();
        throw err;
      }
      progress.drop();
      spans?.add(deliverySpans(req, report, start, Date.now()));
      return report;
    }),
    exportSpans: method(b.object({ spans: b.array(spanWire).max(MAX_QUEUE) }), (p) => {
      spans?.add(p.spans);
      return { queued: spans?.queued ?? 0 };
    }),
    exportMetrics: method(b.object({ body: b.string().max(32 * 1024 * 1024) }), async (p) => {
      if (!spans) return { ok: false };
      const r = await postOtlp("/v1/metrics", p.body);
      const problem = !r.ok ? r.error : r.status >= 300 ? `answered ${r.status}` : null;
      if (problem) spans.warn("could not export metrics", problem);
      return { ok: problem === null };
    }),
    forget: method(
      b.object({ keys: b.array(b.string().min(1).max(200)).max(5000) }),
      ({ keys }) => {
        transport.forget(keys);
        return { remembered: transport.remembered };
      },
    ),
  };
  const server = await serveRpc(sock.delivery, { ...methods, ...linkIdentity.methods() });
  let link: RpcServer | null = null;
  if (config.deliveryListen) {
    const tls = await loadLinkTls(config.nodeDir);
    const linkServer = await serveRpc(
      { ...config.deliveryListen, tls },
      {
        ...methods,
        ...nodeLinkMethods(config.nodeDir, tls, () => linkServer),
      },
      { onRefused: (reason, remote) => log.warn("node link refused", { reason, remote }) },
    );
    link = linkServer;
  }
  await checkIps();
  const stopChecks = every(3_600_000, checkIps);
  void checkLists();
  const stopLists = every(6 * 3_600_000, checkLists);
  const stopExpire = every(60_000, () => transport.forget([]));
  const stopOwned = every(60_000, checkOwned);
  const stopSpans = spans ? every(5_000, () => spans.flush()) : () => {};
  onStop(log, async () => {
    stopChecks();
    stopLists();
    stopExpire();
    stopOwned();
    stopSpans();
    await spans?.flush();
    link?.stop();
    server.stop();
    await pool.closeAll();
  });
  log.info("delivery ready", {
    ehlo: ehloName,
    sources: ips.length ? ips : ["default"],
    dnssec: dnssec.mode,
    ...(config.deliveryListen
      ? { link: `${config.deliveryListen.hostname}:${config.deliveryListen.port}` }
      : {}),
  });
  ready();
}
