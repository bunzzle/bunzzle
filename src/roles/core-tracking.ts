import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { emailExists } from "../delivery/queue.ts";
import { getDomain } from "../domains/domains.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import {
  checkTracking,
  getTracking,
  listTracking,
  recordTrack,
  setTracking,
  type Tracking,
  trackingView,
} from "../tracking/store.ts";
import { b } from "../validate/schema.ts";
import { resolveActor } from "./actor.ts";
import { DOMAIN, MESSAGE_ID, tokenHash } from "./wire.ts";

export interface TrackingDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  dns: RpcClient;
  publicUrl: string | null;
  now?: () => number;
}

const tokenResult = b.object({ purpose: b.string(), messageId: b.string() }).nullable();
const userAgent = b.string().max(1000).optional();

export function trackingMethods(deps: TrackingDeps) {
  const { db, writer, log, signer, delivery, dns } = deps;
  const now = deps.now ?? Date.now;
  const target = deps.publicUrl ? new URL(deps.publicUrl).hostname.toLowerCase() : null;

  const check = async (domain: string): Promise<Tracking | null> => {
    const t = getTracking(db, domain);
    if (!t || !target) return t;
    const found = await delivery.call(
      "dns",
      { queries: [{ name: t.host, type: "CNAME" }] },
      { result: b.record(b.string(), b.array(b.string())), timeoutMs: 30_000 },
    );
    const next = checkTracking(t, found[`CNAME:${t.host}`] ?? [], target, now());
    await writer.run((w) => {
      if (getTracking(w, domain)?.host === next.host) setTracking(w, domain, next, now());
    });
    if (next.status !== t.status) {
      log.info("tracking domain status changed", { domain, host: t.host, status: next.status });
    }
    return next;
  };

  const pushHosts = async () => {
    const hosts = listTracking(db)
      .filter((x) => x.tracking.status === "verified")
      .map((x) => x.tracking.host);
    await dns.call("trackingHosts", { hosts }, { timeoutMs: 5_000 });
  };

  const refresh = async () => {
    for (const { domain, tracking } of listTracking(db)) {
      if (tracking.status === "verified" && now() - (tracking.checkedAt ?? 0) < 86_400_000) {
        continue;
      }
      try {
        await check(domain);
      } catch (err) {
        log.warn("could not check tracking domain", { domain, error: (err as Error).message });
      }
    }
    await pushHosts().catch(() => {});
  };

  const methods: Methods = {
    setDomainTracking: method(
      b.object({
        tokenHash,
        name: b.string().max(253),
        tracking: b
          .object({
            host: b.string().max(253),
            opens: b.boolean().optional(),
            clicks: b.boolean().optional(),
          })
          .nullable(),
      }),
      async (p) => {
        const { project } = resolveActor(db, p.tokenHash, "full");
        const name = p.name.toLowerCase();
        if (!getDomain(db, project, name)) throw new RpcError("not-found", "domain not found");
        let next: Tracking | null = null;
        if (p.tracking) {
          if (!target) {
            throw new RpcError(
              "invalid",
              "tracking needs BUNZZLE_PUBLIC_URL: the host is a CNAME to it",
            );
          }
          const host = p.tracking.host.toLowerCase().replace(/\.$/, "");
          if (!DOMAIN.test(host) || !host.endsWith(`.${name}`)) {
            throw new RpcError("invalid", `the tracking host must be a subdomain of ${name}`);
          }
          const prev = getTracking(db, name);
          next = {
            host,
            opens: p.tracking.opens ?? prev?.opens ?? false,
            clicks: p.tracking.clicks ?? prev?.clicks ?? false,
            status: prev?.host === host ? prev.status : "pending",
            found: prev?.host === host ? prev.found : null,
            checkedAt: prev?.host === host ? prev.checkedAt : null,
          };
        }
        await writer.run((w) => setTracking(w, name, next, now()));
        const checked = next ? await check(name).catch(() => next) : null;
        await pushHosts().catch(() => {});
        return { name, tracking: trackingView(checked, target) };
      },
    ),

    tracking: method(
      b.object({
        tokenHash,
        domain: b.string().max(253),
        id: b.string().regex(MESSAGE_ID),
        urls: b.array(b.string().max(2000)).max(200),
        opens: b.boolean().optional(),
        clicks: b.boolean().optional(),
      }),
      async (p) => {
        const { project, key } = resolveActor(db, p.tokenHash, "send");
        if (key?.domains && !key.domains.includes(p.domain)) return null;
        if (!getDomain(db, project, p.domain)) return null;
        const t = getTracking(db, p.domain);
        const opens = p.opens ?? t?.opens ?? false;
        const clicks = p.clicks ?? t?.clicks ?? false;
        if (!opens && !clicks) return null;
        if (t?.status !== "verified") {
          if (p.opens || p.clicks) {
            throw new RpcError(
              "invalid",
              t
                ? `the tracking host ${t.host} is not verified yet: add a CNAME to ${target ?? "BUNZZLE_PUBLIC_URL"}`
                : `${p.domain} has no tracking host; set one with PATCH /domains/${p.domain}`,
            );
          }
          return null;
        }
        const tokens = await signer.call(
          "trackTokens",
          { id: p.id, opens, urls: clicks ? p.urls : [] },
          {
            result: b.object({ open: b.string().nullable(), links: b.array(b.string()) }),
            timeoutMs: 10_000,
          },
        );
        return { host: t.host, opens, clicks, ...tokens };
      },
    ),

    trackOpen: method(b.object({ token: b.string().max(100), userAgent }), async (p) => {
      const t = await signer.call(
        "readToken",
        { token: p.token },
        { result: tokenResult, timeoutMs: 10_000 },
      );
      if (t?.purpose !== "o") return { recorded: false };
      const recorded = await writer.run(
        (d) =>
          emailExists(d, t.messageId) &&
          recordTrack(d, t.messageId, "opened", { user_agent: p.userAgent ?? null }, now()),
      );
      return { recorded };
    }),

    trackClick: method(
      b.object({
        token: b.string().max(100),
        url: b.string().max(2000),
        userAgent,
        record: b.boolean(),
      }),
      async (p) => {
        const t = await signer.call(
          "readToken",
          { token: p.token, url: p.url },
          { result: tokenResult, timeoutMs: 10_000 },
        );
        if (t?.purpose !== "c") throw new RpcError("not-found", "unknown link");
        const recorded =
          p.record &&
          (await writer.run(
            (d) =>
              emailExists(d, t.messageId) &&
              recordTrack(
                d,
                t.messageId,
                "clicked",
                { link: p.url, user_agent: p.userAgent ?? null },
                now(),
              ),
          ));
        return { recorded };
      },
    ),
  };

  return {
    methods,
    refresh,
    view: (domain: string) => trackingView(getTracking(db, domain), target),
  };
}
