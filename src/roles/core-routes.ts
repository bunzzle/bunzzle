import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { StorageState } from "../core/storage.ts";
import type { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, sealBody } from "../crypto/envelope.ts";
import { getDomain } from "../domains/domains.ts";
import {
  claimRouted,
  createRoute,
  deleteRoute,
  findRoute,
  listRoutes,
  outcomeOf,
  queueRouted,
  ROUTE_FORMATS,
  type Route,
  resetRouted,
  retryFailed,
  settleRouted,
  splitRouteAddress,
} from "../inbound/routes.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { resolveActor } from "./actor.ts";
import { DOMAIN, tokenHash, toWire } from "./wire.ts";

export interface RouteDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  currentKey: () => Promise<EpochPublicKey>;
  allowHttp: boolean;
  storage?: () => StorageState;
  scale?: number;
  now?: () => number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const view = (r: Route) => ({
  object: "route",
  id: r.id,
  address: r.address,
  endpoint: r.url,
  format: r.format,
  created_at: new Date(r.createdAt).toISOString(),
});

export function routeMethods(deps: RouteDeps) {
  const { db, writer, log, signer, delivery } = deps;
  const now = deps.now ?? Date.now;

  const methods: Methods = {
    inboundRoutes: method(
      b.object({ recipients: b.array(b.string().max(320)).min(1).max(100) }),
      ({ recipients }) => {
        const routes = new Map<string, { id: string; format: string; recipients: string[] }>();
        const rest: string[] = [];
        for (const address of recipients) {
          const r = findRoute(db, address);
          if (!r) {
            rest.push(address);
            continue;
          }
          const entry = routes.get(r.id) ?? { id: r.id, format: r.format, recipients: [] };
          entry.recipients.push(address);
          routes.set(r.id, entry);
        }
        return { routes: [...routes.values()], rest };
      },
    ),

    inboundRouted: method(
      b.object({
        routeId: b.string().regex(UUID),
        id: b.string().regex(UUID),
        payload: b.string().max(60 * 1024 * 1024),
      }),
      async ({ routeId, id, payload }) => {
        const storage = deps.storage?.();
        if (storage?.low) {
          throw new RpcError("storage-low", `free disk space is below ${storage.minFreeMb} MB`);
        }
        const sealed = await sealBody(await deps.currentKey(), id, payload);
        await writer.run((d) => queueRouted(d, routeId, id, sealed, payload.length, now()));
        return { id };
      },
    ),

    createRoute: method(
      b.object({
        tokenHash,
        address: b.string().max(320),
        url: b.string().url().max(2048),
        format: b.enum(ROUTE_FORMATS).default("parsed"),
      }),
      async (p) => {
        const { project } = resolveActor(db, p.tokenHash, "full");
        const parts = splitRouteAddress(p.address);
        if (!parts || !DOMAIN.test(parts.domain)) {
          throw new RpcError("invalid", "address must look like name@example.com or *@example.com");
        }
        if (!getDomain(db, project, parts.domain)) {
          throw new RpcError("invalid", `${parts.domain} is not a domain here; add it first`);
        }
        const u = new URL(p.url);
        if (u.protocol !== "https:" && !(deps.allowHttp && u.protocol === "http:")) {
          throw new RpcError("invalid", "route endpoints must be https");
        }
        const address = `${parts.local}@${parts.domain}`;
        const route = await writer.run((d) =>
          createRoute(d, project, address, p.url, p.format, now()),
        );
        if (!route) throw new RpcError("invalid", `a route for ${address} already exists`);
        const secret = await signer.call("routeSecret", { id: route.id }, { result: b.string() });
        return { ...view(route), signing_secret: secret };
      },
    ),

    listRoutes: method(b.object({ tokenHash }), (p) => {
      const { project } = resolveActor(db, p.tokenHash, "read");
      return listRoutes(db, project).map(view);
    }),

    deleteRoute: method(b.object({ tokenHash, id: b.string().max(64) }), async (p) => {
      const { project } = resolveActor(db, p.tokenHash, "full");
      if (!(await writer.run((d) => deleteRoute(d, project, p.id, now())))) {
        throw new RpcError("not-found", "route not found");
      }
      return { id: p.id, deleted: true };
    }),

    retryRoute: method(b.object({ tokenHash, id: b.string().max(64) }), async (p) => {
      const { project } = resolveActor(db, p.tokenHash, "full");
      if (!listRoutes(db, project).some((r) => r.id === p.id)) {
        throw new RpcError("not-found", "route not found");
      }
      const requeued = await writer.run((d) => retryFailed(d, project, p.id, now()));
      return { id: p.id, requeued };
    }),
  };

  const posted = b.union([
    b.object({ ok: b.literal(true), status: b.number(), retryAfter: b.string().optional() }),
    b.object({ ok: b.literal(false), error: b.string() }),
  ]);

  let sending = false;
  const dispatch = async () => {
    if (sending) return;
    sending = true;
    try {
      const due = await writer.run((d) => claimRouted(d, now(), 10));
      await Promise.all(
        due.map(async (d) => {
          let r: b.infer<typeof posted>;
          try {
            r = await delivery.call(
              "postInbound",
              { routeId: d.routeId, id: d.id, url: d.url, body: toWire(d.sealed) },
              { timeoutMs: 90_000, result: posted },
            );
          } catch (err) {
            r = { ok: false, error: (err as Error).message };
          }
          const outcome = outcomeOf(r, now());
          const result = await writer.run((w) =>
            settleRouted(w, d, outcome, now(), deps.scale ?? 1),
          );
          if (result === "failed") {
            log.warn("inbound route delivery failed", {
              route: d.routeId,
              id: d.id,
              error: outcome.ok ? null : outcome.error,
            });
          }
        }),
      );
    } finally {
      sending = false;
    }
  };

  const recover = () => writer.run((d) => resetRouted(d, now()));

  return { methods, dispatch, recover };
}
